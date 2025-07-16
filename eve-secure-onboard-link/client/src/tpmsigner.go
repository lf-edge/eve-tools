// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto"
	"crypto/x509"
	"encoding/asn1"
	"fmt"
	"io"
	"math/big"
	"net/http"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/google/go-tpm/tpmutil"
	vcom "github.com/lf-edge/eve/pkg/pillar/vcom/go-api"
	"google.golang.org/protobuf/proto"
)

type tpmSigner struct {
	pubKey    crypto.PublicKey
	keyHandle uint32
}

func (cs *tpmSigner) Public() crypto.PublicKey {
	return cs.pubKey
}

// TODO : check SignerOpts and make sure the requested hash algorithm is supported
func (cs *tpmSigner) Sign(_ io.Reader, digest []byte, opts crypto.SignerOpts) (signature []byte, err error) {
	signRequest := vcom.TpmRequestSign{
		Index: cs.keyHandle,
		Data:  digest,
	}
	out, err := proto.Marshal(&signRequest)
	if err != nil {
		return nil, fmt.Errorf("failed to marshal sign request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/sign", bytes.NewBuffer(out))
	if err != nil {
		return nil, fmt.Errorf("failed to create sign request: %w", err)
	}
	signResp, err := getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("failed to send sign request: %w", err)
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected response status: %s", signResp.Status)
	}

	body, err := io.ReadAll(signResp.Body)
	if err != nil {
		return nil, fmt.Errorf("failed to read sign response body: %w", err)
	}
	var tpmRespSign vcom.TpmResponseSign
	err = proto.Unmarshal(body, &tpmRespSign)
	if err != nil {
		return nil, fmt.Errorf("failed to unmarshal sign response body: %w", err)
	}

	if tpmRespSign.RsaSignature != nil {
		return tpmRespSign.RsaSignature, nil
	}
	if tpmRespSign.EccSignatureR != nil && tpmRespSign.EccSignatureS != nil {
		R := new(big.Int)
		R.SetBytes(tpmRespSign.EccSignatureR)
		S := new(big.Int)
		S.SetBytes(tpmRespSign.EccSignatureS)
		sigStruct := struct{ R, S *big.Int }{R, S}
		return asn1.Marshal(sigStruct)
	}

	return nil, fmt.Errorf("no valid signature found in response")
}

func getTpmSigner(keyHandle tpmutil.Handle) (crypto.Signer, x509.SignatureAlgorithm, error) {
	if keyHandle == 0 {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("key handle is zero, cannot get TPM signer")
	}
	request := vcom.TpmRequestGetPub{
		Index: uint32(keyHandle),
	}
	out, err := proto.Marshal(&request)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to marshal request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/getpub", bytes.NewBuffer(out))
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to create request: %w", err)
	}
	resp, err := getClient().Do(req)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to send request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("unexpected response status: %s", resp.Status)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to read response body: %w", err)
	}

	var tpmResp vcom.TpmResponseGetPub
	err = proto.Unmarshal(body, &tpmResp)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to unmarshal response body: %w", err)
	}

	if len(tpmResp.Public) == 0 {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("no public key received from TPM")
	}

	tpmPublicKey, err := tpm2.DecodePublic(tpmResp.Public)
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to decode public key: %w", err)
	}
	publicKey, err := tpmPublicKey.Key()
	if err != nil {
		return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("failed to get public key from TPM: %w", err)
	}

	keyAlg := publicToSignatureAlgorithm(tpmPublicKey)
	if keyAlg == x509.UnknownSignatureAlgorithm {
		// return default
		switch tpmPublicKey.Type {
		case tpm2.AlgRSA:
			tpmPublicKey.RSAParameters = &tpm2.RSAParams{
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgRSASSA,
					Hash: tpm2.AlgSHA256,
				},
			}
		case tpm2.AlgECC:
			tpmPublicKey.ECCParameters = &tpm2.ECCParams{
				Sign: &tpm2.SigScheme{
					Alg:  tpm2.AlgECDSA,
					Hash: tpm2.AlgSHA256,
				},
			}
		default:
			return nil, x509.UnknownSignatureAlgorithm, fmt.Errorf("signing scheme is not defined for key type %v", tpmPublicKey.Type)
		}
	}

	signer := &tpmSigner{pubKey: publicKey, keyHandle: uint32(keyHandle)}
	return signer, publicToSignatureAlgorithm(tpmPublicKey), nil
}

func publicToSignatureAlgorithm(pub tpm2.Public) x509.SignatureAlgorithm {
	switch pub.Type {
	case tpm2.AlgRSA:
		if pub.RSAParameters != nil && pub.RSAParameters.Sign != nil {
			switch pub.RSAParameters.Sign.Alg {
			case tpm2.AlgRSASSA:
				switch pub.RSAParameters.Sign.Hash {
				case tpm2.AlgSHA1:
					return x509.SHA1WithRSA
				case tpm2.AlgSHA256:
					return x509.SHA256WithRSA
				case tpm2.AlgSHA384:
					return x509.SHA384WithRSA
				case tpm2.AlgSHA512:
					return x509.SHA512WithRSA
				}
			case tpm2.AlgRSAPSS:
				switch pub.RSAParameters.Sign.Hash {
				case tpm2.AlgSHA256:
					return x509.SHA256WithRSAPSS
				case tpm2.AlgSHA384:
					return x509.SHA384WithRSAPSS
				case tpm2.AlgSHA512:
					return x509.SHA512WithRSAPSS
				}
			}
		}
		return x509.UnknownSignatureAlgorithm

	case tpm2.AlgECC:
		if pub.ECCParameters != nil && pub.ECCParameters.Sign != nil {
			switch pub.ECCParameters.Sign.Alg {
			case tpm2.AlgECDSA:
				switch pub.ECCParameters.Sign.Hash {
				case tpm2.AlgSHA256:
					return x509.ECDSAWithSHA256
				case tpm2.AlgSHA384:
					return x509.ECDSAWithSHA384
				case tpm2.AlgSHA512:
					return x509.ECDSAWithSHA512
				}
			}
		}
		return x509.UnknownSignatureAlgorithm

	default:
		return x509.UnknownSignatureAlgorithm
	}
}
