// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	cryptorand "crypto/rand"
	"crypto/sha256"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"math"
	"math/big"
	"time"

	"github.com/google/go-tpm/legacy/tpm2"
)

func getDeviceId(pubKey any) (string, error) {
	derBytes, err := x509.MarshalPKIXPublicKey(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to marshal public key: %w", err)
	}

	hash := sha256.Sum256(derBytes)
	return fmt.Sprintf("%x", hash), nil
}

func signClientCertificate(data []byte, deviceID string) ([]byte, error) {
	block, _ := pem.Decode(data)
	if block == nil || block.Type != "CERTIFICATE REQUEST" {
		return nil, fmt.Errorf("invalid certificate request format")
	}
	csr, err := x509.ParseCertificateRequest(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate request: %w", err)
	}

	// we only accept CSR by certified keys
	csrSignedWithCertifiedKey := false
	for _, devicePub := range devices[deviceID].certifiedKeys {
		devicePubBytes, _ := x509.MarshalPKIXPublicKey(devicePub)
		csrPubBytes, _ := x509.MarshalPKIXPublicKey(csr.PublicKey)
		if bytes.Equal(devicePubBytes, csrPubBytes) {
			fmt.Println("\tCSR signed with one of the device certified keys")
			csrSignedWithCertifiedKey = true
		}
	}
	if !csrSignedWithCertifiedKey {
		return nil, fmt.Errorf("CSR not signed with a certified key")
	}

	if err := csr.CheckSignature(); err != nil {
		return nil, fmt.Errorf("CSR signature verification failed: %w", err)
	}

	serial, err := cryptorand.Int(cryptorand.Reader, new(big.Int).SetInt64(math.MaxInt64-1))
	if err != nil {
		return nil, fmt.Errorf("failed to generate serial number: %w", err)
	}
	serial = new(big.Int).Add(serial, big.NewInt(1))
	certTmpl := &x509.Certificate{
		SerialNumber:          serial,
		Subject:               csr.Subject,
		NotBefore:             time.Now(),
		NotAfter:              time.Now().Add(365 * 24 * time.Hour),
		KeyUsage:              x509.KeyUsageDigitalSignature | x509.KeyUsageKeyEncipherment,
		ExtKeyUsage:           []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
		BasicConstraintsValid: true,
		DNSNames:              csr.DNSNames,
	}
	certDER, err := x509.CreateCertificate(cryptorand.Reader, certTmpl, srvCaCert, csr.PublicKey, srvCaKey)
	if err != nil {
		return nil, fmt.Errorf("failed to create certificate: %w", err)
	}

	certPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE",
		Bytes: certDER,
	})
	if certPEM == nil {
		return nil, fmt.Errorf("failed to encode certificate to PEM format")
	}

	return certPEM, nil
}

func registerDevice(ek []byte) (string, error) {
	tpmPub, err := tpm2.DecodePublic(ek)
	if err != nil {
		return "", fmt.Errorf("failed to decode public key: %w", err)
	}
	pubKey, err := tpmPub.Key()
	if err != nil {
		return "", fmt.Errorf("failed to get EK public key: %w", err)
	}

	deviceID, err := getDeviceId(pubKey)
	if err != nil {
		return "", fmt.Errorf("failed to get device ID: %w", err)
	}

	devices[deviceID] = &Device{
		deviceID:            deviceID,
		credentialActivated: false,
		ekVerified:          true,
		ek:                  &tpmPub,
	}

	return deviceID, nil
}

func updateDeviceCredAcInfo(ekPub *tpm2.Public, akPub *tpm2.Public, credPlain []byte) (string, error) {
	ekCryptoPub, err := ekPub.Key()
	if err != nil {
		return "", fmt.Errorf("failed to get EK public key: %w", err)
	}

	deviceID, err := getDeviceId(ekCryptoPub)
	if err != nil {
		return "", fmt.Errorf("failed to get device ID: %w", err)
	}
	if _, exists := devices[deviceID]; !exists {
		return "", fmt.Errorf("device not found: %s", deviceID)
	}

	if !devices[deviceID].ekVerified {
		return "", fmt.Errorf("failed to update, device EK not verified: %s", deviceID)
	}

	deviceEk, err := devices[deviceID].ek.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode device EK: %w", err)
	}
	acEk, err := ekPub.Encode()
	if err != nil {
		return "", fmt.Errorf("failed to encode EK public key: %w", err)
	}
	if !bytes.Equal(deviceEk, acEk) {
		return "", fmt.Errorf("device EK does not match the provided EK public key: %s", deviceID)
	}

	// update device information
	devices[deviceID].credentialActivated = true
	devices[deviceID].cred = credPlain
	devices[deviceID].ak = akPub

	return deviceID, nil
}
