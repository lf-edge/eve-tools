// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/rand"
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/pem"
	"fmt"
	"os"

	"github.com/google/go-tpm/tpmutil"
)

func generateCsr(deviceID string, keyHandle tpmutil.Handle) ([]byte, error) {
	tpmSigner, sigAlg, err := getTpmSigner(keyHandle)
	if err != nil {
		return nil, fmt.Errorf("failed to get TPM signer: %w", err)
	}

	csrTemplate := x509.CertificateRequest{
		Subject: pkix.Name{
			CommonName:   deviceID,
			Organization: []string{"Example Org"},
		},
		SignatureAlgorithm: sigAlg,
	}

	csr, err := x509.CreateCertificateRequest(rand.Reader, &csrTemplate, tpmSigner)
	if err != nil {
		return nil, fmt.Errorf("failed to create CSR: %w", err)
	}

	csrPEM := pem.EncodeToMemory(&pem.Block{
		Type:  "CERTIFICATE REQUEST",
		Bytes: csr,
	})

	return csrPEM, nil
}

func submitCsrForCertificate(url, token string, devId string, signingKey tpmutil.Handle) ([]byte, error) {
	crs, err := generateCsr(devId, signingKey)
	if err != nil {
		return nil, fmt.Errorf("error generating CSR: %w", err)
	}

	clientCertPEM, err := postData(url+"/certificates", crs, token, nil, 0)
	if err != nil {
		return nil, fmt.Errorf("error posting CSR to server: %w", err)
	}
	clientCertDER, err := pemToDER(clientCertPEM)
	if err != nil {
		return nil, fmt.Errorf("error converting PEM to DER: %w", err)
	}

	// make sure client cert is signed by the server's CA
	caCertPEM, err := os.ReadFile(verifierCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read server CA cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}
	clientCert, err := x509.ParseCertificate(clientCertDER)
	if err != nil {
		return nil, fmt.Errorf("error parsing client certificate: %w", err)
	}
	if _, err := clientCert.Verify(x509.VerifyOptions{
		Roots:     caCertPool,
		KeyUsages: []x509.ExtKeyUsage{x509.ExtKeyUsageClientAuth},
	}); err != nil {
		return nil, fmt.Errorf("client certificate verification failed: %w", err)
	}

	return clientCertDER, nil
}
