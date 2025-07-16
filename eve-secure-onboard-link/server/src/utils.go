// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/rand"
	"crypto/x509"
	"encoding/pem"
	"fmt"
	"net/http"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
)

func handleHTTPError(w http.ResponseWriter, httpCode int, format string, a ...any) string {
	err := fmt.Sprintf(format, a...)
	http.Error(w, err, httpCode)
	return err
}

func generateJWTSecret() ([]byte, error) {
	secret := make([]byte, 32)
	_, err := rand.Read(secret)
	return secret, err
}

func getDigest(alg tpm2.Algorithm, data []byte) ([]byte, crypto.Hash, error) {
	hash, err := alg.Hash()
	if err != nil {
		return nil, crypto.Hash(0), fmt.Errorf("failed to get hash algorithm for AK: %w", err)
	}
	hasher := hash.New()
	hasher.Write(data)
	return hasher.Sum(nil), hash, nil
}

func fileExists(path string) bool {
	info, err := os.Stat(path)
	return err == nil && !info.IsDir()
}

func parseCertFromPEM(certPEM []byte) (*x509.Certificate, error) {
	block, _ := pem.Decode(certPEM)
	if block == nil || block.Type != "CERTIFICATE" {
		return nil, fmt.Errorf("failed to decode PEM block containing certificate")
	}

	cert, err := x509.ParseCertificate(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse certificate: %w", err)
	}

	return cert, nil
}

func parsePrivateKeyFromPEM(keyPEM []byte) (crypto.PrivateKey, error) {
	block, _ := pem.Decode(keyPEM)
	if block == nil || block.Type != "PRIVATE KEY" {
		return nil, fmt.Errorf("failed to decode PEM block containing private key")
	}

	parsedKey, err := x509.ParsePKCS8PrivateKey(block.Bytes)
	if err != nil {
		return nil, fmt.Errorf("failed to parse PKCS#8 private key: %w", err)
	}

	return parsedKey, nil
}
