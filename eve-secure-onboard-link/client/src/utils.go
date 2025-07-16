// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"fmt"
	"io"
	"net/http"
	"os"

	"github.com/google/go-tpm/tpmutil"
)

func postData(url string, data []byte, auth string, clientCertDER []byte, signingKey tpmutil.Handle) ([]byte, error) {
	req, err := http.NewRequest("POST", url, bytes.NewBuffer(data))
	if err != nil {
		return nil, err
	}

	if auth != "" {
		req.Header.Set("Authorization", "Bearer "+auth)
	}

	// Load the CA certificate used by the server
	caCertPEM, err := os.ReadFile(verifierCertFile)
	if err != nil {
		return nil, fmt.Errorf("failed to read server CA cert: %v", err)
	}
	caCertPool := x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return nil, fmt.Errorf("failed to append CA certificate to pool")
	}
	tlsConfig := &tls.Config{
		RootCAs: caCertPool,
	}

	if len(clientCertDER) > 0 {
		tpmSigner, _, err := getTpmSigner(signingKey)
		if err != nil {
			return nil, fmt.Errorf("error getting TPM signer: %v", err)
		}

		tlsCert := tls.Certificate{
			Certificate: [][]byte{clientCertDER},
			PrivateKey:  tpmSigner,
		}
		tlsConfig.Certificates = []tls.Certificate{tlsCert}
	}
	client := &http.Client{
		Transport: &http.Transport{
			TLSClientConfig: tlsConfig,
		},
	}

	resp, err := client.Do(req)
	if err != nil {
		return nil, fmt.Errorf("error making HTTP request: %v", err)
	}
	defer resp.Body.Close()

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, err
	}

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("unexpected status code: %d, response: %s", resp.StatusCode, body)
	}

	return body, nil
}

func pemToDER(pemBytes []byte) ([]byte, error) {
	block, _ := pem.Decode(pemBytes)
	if block == nil {
		return nil, errors.New("failed to decode PEM block")
	}
	return block.Bytes, nil
}
