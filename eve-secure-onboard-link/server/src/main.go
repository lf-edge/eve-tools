// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto"
	"crypto/tls"
	"crypto/x509"
	"encoding/pem"
	"errors"
	"flag"
	"fmt"
	"log"
	"net/http"
	"os"

	"github.com/google/go-tpm/legacy/tpm2"
	"github.com/lf-edge/eve-tools/eve-activate-cred/common"
)

type Device struct {
	deviceID string
	// If credentialActivated is true, it means we can trust the AK to be used in csr
	credentialActivated bool
	cred                []byte
	ekVerified          bool
	ek                  *tpm2.Public
	ak                  *tpm2.Public
	certifiedKeys       []crypto.PublicKey
}

var (
	devices            = make(map[string]*Device)
	jwtSharedSecret    []byte
	skipEkVerification bool

	srvCaCert     *x509.Certificate
	srvCaKey      crypto.PrivateKey
	serverTlsCert tls.Certificate
	caCertPool    *x509.CertPool
)

const (
	certFile = "server_cert.pem"
	keyFile  = "server_key.pem"
)

func main() {
	genCerts := flag.Bool("gen-certs", false, "Generate new self-signed CA certificate and key and exit")
	srvPort := flag.String("port", common.ServerPort, "Port for the secure server")
	skipEkVerificationFlag := flag.Bool("skip-ek-verification", false, "Skip EK verification for untrusted devices")
	flag.Parse()

	if *genCerts {
		if err := setServerCert(true); err != nil {
			log.Fatalf("failed to generate new certificates: %v", err)
		}
		fmt.Println("New self-signed CA certificate and key generated successfully.")
		os.Exit(0)
	}

	if *skipEkVerificationFlag {
		skipEkVerification = true
		fmt.Println("[!] Skipping EK verification for untrusted devices")
	}

	mux := http.NewServeMux()
	mux.HandleFunc("/device-init", handleDeviceInit)
	mux.HandleFunc("/activate-cred-param", handleAcParam)
	mux.HandleFunc("/activate-cred", requireAuth(handleAcActive))
	mux.HandleFunc("/certificates", requireAuth(handleRequestCsr))
	mux.HandleFunc("/key-certification", requireAuth(handleKeyCertification))
	mux.HandleFunc("/secure", handleSecureRequest)

	if err := Initialize(); err != nil {
		log.Fatalf("failed to initialize: %v", err)
	}

	// Set up TLS configuration
	tlsConfig := &tls.Config{
		Certificates: []tls.Certificate{serverTlsCert},
		// don't be strict on the client certs, but request them,
		// "/secure" endpoint requires it.
		ClientAuth: tls.RequestClientCert,
		ClientCAs:  caCertPool,
		MinVersion: tls.VersionTLS12,
	}
	server := &http.Server{
		Addr:      *srvPort,
		TLSConfig: tlsConfig,
		Handler:   mux,
	}

	log.Printf("Server starting on port %s...\n", *srvPort)
	err := server.ListenAndServeTLS("", "")
	if err != nil {
		log.Fatalf("failed to start server: %v", err)
	}
}

func setServerCert(regen bool) error {
	certExists := fileExists(certFile)
	keyExists := fileExists(keyFile)

	var caCertPEM, keyPEM []byte
	var err error
	if certExists && keyExists && !regen {
		fmt.Println("Loading CA certificate and key files...")

		caCertPEM, err = os.ReadFile(certFile)
		if err != nil {
			return fmt.Errorf("failed to read cert file: %w", err)
		}
		keyPEM, err = os.ReadFile(keyFile)
		if err != nil {
			return fmt.Errorf("failed to read key file: %w", err)
		}

		caCert, err := parseCertFromPEM(caCertPEM)
		if err != nil {
			return fmt.Errorf("failed to parse CA certificate: %w", err)
		}
		caKey, err := parsePrivateKeyFromPEM(keyPEM)
		if err != nil {
			return fmt.Errorf("failed to parse CA private key: %w", err)
		}

		srvCaKey = caKey
		srvCaCert = caCert
	} else {
		fmt.Println("Generating new self-signed CA certificate and key...")

		caKey, caCert, err := generateSelfSignedCA()
		if err != nil {
			return fmt.Errorf("failed to generate CA: %w", err)
		}

		caCertPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "CERTIFICATE",
			Bytes: caCert.Raw,
		})
		if caCertPEM == nil {
			return errors.New("failed to encode CA certificate to PEM")
		}

		keyDER, err := x509.MarshalPKCS8PrivateKey(caKey)
		if err != nil {
			return fmt.Errorf("failed to marshal CA private key: %w", err)
		}
		keyPEM = pem.EncodeToMemory(&pem.Block{
			Type:  "PRIVATE KEY",
			Bytes: keyDER,
		})
		if keyPEM == nil {
			return errors.New("failed to encode CA private key to PEM")
		}

		if err := os.WriteFile(certFile, caCertPEM, 0600); err != nil {
			return fmt.Errorf("failed to save cert file: %w", err)
		}
		if err := os.WriteFile(keyFile, keyPEM, 0600); err != nil {
			return fmt.Errorf("failed to save key file: %w", err)
		}

		srvCaKey = caKey
		srvCaCert = caCert
	}

	// Load the certificate and key into TLS
	serverTlsCert, err = tls.X509KeyPair(caCertPEM, keyPEM)
	if err != nil {
		return fmt.Errorf("failed to create TLS certificate: %w", err)
	}

	caCertPool = x509.NewCertPool()
	if !caCertPool.AppendCertsFromPEM(caCertPEM) {
		return fmt.Errorf("failed to append CA certificate to cert pool")
	}

	return nil
}

func Initialize() error {
	// Generate a JWT shared secret
	var err error
	jwtSharedSecret, err = generateJWTSecret()
	if err != nil {
		return fmt.Errorf("failed to generate JWT secret: %w", err)
	}

	if err := setServerCert(false); err != nil {
		return fmt.Errorf("failed to set server certificate: %w", err)
	}

	return nil
}
