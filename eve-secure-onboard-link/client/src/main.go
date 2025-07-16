// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"flag"
	"fmt"
	"log"

	"github.com/lf-edge/eve-tools/eve-activate-cred/common"
	vcom "github.com/lf-edge/eve/pkg/pillar/vcom/go-api"
)

const (
	verifierCertFile = "server_cert.pem"
	defaultServerURL = "https://localhost" + common.ServerPort
)

func main() {
	serverURL := flag.String("server", defaultServerURL, "URL of the secure server")
	useLocalCID = flag.Bool("use-local-cid", false, "Use local CID for VSOCK communication")
	flag.Parse()

	fmt.Println("[0] Initiating device registration and activation...")
	ekPub, err := getPub(vcom.TpmEKHandle)
	if err != nil {
		log.Fatalf("error getting EK public key: %v", err)
	}
	ekCert, err := getEkCertificate()
	if err != nil {
		log.Fatalf("error getting EK certificate: %v", err)
	}
	init := common.InitDeviceReq{
		EkCert: ekCert,
		EkPub:  ekPub,
	}
	out, err := json.Marshal(init)
	if err != nil {
		log.Fatalf("error marshalling device init request: %v", err)
	}
	_, err = postData(*serverURL+"/device-init", out, "", nil, 0)
	if err != nil {
		log.Fatalf("error posting EK certificate to server: %v", err)
	}

	fmt.Println("[1] Establishing trust in Attestation Key (AK)...")
	acParam, err := initiateAkActivationWithVerifier(*serverURL)
	if err != nil {
		log.Fatalf("error initiating AK activation: %v", err)
	}
	fmt.Printf("\tReceived device ID: %s\n", acParam.DeviceID)
	fmt.Printf("\tReceived token: %s...\n", acParam.Token[:16])

	fmt.Println("[2] Proving TPM holds the EK and AK can decrypt credential...")
	err = completeAkActivationWithVerifier(*serverURL, acParam.Token, acParam.Cred)
	if err != nil {
		log.Fatalf("error completing AK activation: %v", err)
	}
	fmt.Println("[3] Activation completed successfully, verifier now trusts the AK.")

	fmt.Println("[4] Proving signing key is certified by the AK...")
	err = proveKeyCertificationWithVerifier(*serverURL, acParam.Token, vcom.TpmEcdhHandle)
	if err != nil {
		log.Fatalf("error proving key certification: %v", err)
	}
	fmt.Println("[5] Key certification completed successfully, verifier now trusts the signing key.")

	fmt.Println("[6] Submitting CSR for certificate...")
	clientCertDER, err := submitCsrForCertificate(*serverURL, acParam.Token, acParam.DeviceID, vcom.TpmEcdhHandle)
	if err != nil {
		log.Fatalf("error submitting CSR for certificate: %v", err)
	}
	fmt.Println("[7] CSR submitted successfully, received signed client certificate.")

	fmt.Println("[8] Accessing secure endpoint with client certificate...")
	out, err = postData(*serverURL+"/secure", nil, "", clientCertDER, vcom.TpmEcdhHandle)
	if err != nil {
		log.Fatalf("error posting CSR to server: %v", err)
	}
	fmt.Printf("\tReceived data from server: \"%s\"\n", string(out))
	fmt.Println("[9] Secure endpoint accessed successfully, client certificate is valid.")
	fmt.Println("[10] All operations completed successfully.")
}
