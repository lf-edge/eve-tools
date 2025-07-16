// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/lf-edge/eve-tools/eve-activate-cred/common"
)

func handleDeviceInit(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Println("[+] Received device init...")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to read request body: %v", err))
		return
	}
	defer r.Body.Close()

	var initReq common.InitDeviceReq
	err = json.Unmarshal(body, &initReq)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to unmarshal request body: %v", err))
		return
	}

	err = verifyEkCertificate(initReq.EkCert, initReq.EkPub)
	if err != nil {
		if skipEkVerification {
			fmt.Printf("\tEK verification failed %v, but skipping due to configuration\n", err)
		} else {
			fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to verify EK certificate: %v", err))
			return
		}
	} else {
		fmt.Println("\tEK certificate verified successfully")
	}

	deviceID, err := registerDevice(initReq.EkPub)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusInternalServerError, "failed to register device: %v", err))
		return
	}
	fmt.Printf("\tUntrusted device registered with ID: %s\n", deviceID)

	w.WriteHeader(http.StatusOK)
}

func handleAcParam(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}
	fmt.Println("[+] Received activate credential parameters from untrusted device...")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to read request body"))
		return
	}
	defer r.Body.Close()

	// verify activatate credential parameters and generate the credential
	cred, credPlain, ekPub, akPub, err := verifyActivateCredParameters(body)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to verify activate credential parameters: %v", err))
		return
	}
	deviceID, err := updateDeviceCredAcInfo(ekPub, akPub, credPlain)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusInternalServerError, "failed to update device: %v", err))
		return
	}

	token, err := generateJWT(deviceID)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusInternalServerError, "failed to generate JWT: %v", err))
		return
	}
	responseJson, err := json.Marshal(common.AcParamRes{
		DeviceID: deviceID,
		Token:    token,
		Cred:     cred,
	})
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusInternalServerError, "failed to marshal response: %v", err))
		return
	}

	fmt.Printf("\tJWT generated for device : %s...\n", token[:32])
	fmt.Printf("\tUpdated device registered with ID: %s\n", deviceID)
	w.Header().Add("Content-Type", "application/json")
	w.WriteHeader(http.StatusOK)
	w.Write(responseJson)
}

func handleAcActive(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Println("[+] Received activate credential request...")
	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to read request body: %v", err))
		return
	}
	defer r.Body.Close()

	deviceID, ok := r.Context().Value("device_id").(string)
	if !ok {
		fmt.Println(handleHTTPError(w, http.StatusUnauthorized, "device ID not found in context"))
		return
	}
	device, ok := devices[deviceID]
	if !ok {
		fmt.Println(handleHTTPError(w, http.StatusNotFound, "device not found: %s", deviceID))
		return
	}
	fmt.Printf("\tDevice ID from JWT : %s\n", deviceID)
	fmt.Printf("\tDevice credential : %x\n", device.cred)

	// verify the credential is activated (decrypted)
	if verifyCredentialActivation(body, device.cred) != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to verify credential activation: %v", err))
		return
	}

	// Mark the device as activated
	if _, exists := devices[deviceID]; !exists {
		fmt.Println(handleHTTPError(w, http.StatusNotFound, "device not found: %s", deviceID))
		return
	} else {
		device := devices[deviceID]
		device.credentialActivated = true
	}

	fmt.Println("\tDevice AK is now trusted")
	w.WriteHeader(http.StatusOK)
}

func handleRequestCsr(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}
	deviceID, ok := r.Context().Value("device_id").(string)
	if !ok {
		fmt.Println(handleHTTPError(w, http.StatusUnauthorized, "device ID not found in context"))
		return
	}

	fmt.Printf("[+] Received request for CSR from device %s\n", deviceID)
	device, exists := devices[deviceID]
	if !exists || !device.credentialActivated {
		http.Error(w, "device not found or not trusted", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to read request body: %v", err))
		return
	}
	defer r.Body.Close()

	// perform request validation and sign the CSR, we only sign a CSR signed by a certified key
	certPEM, err := signClientCertificate(body, deviceID)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to sign client certificate: %v", err))
		return
	}

	fmt.Println("\tCSR signed successfully, sending back the certificate...")
	w.Header().Set("Content-Type", "application/x-pem-file")
	w.WriteHeader(http.StatusOK)
	w.Write(certPEM)
}

func handleKeyCertification(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}
	deviceID, ok := r.Context().Value("device_id").(string)
	if !ok {
		fmt.Println(handleHTTPError(w, http.StatusUnauthorized, "device ID not found in context"))
		return
	}

	fmt.Printf("[+] Received key certification request from device %s\n", deviceID)
	device, exists := devices[deviceID]
	if !exists || !device.credentialActivated {
		http.Error(w, "device not found or not trusted", http.StatusNotFound)
		return
	}

	body, err := io.ReadAll(r.Body)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to read request body: %v", err))
		return
	}
	defer r.Body.Close()

	// perform verification of key certification attestation payload and record the certified key
	pubKey, err := verifyKeyCertification(body, deviceID)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusBadRequest, "failed to verify key certification: %v", err))
		return
	}
	devices[deviceID].certifiedKeys = append(devices[deviceID].certifiedKeys, pubKey)

	fmt.Printf("\tKey certification successful for device: %s\n", deviceID)
	w.WriteHeader(http.StatusOK)
}

func handleSecureRequest(w http.ResponseWriter, r *http.Request) {
	if r.Method != http.MethodPost {
		http.Error(w, "Only POST is allowed", http.StatusMethodNotAllowed)
		return
	}

	fmt.Println("[+] Received access to the secure endpoint...")

	// check if the client is authorized by verifying the client certificate signed by our CA
	err := isClientAuthorized(r.TLS.PeerCertificates)
	if err != nil {
		fmt.Println(handleHTTPError(w, http.StatusForbidden, "client authorization failed: %v", err))
		return
	}

	fmt.Println("\tClient authorization successful")
	w.WriteHeader(http.StatusOK)
	w.Write([]byte("Super secret data"))
}
