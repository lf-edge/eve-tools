// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"net/http"

	"github.com/google/go-tpm/tpmutil"
	"github.com/lf-edge/eve-tools/eve-activate-cred/common"
	vcom "github.com/lf-edge/eve/pkg/pillar/vcom/go-api"
	"google.golang.org/protobuf/proto"
)

func getActivateCredParams() ([]byte, error) {
	paramsRequest := vcom.TpmRequestActivateCredParams{
		Index: uint32(vcom.TpmAIKHandle),
	}
	out, err := proto.Marshal(&paramsRequest)
	if err != nil {
		return nil, fmt.Errorf("error when marshalling request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/activatecredparams", bytes.NewBuffer(out))
	if err != nil {
		return nil, fmt.Errorf("error when creating request: %w", err)
	}
	signResp, err := getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("error when sending request: %w", err)
	}
	defer signResp.Body.Close()

	if signResp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code 200, got %d", signResp.StatusCode)
	}

	body, err := io.ReadAll(signResp.Body)
	if err != nil {
		return nil, fmt.Errorf("error when reading response body: %w", err)
	}

	var tpmRespACParams vcom.TpmResponseActivateCredParams
	err = proto.Unmarshal(body, &tpmRespACParams)
	if err != nil {
		return nil, fmt.Errorf("error when unmarshalling response body: %w", err)
	}

	return body, nil
}

func completeAkActivationWithVerifier(url, token string, cred []byte) error {
	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/activatecred", bytes.NewBuffer(cred))
	if err != nil {
		return fmt.Errorf("error creating request: %w", err)
	}
	credResp, err := getClient().Do(req)
	if err != nil {
		return fmt.Errorf("error sending request: %w", err)
	}
	defer credResp.Body.Close()
	if credResp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code 200, got %d", credResp.StatusCode)
	}
	body, err := io.ReadAll(credResp.Body)
	if err != nil {
		return fmt.Errorf("error reading response body: %w", err)
	}

	var tpmResp vcom.TpmResponseActivatedCred
	err = proto.Unmarshal(body, &tpmResp)
	if err != nil {
		return fmt.Errorf("error unmarshalling response body: %w", err)
	} else {
		fmt.Printf("\tRecovered credential: %x\n", tpmResp.Secret)
	}
	_, err = postData(url+"/activate-cred", body, token, nil, 0)
	if err != nil {
		return fmt.Errorf("error posting activate credential parameters: %w", err)
	}

	return nil
}

func proveKeyCertificationWithVerifier(url, token string, signingKey tpmutil.Handle) error {
	request := vcom.TpmRequestCertify{
		Index: uint32(signingKey),
	}
	out, err := proto.Marshal(&request)
	if err != nil {
		return fmt.Errorf("error when marshalling request: %w", err)
	}
	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/certifykey", bytes.NewBuffer(out))
	if err != nil {
		return fmt.Errorf("error when creating request: %w", err)
	}
	resp, err := getClient().Do(req)
	if err != nil {
		return fmt.Errorf("error when sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
	}
	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return fmt.Errorf("error when reading response body: %w", err)
	}

	// send the certification data to the server to establish trust in the new key
	_, err = postData(url+"/key-certification", body, token, nil, 0)
	if err != nil {
		return fmt.Errorf("error posting activate credential parameters: %w", err)
	}

	return nil
}

func getPub(key tpmutil.Handle) ([]byte, error) {
	request := vcom.TpmRequestGetPub{
		Index: uint32(key),
	}
	out, err := proto.Marshal(&request)
	if err != nil {
		return nil, fmt.Errorf("error when marshalling request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/getpub", bytes.NewBuffer(out))
	if err != nil {
		return nil, fmt.Errorf("error when creating request: %w", err)
	}
	resp, err := getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("error when sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error when reading response body: %w", err)
	}
	var tpmResp vcom.TpmResponseGetPub
	err = proto.Unmarshal(body, &tpmResp)
	if err != nil {
		return nil, fmt.Errorf("error when unmarshalling response body: %w", err)
	}

	if len(tpmResp.Public) == 0 {
		return nil, fmt.Errorf("expected non-empty EK, got empty string")
	}

	return tpmResp.Public, nil
}

func getEkCertificate() ([]byte, error) {
	request := vcom.TpmRequestReadNv{
		Index: vcom.TpmEKCertHandle,
	}
	out, err := proto.Marshal(&request)
	if err != nil {
		return nil, fmt.Errorf("error when marshalling request: %w", err)
	}

	req, err := http.NewRequest(http.MethodPost, "http://vsock/tpm/readnv", bytes.NewBuffer(out))
	if err != nil {
		return nil, fmt.Errorf("error when creating request: %w", err)
	}
	resp, err := getClient().Do(req)
	if err != nil {
		return nil, fmt.Errorf("error when sending request: %w", err)
	}
	defer resp.Body.Close()

	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("expected status code 200, got %d", resp.StatusCode)
	}

	body, err := io.ReadAll(resp.Body)
	if err != nil {
		return nil, fmt.Errorf("error when reading response body: %w", err)
	}
	var tpmResp vcom.TpmResponseReadNv
	err = proto.Unmarshal(body, &tpmResp)
	if err != nil {
		return nil, fmt.Errorf("error when unmarshalling response body: %w", err)
	}

	if len(tpmResp.Data) == 0 {
		return nil, fmt.Errorf("expected non-empty EK cert, got empty")
	}

	return tpmResp.Data, nil
}

func initiateAkActivationWithVerifier(url string) (*common.AcParamRes, error) {
	acParam, err := getActivateCredParams()
	if err != nil {
		return nil, fmt.Errorf("error getting activate credential parameters: %w", err)
	}

	// initiate the trust process by sending the AC parameters to the server
	out, err := postData(url+"/activate-cred-param", acParam, "", nil, 0)
	if err != nil {
		return nil, fmt.Errorf("error posting activate credential parameters: %w", err)
	}

	// We recived the credential from the server, now we need to activate it
	// to prove the device identity and establish trust in AK
	response := common.AcParamRes{}
	err = json.Unmarshal(out, &response)
	if err != nil {
		return nil, fmt.Errorf("error unmarshalling activate credential response: %w", err)
	}

	return &response, nil
}
