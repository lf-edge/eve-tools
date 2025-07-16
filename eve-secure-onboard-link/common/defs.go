// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package common

const (
	ServerPort = ":9191"
)

type AcParamRes struct {
	DeviceID string `json:"device_id"`
	Token    string `json:"token"`
	Cred     []byte `json:"cred"`
}

type InitDeviceReq struct {
	EkCert []byte `json:"ek_cert"`
	EkPub  []byte `json:"ek_pub"`
}
