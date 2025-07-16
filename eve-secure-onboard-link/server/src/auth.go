// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"context"
	"crypto/x509"
	"fmt"
	"net/http"
	"strings"
	"time"

	"github.com/golang-jwt/jwt"
)

func requireAuth(next http.HandlerFunc) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		authHeader := r.Header.Get("Authorization")
		if authHeader == "" || !strings.HasPrefix(authHeader, "Bearer ") {
			fmt.Println(handleHTTPError(w, http.StatusUnauthorized, "Authorization header is missing or invalid"))
			return
		}
		tokenString := strings.TrimPrefix(authHeader, "Bearer ")
		deviceId, err := verifyJWT(tokenString)
		if err != nil {
			fmt.Println(handleHTTPError(w, http.StatusForbidden, "failed to verify JWT: %v", err))
			return
		}

		device, exists := devices[deviceId]
		if !exists {
			fmt.Println(handleHTTPError(w, http.StatusNotFound, "device not found: %s", deviceId))
			return
		}
		if !device.ekVerified {
			fmt.Println(handleHTTPError(w, http.StatusForbidden, "device EK not verified: %s", deviceId))
			return
		}

		ctx := context.WithValue(r.Context(), "device_id", deviceId)
		r = r.WithContext(ctx)
		next(w, r)
	}
}

func verifyJWT(tokenStr string) (string, error) {
	token, err := jwt.Parse(tokenStr, func(token *jwt.Token) (any, error) {
		if _, ok := token.Method.(*jwt.SigningMethodHMAC); !ok {
			return nil, fmt.Errorf("unexpected signing method: %v", token.Header["alg"])
		}
		return jwtSharedSecret, nil
	})
	if err != nil || !token.Valid {
		return "", err
	}

	claims := token.Claims.(jwt.MapClaims)
	deviceID, ok := claims["device_id"].(string)
	if !ok {
		return "", fmt.Errorf("missing device_id claim")
	}
	return deviceID, nil
}

func generateJWT(deviceID string) (string, error) {
	claims := jwt.MapClaims{
		"device_id": deviceID,
		"exp":       time.Now().Add(10 * time.Minute).Unix(), // expires in 10 min
		"iat":       time.Now().Unix(),
	}

	token := jwt.NewWithClaims(jwt.SigningMethodHS256, claims)
	return token.SignedString(jwtSharedSecret)
}

func isClientAuthorized(peerCerts []*x509.Certificate) error {
	// check if we have at least one client certificate
	if len(peerCerts) == 0 {
		return fmt.Errorf("client certificate is required")
	}

	// loop through client certificates and at least one should be signed by our CA
	found := false
	for _, clientCert := range peerCerts {
		fmt.Printf("\tClient certificate subject (device id): %s\n", clientCert.Subject.CommonName)
		// beside signature validation, we can also check other fields like DNSNames, IPAddresses,
		// key usage, validity period, etc. but for simplicity, we just check the signature.
		if clientCert.CheckSignatureFrom(srvCaCert) == nil {
			found = true
		}
	}
	if !found {
		return fmt.Errorf("client certificate is not signed by our CA")
	}

	return nil
}
