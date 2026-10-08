// Copyright (c) 2025 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"runtime"
	"strings"
	"testing"
	"time"

	"github.com/golang-jwt/jwt/v5"
)

func setTestSecret(t *testing.T) {
	t.Helper()
	old := jwtSharedSecret
	jwtSharedSecret = []byte("test-secret-0123456789abcdef")
	t.Cleanup(func() { jwtSharedSecret = old })
}

func signHS256(t *testing.T, claims jwt.MapClaims, secret []byte) string {
	t.Helper()
	s, err := jwt.NewWithClaims(jwt.SigningMethodHS256, claims).SignedString(secret)
	if err != nil {
		t.Fatal(err)
	}
	return s
}

func TestJWTRoundTrip(t *testing.T) {
	setTestSecret(t)
	tok, err := generateJWT("dev-1")
	if err != nil {
		t.Fatal(err)
	}
	id, err := verifyJWT(tok)
	if err != nil || id != "dev-1" {
		t.Fatalf("verifyJWT = %q, %v; want dev-1, nil", id, err)
	}
}

func TestJWTRejected(t *testing.T) {
	setTestSecret(t)
	now := time.Now()
	none, err := jwt.NewWithClaims(jwt.SigningMethodNone, jwt.MapClaims{
		"device_id": "dev-1", "exp": now.Add(time.Minute).Unix(),
	}).SignedString(jwt.UnsafeAllowNoneSignatureType)
	if err != nil {
		t.Fatal(err)
	}
	cases := map[string]string{
		"expired": signHS256(t, jwt.MapClaims{
			"device_id": "dev-1", "exp": now.Add(-time.Minute).Unix(),
		}, jwtSharedSecret),
		"wrong secret": signHS256(t, jwt.MapClaims{
			"device_id": "dev-1", "exp": now.Add(time.Minute).Unix(),
		}, []byte("other-secret")),
		"missing device_id": signHS256(t, jwt.MapClaims{
			"exp": now.Add(time.Minute).Unix(),
		}, jwtSharedSecret),
		"alg none": none,
		"garbage":  "not.a.jwt",
	}
	for name, tok := range cases {
		if id, err := verifyJWT(tok); err == nil {
			t.Errorf("%s: verifyJWT accepted token, device_id %q", name, id)
		}
	}
}

// CVE-2025-30204: a token of many '.' must not cost allocation
// proportional to its length.
func TestJWTManyPeriodsBoundedAlloc(t *testing.T) {
	setTestSecret(t)
	tok := strings.Repeat(".", 1<<20)
	var before, after runtime.MemStats
	runtime.GC()
	runtime.ReadMemStats(&before)
	if _, err := verifyJWT(tok); err == nil {
		t.Fatal("verifyJWT accepted a malformed token")
	}
	runtime.ReadMemStats(&after)
	if got := after.TotalAlloc - before.TotalAlloc; got > 4*uint64(len(tok)) {
		t.Fatalf("verifyJWT allocated %d bytes for a %d-byte token", got, len(tok))
	}
}
