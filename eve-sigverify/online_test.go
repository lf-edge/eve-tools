// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"net/http"
	"net/http/httptest"
	"os"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// TestReleaseAttestation checks GitHub's immutable-release attestation of
// cli/cli v2.102.0 against GitHub's trusted root, both saved in testdata.
func TestReleaseAttestation(t *testing.T) {
	data, err := os.ReadFile("testdata/cli-v2.102.0.release-attestation.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := root.NewTrustedRootFromPath("testdata/github_trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	gh, err := verify.NewVerifier(tr, verify.WithSignedTimestamps(1))
	if err != nil {
		t.Fatal(err)
	}
	sigstore, err := verify.NewVerifier(testRoot(t), verify.WithSignedTimestamps(1))
	if err != nil {
		t.Fatal(err)
	}
	const (
		repo    = "cli/cli"
		tag     = "v2.102.0"
		commit  = "fc4b137cdef0a6bd28fd461b7cf9c84a5812a8cd"
		sums    = "gh_2.102.0_checksums.txt"
		sumsSHA = "afe49e9affa232faa8212aed035417166f6ade9b9470acb53d4dbd28c0504e8d"
		deb     = "gh_2.102.0_linux_386.deb"
		debSHA  = "759b31942b78c05434a5d958fdacfc66aaf81446e283b4a8b1444104cf9de850"
	)
	files := map[string]string{sums: sumsSHA, deb: debSHA}
	tests := []struct {
		name              string
		sv                *verify.Verifier
		repo, tag, commit string
		files             map[string]string
		wantErr           string
	}{
		{name: "valid", sv: gh, repo: repo, tag: tag, commit: commit, files: files},
		{name: "Sigstore public-good root", sv: sigstore, repo: repo, tag: tag, commit: commit, files: files, wantErr: "certificate"},
		{name: "other tag", sv: gh, repo: repo, tag: "v2.101.0", commit: commit, files: files, wantErr: "attestation is for cli/cli v2.102.0"},
		{name: "other repository", sv: gh, repo: "lf-edge/eve", tag: tag, commit: commit, files: files, wantErr: "attestation is for cli/cli"},
		{name: "other commit", sv: gh, repo: repo, tag: tag, commit: strings.Repeat("0", 40), files: files, wantErr: "the signing run built"},
		{name: "asset not attested", sv: gh, repo: repo, tag: tag, commit: commit, files: map[string]string{sums: sumsSHA, "extra.img": debSHA}, wantErr: "asset extra.img"},
		{name: "asset swapped", sv: gh, repo: repo, tag: tag, commit: commit, files: map[string]string{sums: sumsSHA, deb: sumsSHA}, wantErr: "asset " + deb},
		{name: "digest not a subject", sv: gh, repo: repo, tag: tag, commit: commit, files: map[string]string{"a": debSHA[:62] + "00"}, wantErr: "artifact"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkErr(t, checkAttestationBundle(tc.sv, data, tc.repo, tc.tag, tc.commit, tc.files), tc.wantErr)
		})
	}
}

// TestFetchBundle reads the snappy-compressed form GitHub serves from
// bundle_url.
func TestFetchBundle(t *testing.T) {
	want, err := os.ReadFile("testdata/cli-v2.102.0.release-attestation.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	srv := httptest.NewServer(http.FileServer(http.Dir("testdata")))
	defer srv.Close()
	for _, f := range []string{"cli-v2.102.0.release-attestation.sigstore.json.sn", "cli-v2.102.0.release-attestation.sigstore.json"} {
		got, err := fetchBundle(srv.URL + "/" + f)
		if err != nil || !bytes.Equal(got, want) {
			t.Errorf("%s: %d bytes, %v", f, len(got), err)
		}
	}
	if _, err := fetchBundle(srv.URL + "/signtest.sha256sums"); err == nil {
		t.Error("accepted a file that is neither JSON nor snappy")
	}
}
