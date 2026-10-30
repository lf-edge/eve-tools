// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"fmt"
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
			checkErr(t, checkAttestationBundle(tc.sv, data, tc.repo, tc.tag, tc.commit, tc.files, noPeel), tc.wantErr)
		})
	}
}

func noPeel(sha string) (string, error) {
	return "", fmt.Errorf("%s: 404 Not Found", sha)
}

// TestReleaseAttestationAnnotatedTag checks GitHub's attestation of
// lf-edge/eve 17.12.0, whose annotated tag the attestation names by
// the tag object rather than the commit.
func TestReleaseAttestationAnnotatedTag(t *testing.T) {
	data, err := os.ReadFile("testdata/eve-17.12.0.release-attestation.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	tr, err := root.NewTrustedRootFromPath("testdata/github_trusted_root.json")
	if err != nil {
		t.Fatal(err)
	}
	sv, err := verify.NewVerifier(tr, verify.WithSignedTimestamps(1))
	if err != nil {
		t.Fatal(err)
	}
	const (
		repo      = "lf-edge/eve"
		tag       = "17.12.0"
		tagObject = "f12a3cfc8247dd8ca2c87b0b80848d8e35b5e20f"
		commit    = "ed75ebb94fd7c65e6cbe3fb5d883c062b1956b7f"
	)
	files := map[string]string{
		"amd64.kvm.generic.sha256sums": "a9d5f325f8a3881bd9a1c736e0014d428268b569f19365f6a5f9a360c5d35a58",
		"arm64.kvm.generic.sha256sums": "629314fc14850f6374bb0e3c3ba3bf82202dbfd8c06e15c464d3c1f405d0cb1f",
	}
	peelTo := func(c string) func(string) (string, error) {
		return func(sha string) (string, error) {
			if sha != tagObject {
				return "", fmt.Errorf("unexpected tag object %s", sha)
			}
			return c, nil
		}
	}
	tests := []struct {
		name    string
		peel    func(string) (string, error)
		wantErr string
	}{
		{name: "tag peels to the built commit", peel: peelTo(commit)},
		{name: "tag peels to another commit", peel: peelTo(strings.Repeat("0", 40)), wantErr: "the signing run built"},
		{name: "not a tag object", peel: noPeel, wantErr: "not an annotated tag"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			checkErr(t, checkAttestationBundle(sv, data, repo, tag, commit, files, tc.peel), tc.wantErr)
		})
	}
}

// TestPeelTag reads a tag object from the GitHub API.
func TestPeelTag(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		switch r.URL.Path {
		case "/repos/o/r/git/tags/aaa":
			fmt.Fprint(w, `{"object":{"type":"commit","sha":"ccc"}}`)
		case "/repos/o/r/git/tags/bbb":
			fmt.Fprint(w, `{"object":{"type":"tag","sha":"aaa"}}`)
		default:
			http.NotFound(w, r)
		}
	}))
	defer srv.Close()
	saved := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = saved }()
	peel := peelTag("o/r")
	if c, err := peel("aaa"); err != nil || c != "ccc" {
		t.Errorf("peel(aaa) = %q, %v; want ccc", c, err)
	}
	if _, err := peel("bbb"); err == nil || !strings.Contains(err.Error(), "points at a tag") {
		t.Errorf("peel(bbb) error = %v; want points at a tag", err)
	}
	if _, err := peel("ddd"); err == nil || !strings.Contains(err.Error(), "404") {
		t.Errorf("peel(ddd) error = %v; want 404", err)
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
