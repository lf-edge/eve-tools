// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"net/http"
	"net/http/httptest"
	"os"
	"testing"
)

// testdata/9.9.0-rc13.* are the tagger statement and the sums file it covers
// from release 9.9.0-rc13 of a fork, signed by its release-sign.yml on its
// sign-master branch.
const (
	taggerTag    = "9.9.0-rc13"
	taggerCommit = "f8f7df7e27d847b92b2c9cca754c665c76f0cecd"
	taggerLogin  = "eriknordmark"
	taggerID     = 26916952
)

func TestTagger(t *testing.T) {
	bundle, err := os.ReadFile("testdata/9.9.0-rc13.tagger.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	sums, err := os.ReadFile("testdata/9.9.0-rc13.signtest.sha256sums")
	if err != nil {
		t.Fatal(err)
	}
	p := defaultPolicy(forkRepo, forkSigner)
	otherType := p
	otherType.taggerType = "https://github.com/lf-edge/eve/release-tagger/v1"
	otherSigner := defaultPolicy(forkRepo, defaultSignerRef)

	tests := []struct {
		name    string
		policy  policy
		sums    [][]byte
		tag     string
		commit  string
		wantErr string
	}{
		{name: "tagger", policy: p, sums: [][]byte{sums}, tag: taggerTag, commit: taggerCommit},
		{name: "other release", policy: p, sums: [][]byte{sums}, tag: "9.9.0-rc12", commit: taggerCommit, wantErr: "signed for release 9.9.0-rc13, not 9.9.0-rc12"},
		{name: "other commit", policy: p, sums: [][]byte{sums}, tag: taggerTag, commit: "4e453340f2c5158b00373ae6863d1b8dad646b16", wantErr: "names 9.9.0-rc13 at"},
		{name: "not a subject", policy: p, sums: [][]byte{sums, append(sums, '\n')}, tag: taggerTag, commit: taggerCommit, wantErr: "artifact"},
		{name: "other predicate type", policy: otherType, sums: [][]byte{sums}, tag: taggerTag, commit: taggerCommit, wantErr: "not a https://github.com/lf-edge/eve/release-tagger/v1 statement"},
		{name: "other signer", policy: otherSigner, sums: [][]byte{sums}, tag: taggerTag, commit: taggerCommit, wantErr: "expected SAN value"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := newVerifier(testRoot(t), tc.policy)
			if err != nil {
				t.Fatal(err)
			}
			u, err := v.checkTagger(bundle, tc.sums, tc.tag, tc.commit)
			checkErr(t, err, tc.wantErr)
			if err == nil && (u.Login != taggerLogin || u.ID != taggerID) {
				t.Fatalf("tagger %v, want %s %d", u, taggerLogin, taggerID)
			}
		})
	}
}

func TestEnvironmentApprovers(t *testing.T) {
	srv := httptest.NewServer(http.HandlerFunc(func(w http.ResponseWriter, r *http.Request) {
		if r.URL.Path != "/repos/eriknordmark/eve/actions/runs/41144150800/approvals" {
			http.NotFound(w, r)
			return
		}
		w.Write([]byte(`[
			{"user": {"login": "a", "id": 1}, "state": "approved", "environments": [{"name": "release"}]},
			{"user": {"login": "b", "id": 2}, "state": "rejected", "environments": [{"name": "release"}]},
			{"user": {"login": "c", "id": 3}, "state": "approved", "environments": [{"name": "other"}]},
			{"user": {"login": "a", "id": 1}, "state": "approved", "environments": [{"name": "release"}]}
		]`))
	}))
	defer srv.Close()
	saved := githubAPI
	githubAPI = srv.URL
	defer func() { githubAPI = saved }()

	v, err := newVerifier(testRoot(t), defaultPolicy(forkRepo, forkSigner))
	if err != nil {
		t.Fatal(err)
	}
	users, err := v.environmentApprovers("https://github.com/eriknordmark/eve/actions/runs/41144150800/attempts/1")
	if err != nil {
		t.Fatal(err)
	}
	if len(users) != 1 || users[0] != (githubUser{Login: "a", ID: 1}) {
		t.Fatalf("approvers %v, want only a (1)", users)
	}
	if _, err := v.environmentApprovers("https://github.com/lf-edge/eve/actions/runs/41144150800/attempts/1"); err == nil {
		t.Fatal("accepted a run of another repository")
	}
}
