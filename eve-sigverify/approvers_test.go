// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"net/http"
	"net/http/httptest"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/verify"
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

// taggerImage is one of the image digests the 9.9.0-rc13 tagger statement
// lists as a subject.
const taggerImage = "028cc8dbb869c10cdd9a4a9aa97f54ab670a177c4b0845fb70d0fbff5052f904"

func digestOption(t *testing.T, hexDigest string) verify.ArtifactPolicyOption {
	t.Helper()
	d, err := hex.DecodeString(hexDigest)
	if err != nil {
		t.Fatal(err)
	}
	return verify.WithArtifactDigest("sha256", d)
}

// TestTaggerForImage checks that a tagger statement is bound to an image by
// the image's digest.
func TestTaggerForImage(t *testing.T) {
	bundle, err := os.ReadFile("testdata/9.9.0-rc13.tagger.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	v, err := newVerifier(testRoot(t), defaultPolicy(forkRepo, forkSigner))
	if err != nil {
		t.Fatal(err)
	}
	tests := []struct {
		name    string
		digest  string
		commit  string
		wantErr string
	}{
		{name: "image digest", digest: taggerImage, commit: taggerCommit},
		{name: "other image", digest: taggerImage[:62] + "00", commit: taggerCommit, wantErr: "artifact"},
		{name: "other commit", digest: taggerImage, commit: strings.Repeat("0", 40), wantErr: "names 9.9.0-rc13 at"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			u, err := v.checkTaggerFor(bundle, []verify.ArtifactPolicyOption{digestOption(t, tc.digest)}, taggerTag, tc.commit)
			checkErr(t, err, tc.wantErr)
			if err == nil && (u.Login != taggerLogin || u.ID != taggerID) {
				t.Fatalf("tagger %v, want %s %d", u, taggerLogin, taggerID)
			}
		})
	}
}

// testdata/9.9.0-rc14.image is an image manifest of release 9.9.0-rc14 of a
// fork with three of its referrers: the cosign signature, the tagger
// statement and the maintainer approval.
const (
	imageLayout         = "testdata/9.9.0-rc14.image"
	imageTag            = "9.9.0-rc14"
	imageCommit         = "97df395f4bf531bbb04b4fd7dab3201c89a4269e"
	imageTaggerReferrer = "sha256:9143da6a13e4bfabdb142920bb4e94c1f94a1f211f755cd2b5d4f5f62d4c5d2d"
)

// imageVerifier returns a verifier for release imageTag of the fork,
// approved by maintainer.
func imageVerifier(t *testing.T) *verifier {
	t.Helper()
	p := defaultPolicy(forkRepo, forkSigner)
	p.ref = "refs/tags/" + imageTag
	p.maintainers = []string{maintainer}
	v, err := newVerifier(testRoot(t), p)
	if err != nil {
		t.Fatal(err)
	}
	return v
}

// imageLayoutWithout copies the imageLayout layout without the referrer
// manifest digest names and returns the copy's directory.
func imageLayoutWithout(t *testing.T, digest string) string {
	t.Helper()
	dir := t.TempDir()
	if err := os.CopyFS(dir, os.DirFS(imageLayout)); err != nil {
		t.Fatal(err)
	}
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		t.Fatal(err)
	}
	var idx manifest
	if err := json.Unmarshal(data, &idx); err != nil {
		t.Fatal(err)
	}
	n := len(idx.Manifests)
	idx.Manifests = slices.DeleteFunc(idx.Manifests, func(d descriptor) bool { return d.Digest == digest })
	if len(idx.Manifests) != n-1 {
		t.Fatalf("%s is not listed in %s", digest, imageLayout)
	}
	if data, err = json.Marshal(idx); err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(filepath.Join(dir, "index.json"), data, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir
}

// captureOutput runs f and returns what it wrote to stdout and stderr.
func captureOutput(t *testing.T, f func()) (stdout, stderr string) {
	t.Helper()
	read := func(w **os.File) func() string {
		r, pw, err := os.Pipe()
		if err != nil {
			t.Fatal(err)
		}
		saved := *w
		*w = pw
		return func() string {
			*w = saved
			pw.Close()
			data, err := io.ReadAll(r)
			r.Close()
			if err != nil {
				t.Fatal(err)
			}
			return string(data)
		}
	}
	endOut, endErr := read(&os.Stdout), read(&os.Stderr)
	f()
	return endOut(), endErr()
}

// TestImageTagger checks that an image reports who pushed its release tag
// from the tagger statement among its referrers, and none when there is no
// such referrer.
func TestImageTagger(t *testing.T) {
	v := imageVerifier(t)
	tests := []struct {
		name   string
		dir    string
		tagger githubUser
	}{
		{name: "tagger referrer", dir: imageLayout, tagger: githubUser{Login: taggerLogin, ID: taggerID}},
		{name: "no tagger referrer", dir: imageLayoutWithout(t, imageTaggerReferrer)},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			l, err := openLayout(tc.dir)
			if err != nil {
				t.Fatal(err)
			}
			target, err := l.target("")
			if err != nil {
				t.Fatal(err)
			}
			res, err := v.checkImage(l, target, false)
			if err != nil {
				t.Fatal(err)
			}
			if res.tagger != tc.tagger {
				t.Errorf("tagger %v, want %v", res.tagger, tc.tagger)
			}
			if res.tag != imageTag || res.commit != imageCommit || res.approver != maintainer {
				t.Errorf("tag %s, commit %s, approver %s; want %s, %s, %s", res.tag, res.commit, res.approver, imageTag, imageCommit, maintainer)
			}
		})
	}
}

// TestVerifyImageTagger checks what offline image mode prints for the tagger.
func TestVerifyImageTagger(t *testing.T) {
	v := imageVerifier(t)
	pushed := fmt.Sprintf("OK: tag %s pushed by %s (GitHub user ID %d)", imageTag, taggerLogin, taggerID)
	tests := []struct {
		name       string
		dir        string
		wantOut    string
		wantNoOut  string
		wantStderr string
	}{
		{name: "tagger referrer", dir: imageLayout, wantOut: pushed},
		{name: "no tagger referrer", dir: imageLayoutWithout(t, imageTaggerReferrer), wantNoOut: "pushed by", wantStderr: "has no tagger statement among its referrers"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			var err error
			stdout, stderr := captureOutput(t, func() { err = v.verifyImage(tc.dir, "") })
			if err != nil {
				t.Fatal(err)
			}
			if !strings.Contains(stdout, "approved by "+maintainer) {
				t.Errorf("stdout %q does not report the approval", stdout)
			}
			if tc.wantOut != "" && !strings.Contains(stdout, tc.wantOut) {
				t.Errorf("stdout %q does not contain %q", stdout, tc.wantOut)
			}
			if tc.wantNoOut != "" && strings.Contains(stdout, tc.wantNoOut) {
				t.Errorf("stdout %q contains %q", stdout, tc.wantNoOut)
			}
			if (tc.wantStderr == "") != (stderr == "") || !strings.Contains(stderr, tc.wantStderr) {
				t.Errorf("stderr %q, want it to contain %q", stderr, tc.wantStderr)
			}
		})
	}
}

// TestReferrerTagger checks that the tagger statements among an image's
// referrers must each name the release and its commit, and agree.
func TestReferrerTagger(t *testing.T) {
	v, err := newVerifier(testRoot(t), defaultPolicy(forkRepo, forkSigner))
	if err != nil {
		t.Fatal(err)
	}
	statement := func(predicateType, tag, commit, login string, id int) *verify.VerificationResult {
		j := fmt.Sprintf(`{"statement":{"predicateType":%q,"predicate":{"tag":%q,"commit":%q,"tagger":{"login":%q,"id":%d}}}}`,
			predicateType, tag, commit, login, id)
		var r verify.VerificationResult
		if err := json.Unmarshal([]byte(j), &r); err != nil {
			t.Fatal(err)
		}
		return &r
	}
	ref := func(signedTag string, r *verify.VerificationResult) taggerReferrer {
		return taggerReferrer{result: r, tag: signedTag, manifest: "sha256:abc"}
	}
	alice := statement(v.policy.taggerType, "1.0.0", "c1", "alice", 1)
	aliceAgain := statement(v.policy.taggerType, "1.0.0", "c1", "alice", 1)
	bob := statement(v.policy.taggerType, "1.0.0", "c1", "bob", 2)
	tests := []struct {
		name    string
		refs    []taggerReferrer
		want    githubUser
		wantErr string
	}{
		{name: "none"},
		{name: "one", refs: []taggerReferrer{ref("1.0.0", alice)}, want: githubUser{Login: "alice", ID: 1}},
		{name: "agreeing", refs: []taggerReferrer{ref("1.0.0", alice), ref("1.0.0", aliceAgain)}, want: githubUser{Login: "alice", ID: 1}},
		{name: "disagreeing", refs: []taggerReferrer{ref("1.0.0", alice), ref("1.0.0", bob)}, wantErr: "tagger statements name alice (GitHub user ID 1) and bob (GitHub user ID 2)"},
		{name: "signed for other release", refs: []taggerReferrer{ref("0.9.0", alice)}, wantErr: "signed for release 0.9.0, not 1.0.0"},
		{name: "names other release", refs: []taggerReferrer{ref("1.0.0", statement(v.policy.taggerType, "0.9.0", "c1", "alice", 1))}, wantErr: "names 0.9.0 at c1, not 1.0.0 at c1"},
		{name: "names other commit", refs: []taggerReferrer{ref("1.0.0", statement(v.policy.taggerType, "1.0.0", "c2", "alice", 1))}, wantErr: "names 1.0.0 at c2, not 1.0.0 at c1"},
		{name: "names no tagger", refs: []taggerReferrer{ref("1.0.0", statement(v.policy.taggerType, "1.0.0", "c1", "", 0))}, wantErr: "names no tagger"},
		{name: "other predicate type", refs: []taggerReferrer{ref("1.0.0", statement(v.policy.approvalType, "1.0.0", "c1", "alice", 1))}, wantErr: "not a " + v.policy.taggerType + " statement"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			got, err := v.referrerTagger(tc.refs, "1.0.0", "c1")
			checkErr(t, err, tc.wantErr)
			if err == nil && got != tc.want {
				t.Fatalf("tagger %v, want %v", got, tc.want)
			}
		})
	}
}

func TestReportApproval(t *testing.T) {
	signers := parseSigners([]byte("alice alice@example.com\nbob bob@example.com\nbobby BOB@example.com\n"), "list")
	tests := []struct {
		name    string
		signers releaseSigners
		tagger  githubUser
		email   string
		wantErr string
	}{
		{name: "other account", signers: signers, tagger: githubUser{Login: "carol", ID: 3}, email: "alice@example.com"},
		{name: "tagger approved", signers: signers, tagger: githubUser{Login: "alice", ID: 1}, email: "alice@example.com", wantErr: "alice both pushed tag"},
		{name: "login case differs", signers: signers, tagger: githubUser{Login: "ALICE", ID: 1}, email: "alice@example.com", wantErr: "both pushed tag"},
		{name: "email case differs", signers: signers, tagger: githubUser{Login: "bobby", ID: 2}, email: "Bob@Example.com", wantErr: "bobby both pushed tag"},
		{name: "tagger not recorded", signers: signers, email: "alice@example.com"},
		{name: "email not listed", signers: signers, tagger: githubUser{Login: "alice", ID: 1}, email: "dave@example.com"},
		{name: "no signers list", tagger: githubUser{Login: "alice", ID: 1}, email: "alice@example.com"},
		{name: "no approval", signers: signers, tagger: githubUser{Login: "alice", ID: 1}},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v := &verifier{signers: tc.signers}
			checkErr(t, v.reportApproval("1.0.0", tc.tagger, tc.email), tc.wantErr)
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
