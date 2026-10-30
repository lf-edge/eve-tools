// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"errors"
	"os"
	"path/filepath"
	"strings"
	"testing"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// The testdata amd64.kvm.generic.* files are assets of lf-edge/eve 17.12.0.
// lf-edge/eve releases carry no maintainer approval, so signtest.* with its
// approval are those of release 9.9.0-rc9 of a fork, signed by the fork's
// release-sign.yml on its sign-master branch.
const (
	sumsName      = "amd64.kvm.generic.sha256sums"
	releaseRepo   = "lf-edge/eve"
	releaseTag    = "17.12.0"
	forkRepo      = "eriknordmark/eve"
	forkSigner    = "refs/heads/sign-master"
	signedAsset   = "amd64.kvm.generic.images.txt"
	trustedRootTD = "testdata/trusted_root.json"
	maintainer    = "erik@zededa.com"
)

func stageAssets(t *testing.T, sums []byte, files ...string) string {
	t.Helper()
	dir := t.TempDir()
	if sums == nil {
		var err error
		if sums, err = os.ReadFile(filepath.Join("testdata", sumsName)); err != nil {
			t.Fatal(err)
		}
	}
	copyFile(t, filepath.Join("testdata", sumsName+".sigstore.json"), filepath.Join(dir, sumsName+".sigstore.json"))
	if err := os.WriteFile(filepath.Join(dir, sumsName), sums, 0o644); err != nil {
		t.Fatal(err)
	}
	for _, f := range files {
		copyFile(t, filepath.Join("testdata", f), filepath.Join(dir, f))
	}
	return dir
}

func copyFile(t *testing.T, from, to string) {
	t.Helper()
	data, err := os.ReadFile(from)
	if err != nil {
		t.Fatal(err)
	}
	if err := os.WriteFile(to, data, 0o644); err != nil {
		t.Fatal(err)
	}
}

func TestVerifyAssets(t *testing.T) {
	sums, err := os.ReadFile(filepath.Join("testdata", sumsName))
	if err != nil {
		t.Fatal(err)
	}
	want, err := parseSums(sums)
	if err != nil {
		t.Fatal(err)
	}
	h := want[signedAsset]
	tamperedSums := []byte(strings.Replace(string(sums), h, strings.Repeat("0", 8)+h[8:], 1))

	release := defaultPolicy(releaseRepo, defaultSignerRef)
	tagged := release
	tagged.ref = "refs/tags/" + releaseTag
	otherTag := release
	otherTag.ref = "refs/tags/17.11.0"
	otherRepo := release
	otherRepo.repository = "https://github.com/example/eve"
	otherEnv := release
	otherEnv.environment = "packages"
	anyEnv := release
	anyEnv.environment = ""
	tagWorkflow := release
	tagWorkflow.identity = "https://github.com/lf-edge/eve/.github/workflows/publish.yml@refs/tags/" + releaseTag
	unapproved := release
	unapproved.maintainers = []string{maintainer}

	tests := []struct {
		name    string
		policy  policy
		sums    []byte
		files   []string
		tamper  bool
		wantErr string
	}{
		{name: "release policy", policy: release, files: []string{signedAsset}},
		{name: "exact tag", policy: tagged, files: []string{signedAsset}},
		{name: "any environment", policy: anyEnv, files: []string{signedAsset}},
		{name: "fork policy", policy: defaultPolicy("example/eve", defaultSignerRef), files: []string{signedAsset}, wantErr: "expected SAN value"},
		{name: "signer on another branch", policy: defaultPolicy(releaseRepo, "refs/heads/other"), files: []string{signedAsset}, wantErr: "expected SAN value"},
		{name: "other tag", policy: otherTag, files: []string{signedAsset}, wantErr: "expected SourceRepositoryRef"},
		{name: "other repository", policy: otherRepo, files: []string{signedAsset}, wantErr: "expected SourceRepositoryURI"},
		{name: "other environment", policy: otherEnv, files: []string{signedAsset}, wantErr: `deployment environment "release"`},
		{name: "tag workflow identity", policy: tagWorkflow, files: []string{signedAsset}, wantErr: "expected SAN value"},
		{name: "approval missing", policy: unapproved, files: []string{signedAsset}, wantErr: releaseTag + ".maintainer.sigstore.json"},
		{name: "tampered sums", policy: release, sums: tamperedSums, files: []string{signedAsset}, wantErr: "failed to verify signature"},
		{name: "tampered asset", policy: release, files: []string{signedAsset}, tamper: true, wantErr: "signed sums say"},
		{name: "no listed asset present", policy: release, wantErr: "none of the 8 assets"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			dir := stageAssets(t, tc.sums, tc.files...)
			if tc.tamper {
				f, err := os.OpenFile(filepath.Join(dir, signedAsset), os.O_APPEND|os.O_WRONLY, 0)
				if err != nil {
					t.Fatal(err)
				}
				f.Write([]byte{0})
				f.Close()
			}
			v, err := newVerifier(testRoot(t), tc.policy)
			if err != nil {
				t.Fatal(err)
			}
			checkErr(t, v.verifyAssets(dir, filepath.Join(dir, sumsName), ""), tc.wantErr)
		})
	}
}

// TestApproval checks the 9.9.0-rc9 maintainer approval, whose subjects
// include signtest.sha256sums.
func TestApproval(t *testing.T) {
	sums, err := os.ReadFile("testdata/signtest.sha256sums")
	if err != nil {
		t.Fatal(err)
	}
	approval, err := os.ReadFile("testdata/9.9.0-rc9.maintainer.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	release, err := os.ReadFile("testdata/signtest.sha256sums.sigstore.json")
	if err != nil {
		t.Fatal(err)
	}
	p := defaultPolicy(forkRepo, forkSigner)
	p.maintainers = []string{"someone@example.com", maintainer}
	other := p
	other.maintainers = []string{"someone@example.com"}
	otherType := p
	otherType.approvalType = "https://github.com/lf-edge/eve/release-approval/v1"
	otherRepo := p
	otherRepo.repo = "lf-edge/eve"

	tests := []struct {
		name     string
		policy   policy
		artifact []byte
		tag      string
		wantErr  string
	}{
		{name: "approved", policy: p, artifact: sums, tag: "9.9.0-rc9"},
		{name: "other maintainer", policy: other, artifact: sums, tag: "9.9.0-rc9", wantErr: "expected SAN value"},
		{name: "other predicate type", policy: otherType, artifact: sums, tag: "9.9.0-rc9", wantErr: "not a https://github.com/lf-edge/eve/release-approval/v1 statement"},
		{name: "not a subject", policy: p, artifact: append(sums, '\n'), tag: "9.9.0-rc9", wantErr: "artifact"},
		{name: "other release", policy: p, artifact: sums, tag: "9.9.0-rc8", wantErr: "no approval of release 9.9.0-rc8"},
		{name: "other repository", policy: otherRepo, artifact: sums, tag: "9.9.0-rc9", wantErr: "no approval of release 9.9.0-rc9"},
	}
	for _, tc := range tests {
		t.Run(tc.name, func(t *testing.T) {
			v, err := newVerifier(testRoot(t), tc.policy)
			if err != nil {
				t.Fatal(err)
			}
			a, err := v.verifyApproval(approval, verify.WithArtifact(bytes.NewReader(tc.artifact)))
			if err == nil {
				_, err = v.approvedBy([]*verify.VerificationResult{a}, tc.tag)
			}
			checkErr(t, err, tc.wantErr)
		})
	}

	// The release-sign.yml signature on the same file is not an approval.
	v, err := newVerifier(testRoot(t), p)
	if err != nil {
		t.Fatal(err)
	}
	if _, err := v.verifyApproval(release, verify.WithArtifact(bytes.NewReader(sums))); err == nil {
		t.Fatal("a workflow signature verified as a maintainer approval")
	}
	if _, tag, err := v.verifyRelease(release, verify.WithArtifact(bytes.NewReader(sums))); err != nil || tag != "9.9.0-rc9" {
		t.Fatalf("release signature: tag %q, %v", tag, err)
	}
}

func checkErr(t *testing.T, err error, want string) {
	t.Helper()
	switch {
	case want == "" && err != nil:
		t.Fatalf("unexpected error: %v", err)
	case want != "" && err == nil:
		t.Fatalf("verified, want error containing %q", want)
	case want != "" && !strings.Contains(err.Error(), want):
		t.Fatalf("error %q, want it to contain %q", err, want)
	}
}

func TestParseSumsRejectsPaths(t *testing.T) {
	sum := strings.Repeat("ab", 32)
	for _, name := range []string{"../etc/passwd", "sub/file", "/abs", ".."} {
		if _, err := parseSums([]byte(sum + "  " + name + "\n")); err == nil {
			t.Errorf("parseSums accepted %q", name)
		}
	}
	got, err := parseSums([]byte(sum + " *binary-mode.img\n"))
	if err != nil || got["binary-mode.img"] != sum {
		t.Errorf("binary-mode line: got %v, %v", got, err)
	}
}

// writeLayout builds an OCI layout holding one image with a config and a
// layer, and returns its directory and the image manifest digest.
func writeLayout(t *testing.T) (string, string) {
	t.Helper()
	dir := t.TempDir()
	put := func(data []byte) descriptor {
		d := descriptor{Digest: "sha256:" + sha256Hex(data), Size: int64(len(data))}
		p := filepath.Join(dir, "blobs", "sha256", sha256Hex(data))
		if err := os.MkdirAll(filepath.Dir(p), 0o755); err != nil {
			t.Fatal(err)
		}
		if err := os.WriteFile(p, data, 0o644); err != nil {
			t.Fatal(err)
		}
		return d
	}
	cfg := put([]byte(`{"architecture":"amd64"}`))
	layer := put([]byte("layer"))
	m, _ := json.Marshal(manifest{MediaType: "application/vnd.oci.image.manifest.v1+json", Config: &cfg, Layers: []descriptor{layer}})
	md := put(m)
	idx, _ := json.Marshal(manifest{Manifests: []descriptor{md}})
	if err := os.WriteFile(filepath.Join(dir, "index.json"), idx, 0o644); err != nil {
		t.Fatal(err)
	}
	return dir, md.Digest
}

func TestLayoutContent(t *testing.T) {
	dir, digest := writeLayout(t)
	l, err := openLayout(dir)
	if err != nil {
		t.Fatal(err)
	}
	if got, err := l.target(""); err != nil || got != digest {
		t.Fatalf("target: got %s, %v; want %s", got, err, digest)
	}
	if n, err := l.checkContent(digest, true); err != nil || n != 3 {
		t.Fatalf("checkContent: %d blobs, %v", n, err)
	}
	if err := os.WriteFile(filepath.Join(dir, "blobs", "sha256", sha256Hex([]byte("layer"))), []byte("LAYER"), 0o644); err != nil {
		t.Fatal(err)
	}
	if _, err := l.checkContent(digest, true); err == nil {
		t.Fatal("checkContent accepted a tampered layer")
	}
}

func TestUnsignedImage(t *testing.T) {
	dir, _ := writeLayout(t)
	v, err := newVerifier(testRoot(t), defaultPolicy("lf-edge/eve", defaultSignerRef))
	if err != nil {
		t.Fatal(err)
	}
	err = v.verifyImage(dir, "")
	if err == nil || errors.Is(err, errUsage) || !strings.Contains(err.Error(), "no Sigstore bundle referrers") {
		t.Fatalf("got %v, want a verification failure for missing signatures", err)
	}
}

func testRoot(t *testing.T) *root.TrustedRoot {
	t.Helper()
	tr, err := root.NewTrustedRootFromPath(trustedRootTD)
	if err != nil {
		t.Fatal(err)
	}
	return tr
}
