// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"errors"
	"fmt"
	"io"
	"net/http"
	"net/url"
	"os"
	"path/filepath"
	"slices"
	"strings"
	"time"

	"github.com/klauspost/compress/s2"
	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	// releaseAttester is the identity in the certificate GitHub signs
	// immutable-release attestations with.
	releaseAttester = "https://dotcom.releases.github.com"
	// releasePredicate is the predicate type of those attestations.
	releasePredicate = "https://in-toto.io/attestation/release/v0.2"
	maxAPIResponse   = 16 << 20
)

// githubAPI is GitHub's REST API; tests point it at a local server.
var githubAPI = "https://api.github.com"

var httpClient = &http.Client{Timeout: 30 * time.Minute}

type ghAsset struct {
	Name   string `json:"name"`
	URL    string `json:"browser_download_url"`
	Digest string `json:"digest"`
	Size   int64  `json:"size"`
}

type ghRelease struct {
	TagName   string    `json:"tag_name"`
	Immutable bool      `json:"immutable"`
	Assets    []ghAsset `json:"assets"`
}

// apiGet reads a GitHub API response into out. GH_TOKEN, when set, is sent
// to the API only, never to the hosts assets and bundles redirect to.
func apiGet(path string, out any) error {
	req, err := http.NewRequest(http.MethodGet, githubAPI+path, nil)
	if err != nil {
		return err
	}
	req.Header.Set("Accept", "application/vnd.github+json")
	if t := os.Getenv("GH_TOKEN"); t != "" {
		req.Header.Set("Authorization", "Bearer "+t)
	}
	resp, err := httpClient.Do(req)
	if err != nil {
		return err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return fmt.Errorf("GET %s: %s", path, resp.Status)
	}
	return json.NewDecoder(io.LimitReader(resp.Body, maxAPIResponse)).Decode(out)
}

// download writes the asset to dir and returns its sha256. The asset must be
// at most its listed size and, when the API lists a digest, match it.
func download(a ghAsset, dir string) (string, error) {
	if a.Name == "" || a.Name != filepath.Base(a.Name) || strings.HasPrefix(a.Name, ".") {
		return "", fmt.Errorf("unexpected asset name %q", a.Name)
	}
	resp, err := httpClient.Get(a.URL)
	if err != nil {
		return "", err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return "", fmt.Errorf("downloading %s: %s", a.Name, resp.Status)
	}
	f, err := os.Create(filepath.Join(dir, a.Name))
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(io.MultiWriter(f, h), io.LimitReader(resp.Body, a.Size+1))
	if err != nil {
		return "", fmt.Errorf("downloading %s: %v", a.Name, err)
	}
	if n != a.Size {
		return "", fmt.Errorf("%s: downloaded %d bytes, release lists %d", a.Name, n, a.Size)
	}
	sum := hex.EncodeToString(h.Sum(nil))
	if a.Digest != "" && a.Digest != "sha256:"+sum {
		return "", fmt.Errorf("%s: sha256:%s, release lists %s", a.Name, sum, a.Digest)
	}
	return sum, nil
}

// releaseOptions selects what verifyReleaseOnline fetches and requires.
type releaseOptions struct {
	variants     []string // arch.hv.platform; empty means every sums file
	assets       []string // further assets to download and check
	allowMutable bool
	githubRoot   string // GitHub trusted_root.json; empty fetches it
}

// verifyReleaseOnline downloads a release's sums files, their bundles, each
// variant's images.txt and the requested assets into dir, verifies them as
// the assets mode does, and checks GitHub's immutable-release attestation.
func (v *verifier) verifyReleaseOnline(tag string, o releaseOptions, dir string) error {
	repo := v.policy.repo
	var rel ghRelease
	if err := apiGet(fmt.Sprintf("/repos/%s/releases/tags/%s", repo, url.PathEscape(tag)), &rel); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if rel.TagName != tag {
		return fmt.Errorf("API returned release %q for tag %q", rel.TagName, tag)
	}
	byName := map[string]ghAsset{}
	for _, a := range rel.Assets {
		byName[a.Name] = a
	}
	var sums []string
	for _, a := range rel.Assets {
		variant, ok := strings.CutSuffix(a.Name, ".sha256sums")
		if ok && (len(o.variants) == 0 || slices.Contains(o.variants, variant)) {
			sums = append(sums, a.Name)
		}
	}
	slices.Sort(sums)
	if len(sums) == 0 {
		return fmt.Errorf("%w: release %s has no matching .sha256sums asset", errUsage, tag)
	}
	want := slices.Clone(o.assets)
	for _, s := range sums {
		want = append(want, s, s+".sigstore.json")
		if images := strings.TrimSuffix(s, ".sha256sums") + ".images.txt"; byName[images].Name != "" {
			want = append(want, images)
		}
	}
	if len(v.maintainers) > 0 {
		want = append(want, tag+".maintainer.sigstore.json")
	}
	files := map[string]string{}
	for _, n := range want {
		a, ok := byName[n]
		if !ok {
			return fmt.Errorf("%w: release %s has no asset %s", errUsage, tag, n)
		}
		if _, done := files[n]; done {
			continue
		}
		sum, err := download(a, dir)
		if err != nil {
			return err
		}
		files[n] = sum
	}
	var commit string
	for _, s := range sums {
		r, err := v.checkAssets(dir, filepath.Join(dir, s), "")
		if err != nil {
			return err
		}
		if commit != "" && r.commit != commit {
			return fmt.Errorf("%s was signed for commit %s, another sums file for %s", s, r.commit, commit)
		}
		commit = r.commit
	}
	if !rel.Immutable {
		if !o.allowMutable {
			return fmt.Errorf("release %s is not immutable; -allow-mutable accepts it", tag)
		}
		fmt.Printf("OK: release %s, not immutable (accepted with -allow-mutable)\n", tag)
		return nil
	}
	tr, err := githubRoot(o.githubRoot, dir)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if err := checkReleaseAttestation(tr, repo, tag, commit, files, dir); err != nil {
		return fmt.Errorf("release %s: %v", tag, err)
	}
	fmt.Printf("OK: release %s is immutable: GitHub attests tag %s at commit %s with these %d assets\n",
		tag, tag, commit, len(files))
	return nil
}

type ghAttestations struct {
	Attestations []struct {
		Bundle    json.RawMessage `json:"bundle"`
		BundleURL string          `json:"bundle_url"`
	} `json:"attestations"`
}

// checkReleaseAttestation finds GitHub's release attestation for one of
// files and checks that it names repo, tag and commit, and lists every file
// in files with the same sha256. The bundle is saved to dir.
func checkReleaseAttestation(tr *root.TrustedRoot, repo, tag, commit string, files map[string]string, dir string) error {
	names := sortedKeys(files)
	var list ghAttestations
	if err := apiGet(fmt.Sprintf("/repos/%s/attestations/sha256:%s?per_page=100", repo, files[names[0]]), &list); err != nil {
		return fmt.Errorf("fetching attestations: %v", err)
	}
	sv, err := verify.NewVerifier(tr, verify.WithSignedTimestamps(1))
	if err != nil {
		return err
	}
	var failures []string
	for _, a := range list.Attestations {
		data := []byte(a.Bundle)
		if len(data) == 0 || string(data) == "null" {
			if data, err = fetchBundle(a.BundleURL); err != nil {
				failures = append(failures, err.Error())
				continue
			}
		}
		err := checkAttestationBundle(sv, data, repo, tag, commit, files, peelTag(repo))
		if err == nil {
			return os.WriteFile(filepath.Join(dir, tag+".release-attestation.sigstore.json"), data, 0o644)
		}
		failures = append(failures, err.Error())
	}
	if len(failures) == 0 {
		return errors.New("no attestation found")
	}
	return fmt.Errorf("no valid release attestation: %s", strings.Join(failures, "; "))
}

// fetchBundle downloads an attestation bundle from the pre-signed URL the
// API returns, snappy-compressed when it is not plain JSON.
func fetchBundle(u string) ([]byte, error) {
	resp, err := httpClient.Get(u)
	if err != nil {
		return nil, err
	}
	defer resp.Body.Close()
	if resp.StatusCode != http.StatusOK {
		return nil, fmt.Errorf("attestation bundle: %s", resp.Status)
	}
	data, err := io.ReadAll(io.LimitReader(resp.Body, maxBundleSize))
	if err != nil {
		return nil, err
	}
	if len(data) > 0 && data[0] == '{' {
		return data, nil
	}
	// s2 decodes snappy blocks, the format GitHub stores bundles in.
	n, err := s2.DecodedLen(data)
	if err != nil || n > maxBundleSize {
		return nil, fmt.Errorf("attestation bundle: not JSON or a snappy block of at most %d bytes", maxBundleSize)
	}
	return s2.Decode(nil, data)
}

type releasePredicateFields struct {
	Repository string `json:"repository"`
	Tag        string `json:"tag"`
}

// peelTag returns a function that maps an annotated tag object in repo to
// the commit it points at. GitHub's release attestation names the tag ref's
// object, which for an annotated tag is the tag, not the commit. The lookup
// trusts GitHub, which already signs the attestation.
func peelTag(repo string) func(sha string) (string, error) {
	return func(sha string) (string, error) {
		var t struct {
			Object struct {
				Type string `json:"type"`
				SHA  string `json:"sha"`
			} `json:"object"`
		}
		if err := apiGet(fmt.Sprintf("/repos/%s/git/tags/%s", repo, sha), &t); err != nil {
			return "", err
		}
		if t.Object.Type != "commit" {
			return "", fmt.Errorf("tag object %s points at a %s", sha, t.Object.Type)
		}
		return t.Object.SHA, nil
	}
}

// checkAttestationBundle verifies one release attestation bundle against
// repo, tag, the commit the signing run built, and files. peel resolves an
// annotated tag object to its commit.
func checkAttestationBundle(sv *verify.Verifier, data []byte, repo, tag, commit string, files map[string]string, peel func(string) (string, error)) error {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(data); err != nil {
		return fmt.Errorf("parsing bundle: %v", err)
	}
	names := sortedKeys(files)
	d, err := hex.DecodeString(files[names[0]])
	if err != nil {
		return err
	}
	r, err := sv.Verify(&b, verify.NewPolicy(verify.WithArtifactDigest("sha256", d), verify.WithoutIdentitiesUnsafe()))
	if err != nil {
		return err
	}
	vc, err := b.VerificationContent()
	if err != nil {
		return err
	}
	cert := vc.Certificate()
	if cert == nil || len(cert.URIs) != 1 || cert.URIs[0].String() != releaseAttester {
		return fmt.Errorf("not signed by %s", releaseAttester)
	}
	st := r.Statement
	if st == nil || st.PredicateType != releasePredicate {
		return fmt.Errorf("not a %s statement", releasePredicate)
	}
	pj, err := json.Marshal(st.Predicate)
	if err != nil {
		return err
	}
	var p releasePredicateFields
	if err := json.Unmarshal(pj, &p); err != nil {
		return fmt.Errorf("predicate: %v", err)
	}
	if p.Repository != repo || p.Tag != tag {
		return fmt.Errorf("attestation is for %s %s, not %s %s", p.Repository, p.Tag, repo, tag)
	}
	purl := fmt.Sprintf("pkg:github/%s@%s", repo, tag)
	subjects := map[string]string{}
	tagCommit := ""
	for _, s := range st.Subject {
		if s.GetUri() == purl {
			tagCommit = s.GetDigest()["sha1"]
			continue
		}
		subjects[s.GetName()] = s.GetDigest()["sha256"]
	}
	if tagCommit == "" {
		return fmt.Errorf("attestation names no commit for tag %s", tag)
	}
	if !strings.EqualFold(tagCommit, commit) {
		peeled, err := peel(tagCommit)
		if err != nil {
			return fmt.Errorf("tag %s is at %s, not the commit the signing run built (%s), and is not an annotated tag: %v", tag, tagCommit, commit, err)
		}
		if !strings.EqualFold(peeled, commit) {
			return fmt.Errorf("tag %s is at commit %s, the signing run built %s", tag, peeled, commit)
		}
	}
	for _, n := range names {
		if subjects[n] != files[n] {
			return fmt.Errorf("asset %s: sha256 %s, attestation lists %q", n, files[n], subjects[n])
		}
	}
	return nil
}
