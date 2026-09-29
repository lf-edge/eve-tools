// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bufio"
	"crypto/sha256"
	"crypto/x509"
	"encoding/hex"
	"encoding/json"
	"errors"
	"flag"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"sort"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/bundle"
	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

// signPredicate is the in-toto predicate type of a `cosign sign` signature,
// as opposed to an attestation such as the SPDX SBOM.
const signPredicate = "https://sigstore.dev/cosign/sign/v1"

type verifier struct {
	sv          *verify.Verifier
	identity    verify.CertificateIdentity
	maintainers []verify.CertificateIdentity
	policy      policy
}

// approvalPredicate is the predicate of a maintainer's release approval.
type approvalPredicate struct {
	Repository string `json:"repository"`
	Release    string `json:"release"`
	Commit     string `json:"commit"`
}

// newVerifier requires every signature to carry a transparency log entry and
// a verified timestamp from the trusted root, which is what cosign's keyless
// signing produces.
func newVerifier(trustedRootPath string, p policy) (*verifier, error) {
	tr, err := root.NewTrustedRootFromPath(trustedRootPath)
	if err != nil {
		return nil, fmt.Errorf("loading trusted root: %w", err)
	}
	sv, err := verify.NewVerifier(tr, verify.WithTransparencyLog(1), verify.WithObserverTimestamps(1))
	if err != nil {
		return nil, err
	}
	id, err := p.certificateIdentity()
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	maintainers, err := p.maintainerIdentities()
	if err != nil {
		return nil, fmt.Errorf("policy: %w", err)
	}
	return &verifier{sv: sv, identity: id, maintainers: maintainers, policy: p}, nil
}

func (v *verifier) describePolicy() string {
	id := v.policy.identity
	if id == "" {
		id = v.policy.identityRegexp
	}
	ref := v.policy.ref
	if ref == "" {
		ref = "a release tag"
	}
	return fmt.Sprintf("identity %s, repository %s, ref %s", id, v.policy.repository, ref)
}

func signer(r *verify.VerificationResult) string {
	s := r.Signature.Certificate.SubjectAlternativeName
	for _, ts := range r.VerifiedTimestamps {
		s += fmt.Sprintf(" at %s (%s)", ts.Timestamp.UTC().Format("2006-01-02T15:04:05Z"), ts.Type)
		break
	}
	return s
}

// verifyImage checks that the layout holds the complete image and that at
// least one of its referrers is a cosign signature over its manifest digest
// matching the policy.
func (v *verifier) verifyImage(dir, digest string) error {
	l, err := openLayout(dir)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	target, err := l.target(digest)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	blobs, err := l.checkContent(target)
	if err != nil {
		return fmt.Errorf("image %s content: %v", target, err)
	}
	bundles, err := l.bundlesFor(target)
	if err != nil {
		return err
	}
	if len(bundles) == 0 {
		return fmt.Errorf("image %s has no Sigstore bundle referrers in %s", target, dir)
	}
	digestBytes, err := hex.DecodeString(strings.TrimPrefix(target, "sha256:"))
	if err != nil {
		return err
	}
	artifact := verify.WithArtifactDigest("sha256", digestBytes)
	var signed *verify.VerificationResult
	var tag string
	var approvals []*verify.VerificationResult
	var failures []string
	for _, rb := range bundles {
		r, t, err := v.verifyRelease(rb.json, artifact)
		if err != nil {
			if a, aerr := v.verifyApproval(rb.json, artifact); aerr == nil {
				approvals = append(approvals, a)
				continue
			}
			failures = append(failures, fmt.Sprintf("%s: %v", rb.manifestDigest, err))
			continue
		}
		if r.Statement == nil {
			failures = append(failures, fmt.Sprintf("%s: not a DSSE statement", rb.manifestDigest))
			continue
		}
		if r.Statement.PredicateType != signPredicate {
			fmt.Printf("info: verified %s attestation by %s\n", r.Statement.PredicateType, signer(r))
			continue
		}
		signed, tag = r, t
	}
	for _, f := range failures {
		fmt.Fprintf(os.Stderr, "rejected bundle %s\n", f)
	}
	if signed == nil {
		return fmt.Errorf("image %s: no cosign signature matching %s (%d bundles checked)",
			target, v.describePolicy(), len(bundles))
	}
	approved, err := v.approvedBy(approvals, tag)
	if err != nil {
		return fmt.Errorf("image %s: %v", target, err)
	}
	fmt.Printf("OK: image %s (%d blobs) of release %s signed by %s%s\n", target, blobs, tag, signer(signed), approved)
	return nil
}

// verifyRelease checks a bundle against the release policy and returns the
// release tag the signing run built.
func (v *verifier) verifyRelease(data []byte, artifact verify.ArtifactPolicyOption) (*verify.VerificationResult, string, error) {
	r, cert, err := v.verifyBundle(data, artifact, v.identity)
	if err != nil {
		return nil, "", err
	}
	tag, err := v.policy.checkRelease(cert, *r.Signature.Certificate)
	if err != nil {
		return nil, "", err
	}
	return r, tag, nil
}

// verifyApproval checks a bundle for a maintainer's release approval with
// the artifact among its subjects.
func (v *verifier) verifyApproval(data []byte, artifact verify.ArtifactPolicyOption) (*verify.VerificationResult, error) {
	if len(v.maintainers) == 0 {
		return nil, errors.New("no maintainers in the policy")
	}
	r, _, err := v.verifyBundle(data, artifact, v.maintainers...)
	if err != nil {
		return nil, err
	}
	if r.Statement == nil || r.Statement.PredicateType != v.policy.approvalType {
		return nil, fmt.Errorf("not a %s statement", v.policy.approvalType)
	}
	return r, nil
}

// approvedBy returns, when the policy names maintainers, which one approved
// release tag, or an error if none did.
func (v *verifier) approvedBy(approvals []*verify.VerificationResult, tag string) (string, error) {
	if len(v.maintainers) == 0 {
		return "", nil
	}
	for _, a := range approvals {
		pj, err := json.Marshal(a.Statement.Predicate)
		if err != nil {
			continue
		}
		var p approvalPredicate
		if json.Unmarshal(pj, &p) != nil || p.Release != tag || p.Repository != v.policy.repo {
			fmt.Fprintf(os.Stderr, "rejected approval by %s: for %s %s, not %s %s\n",
				signer(a), p.Repository, p.Release, v.policy.repo, tag)
			continue
		}
		return ", approved by " + signer(a), nil
	}
	return "", fmt.Errorf("no approval of release %s by %s", tag, strings.Join(v.policy.maintainers, ", "))
}

func (v *verifier) verifyBundle(data []byte, artifact verify.ArtifactPolicyOption,
	ids ...verify.CertificateIdentity) (*verify.VerificationResult, *x509.Certificate, error) {
	var b bundle.Bundle
	if err := b.UnmarshalJSON(data); err != nil {
		return nil, nil, fmt.Errorf("parsing bundle: %w", err)
	}
	opts := []verify.PolicyOption{}
	for _, id := range ids {
		opts = append(opts, verify.WithCertificateIdentity(id))
	}
	r, err := v.sv.Verify(&b, verify.NewPolicy(artifact, opts...))
	if err != nil {
		return nil, nil, err
	}
	vc, err := b.VerificationContent()
	if err != nil {
		return nil, nil, err
	}
	return r, vc.Certificate(), nil
}

// verifyAssets checks the sha256sums file against its <sums>.sigstore.json
// bundle, then every listed asset present in dir against the signed sums.
// Listed assets missing from dir are counted, not failed, since users
// usually download only the assets they need.
//
// When the policy names maintainers, approval is the bundle of a maintainer's
// approval of the release, by default <tag>.maintainer.sigstore.json in dir.
func (v *verifier) verifyAssets(dir, sums, approval string) error {
	sumsData, err := os.ReadFile(sums)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	bundleData, err := os.ReadFile(sums + ".sigstore.json")
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	r, tag, err := v.verifyRelease(bundleData, verify.WithArtifact(strings.NewReader(string(sumsData))))
	if err != nil {
		return fmt.Errorf("%s: signature does not match %s: %v", filepath.Base(sums), v.describePolicy(), err)
	}
	approved := ""
	if len(v.maintainers) > 0 {
		if approval == "" {
			approval = filepath.Join(dir, tag+".maintainer.sigstore.json")
		}
		data, err := os.ReadFile(approval)
		if err != nil {
			return fmt.Errorf("%w: %v", errUsage, err)
		}
		a, err := v.verifyApproval(data, verify.WithArtifact(strings.NewReader(string(sumsData))))
		if err != nil {
			return fmt.Errorf("%s: approval %s: %v", filepath.Base(sums), filepath.Base(approval), err)
		}
		if approved, err = v.approvedBy([]*verify.VerificationResult{a}, tag); err != nil {
			return fmt.Errorf("%s: %v", filepath.Base(sums), err)
		}
	}
	want, err := parseSums(sumsData)
	if err != nil {
		return fmt.Errorf("%s: %v", filepath.Base(sums), err)
	}
	var checked, missing int
	for _, name := range sortedKeys(want) {
		got, err := fileSHA256(filepath.Join(dir, name))
		if errors.Is(err, os.ErrNotExist) {
			missing++
			continue
		}
		if err != nil {
			return err
		}
		if got != want[name] {
			return fmt.Errorf("%s: sha256 %s, signed sums say %s", name, got, want[name])
		}
		checked++
	}
	if checked == 0 {
		return fmt.Errorf("%w: signature OK but none of the %d assets listed in %s is in %s",
			errUsage, len(want), filepath.Base(sums), dir)
	}
	fmt.Printf("OK: %s of release %s signed by %s%s; %d assets match, %d listed but not present\n",
		filepath.Base(sums), tag, signer(r), approved, checked, missing)
	return nil
}

// parseSums reads sha256sum(1) output. Names must be plain file names: the
// release workflow runs sha256sum in the assets directory.
func parseSums(data []byte) (map[string]string, error) {
	out := map[string]string{}
	sc := bufio.NewScanner(strings.NewReader(string(data)))
	for n := 1; sc.Scan(); n++ {
		line := sc.Text()
		if line == "" {
			continue
		}
		sum, name, ok := strings.Cut(line, " ")
		name = strings.TrimPrefix(strings.TrimPrefix(name, " "), "*")
		if _, err := hex.DecodeString(sum); !ok || err != nil || len(sum) != 64 {
			return nil, fmt.Errorf("line %d: not a sha256sum line", n)
		}
		if name == "" || name != filepath.Base(name) || name == "." || name == ".." {
			return nil, fmt.Errorf("line %d: unexpected file name %q", n, name)
		}
		out[name] = strings.ToLower(sum)
	}
	if len(out) == 0 {
		return nil, errors.New("no checksums")
	}
	return out, sc.Err()
}

func sortedKeys(m map[string]string) []string {
	keys := make([]string, 0, len(m))
	for k := range m {
		keys = append(keys, k)
	}
	sort.Strings(keys)
	return keys
}

func fileSHA256(path string) (string, error) {
	f, err := os.Open(path)
	if err != nil {
		return "", err
	}
	defer f.Close()
	h := sha256.New()
	if _, err := io.Copy(h, f); err != nil {
		return "", err
	}
	return hex.EncodeToString(h.Sum(nil)), nil
}

// runTrustedRoot fetches Sigstore's public-good trusted root through TUF,
// anchored on the TUF root embedded in sigstore-go.
func runTrustedRoot(args []string) error {
	fs := flag.NewFlagSet("trusted-root", flag.ContinueOnError)
	out := fs.String("o", "trusted_root.json", "output file")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	c, err := tuf.New(tuf.DefaultOptions().WithDisableLocalCache())
	if err != nil {
		return err
	}
	data, err := c.GetTarget("trusted_root.json")
	if err != nil {
		return err
	}
	if _, err := root.NewTrustedRootFromJSON(data); err != nil {
		return err
	}
	if err := os.WriteFile(*out, data, 0o644); err != nil {
		return err
	}
	fmt.Printf("OK: wrote %s\n", *out)
	return nil
}
