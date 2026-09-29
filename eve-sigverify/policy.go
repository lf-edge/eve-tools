// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/x509"
	"crypto/x509/pkix"
	"encoding/asn1"
	"fmt"
	"regexp"
	"slices"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/fulcio/certificate"
	"github.com/sigstore/sigstore-go/pkg/verify"
)

const (
	githubIssuer     = "https://token.actions.githubusercontent.com"
	maintainerIssuer = "https://github.com/login/oauth"
	defaultSignerRef = "refs/heads/master"
	releaseEnv       = "release"
)

// releaseRef matches the release tags release-sign.yml signs for;
// docs/SIGNING.md is the source of this policy.
var releaseRef = regexp.MustCompile(`^refs/tags/[0-9]+\.[0-9]+\.[0-9]+(-lts|-rc[0-9]+)?$`)

// oidDeploymentEnvironment is Fulcio's Deployment Environment extension, a
// DER UTF8String, which sigstore-go v1.2 does not parse.
var oidDeploymentEnvironment = asn1.ObjectIdentifier{1, 3, 6, 1, 4, 1, 57264, 1, 23}

// policy is what a release signature, and optionally a maintainer approval,
// must carry.
type policy struct {
	repo           string // owner/name
	identity       string
	identityRegexp string
	issuer         string
	repository     string
	ref            string // exact Source Repository Ref; empty means any release tag
	environment    string // required Deployment Environment; empty means any
	maintainers    []string
	approvalType   string
}

// defaultPolicy returns the policy for releases of the GitHub repository
// repo (owner/name): signed by its release-sign.yml at signerRef, which
// signs every image and sums file of a release, in the release environment.
func defaultPolicy(repo, signerRef string) policy {
	return policy{
		repo:         repo,
		identity:     fmt.Sprintf("https://github.com/%s/.github/workflows/release-sign.yml@%s", repo, signerRef),
		issuer:       githubIssuer,
		repository:   "https://github.com/" + repo,
		environment:  releaseEnv,
		approvalType: fmt.Sprintf("https://github.com/%s/release-approval/v1", repo),
	}
}

func (p policy) certificateIdentity() (verify.CertificateIdentity, error) {
	san, err := verify.NewSANMatcher(p.identity, p.identityRegexp)
	if err != nil {
		return verify.CertificateIdentity{}, err
	}
	issuer, err := verify.NewIssuerMatcher(p.issuer, "")
	if err != nil {
		return verify.CertificateIdentity{}, err
	}
	return verify.NewCertificateIdentity(san, issuer,
		certificate.Extensions{SourceRepositoryURI: p.repository, SourceRepositoryRef: p.ref})
}

// maintainerIdentities returns one identity per maintainer email; an
// approval signed by any of them is accepted.
func (p policy) maintainerIdentities() ([]verify.CertificateIdentity, error) {
	issuer, err := verify.NewIssuerMatcher(maintainerIssuer, "")
	if err != nil {
		return nil, err
	}
	var ids []verify.CertificateIdentity
	for _, m := range p.maintainers {
		san, err := verify.NewSANMatcher(m, "")
		if err != nil {
			return nil, err
		}
		id, err := verify.NewCertificateIdentity(san, issuer, certificate.Extensions{})
		if err != nil {
			return nil, err
		}
		ids = append(ids, id)
	}
	return ids, nil
}

// checkRelease checks what the identity match leaves open: that the signing
// run built a release tag, in the required environment. It returns the tag.
func (p policy) checkRelease(cert *x509.Certificate, s certificate.Summary) (string, error) {
	ref := s.SourceRepositoryRef
	if p.ref == "" && !releaseRef.MatchString(ref) {
		return "", fmt.Errorf("source repository ref %q is not a release tag", ref)
	}
	if p.environment != "" {
		env, err := deploymentEnvironment(cert)
		if err != nil {
			return "", err
		}
		if env != p.environment {
			return "", fmt.Errorf("deployment environment %q, want %q", env, p.environment)
		}
	}
	tag, ok := strings.CutPrefix(ref, "refs/tags/")
	if !ok {
		return "", fmt.Errorf("source repository ref %q is not a tag", ref)
	}
	return tag, nil
}

func deploymentEnvironment(cert *x509.Certificate) (string, error) {
	i := slices.IndexFunc(cert.Extensions, func(e pkix.Extension) bool {
		return e.Id.Equal(oidDeploymentEnvironment)
	})
	if i < 0 {
		return "", nil
	}
	var env string
	if _, err := asn1.Unmarshal(cert.Extensions[i].Value, &env); err != nil {
		return "", fmt.Errorf("deployment environment extension: %v", err)
	}
	return env, nil
}
