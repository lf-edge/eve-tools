// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	_ "embed"
	"fmt"
	"os"
	"path/filepath"

	"github.com/sigstore/sigstore-go/pkg/root"
	"github.com/sigstore/sigstore-go/pkg/tuf"
)

// githubTUFRoot anchors GitHub's TUF repository, which serves the trusted
// root of GitHub's own Sigstore instance. It is the root.json the GitHub CLI
// v2.102.0 embeds (pkg/cmd/attestation/verification/embed).
//
//go:embed embed/github-tuf-root.json
var githubTUFRoot []byte

const githubTUFMirror = "https://tuf-repo.github.com"

// tufCacheDir keeps TUF metadata between runs, so the highest root version
// seen is a floor that a replayed older root cannot go below.
func tufCacheDir() string {
	dir, err := os.UserCacheDir()
	if err != nil {
		dir = os.TempDir()
	}
	return filepath.Join(dir, "eve-sigverify", "tuf")
}

// fetchTrustedRoot returns trusted_root.json from a TUF repository, after a
// full TUF update: every run refreshes, so expired metadata is refused.
func fetchTrustedRoot(opts *tuf.Options) ([]byte, *root.TrustedRoot, error) {
	c, err := tuf.New(opts)
	if err != nil {
		return nil, nil, err
	}
	data, err := c.GetTarget("trusted_root.json")
	if err != nil {
		return nil, nil, err
	}
	tr, err := root.NewTrustedRootFromJSON(data)
	if err != nil {
		return nil, nil, err
	}
	return data, tr, nil
}

// sigstoreRoot returns the public-good trusted root: from path when given,
// otherwise from Sigstore's TUF repository, anchored on the root sigstore-go
// embeds. keep, when not empty, receives a copy of the fetched file.
func sigstoreRoot(path, keep string) (*root.TrustedRoot, error) {
	if path != "" {
		return root.NewTrustedRootFromPath(path)
	}
	data, tr, err := fetchTrustedRoot(tuf.DefaultOptions().WithCachePath(tufCacheDir()))
	if err != nil {
		return nil, fmt.Errorf("fetching Sigstore's trusted root: %w", err)
	}
	if keep != "" {
		if err := os.WriteFile(filepath.Join(keep, "trusted_root.json"), data, 0o644); err != nil {
			return nil, err
		}
	}
	return tr, nil
}

// githubRoot returns the trusted root of GitHub's Sigstore instance, which
// signs immutable-release attestations: from path when given, otherwise
// from GitHub's TUF repository.
func githubRoot(path, keep string) (*root.TrustedRoot, error) {
	if path != "" {
		return root.NewTrustedRootFromPath(path)
	}
	opts := tuf.DefaultOptions().WithCachePath(tufCacheDir()).
		WithRoot(githubTUFRoot).WithRepositoryBaseURL(githubTUFMirror)
	data, tr, err := fetchTrustedRoot(opts)
	if err != nil {
		return nil, fmt.Errorf("fetching GitHub's trusted root: %w", err)
	}
	if keep != "" {
		if err := os.WriteFile(filepath.Join(keep, "github_trusted_root.json"), data, 0o644); err != nil {
			return nil, err
		}
	}
	return tr, nil
}
