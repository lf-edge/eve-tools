// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"crypto/sha256"
	"encoding/hex"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"
	"strings"
)

const bundleMediaType = "application/vnd.dev.sigstore.bundle.v0.3+json"

type descriptor struct {
	MediaType    string            `json:"mediaType"`
	Digest       string            `json:"digest"`
	Size         int64             `json:"size"`
	ArtifactType string            `json:"artifactType,omitempty"`
	Annotations  map[string]string `json:"annotations,omitempty"`
}

// manifest covers the fields of an OCI/Docker image manifest or index that
// verification needs.
type manifest struct {
	MediaType    string       `json:"mediaType"`
	ArtifactType string       `json:"artifactType,omitempty"`
	Config       *descriptor  `json:"config,omitempty"`
	Layers       []descriptor `json:"layers,omitempty"`
	Manifests    []descriptor `json:"manifests,omitempty"`
	Subject      *descriptor  `json:"subject,omitempty"`
}

// layout is an OCI image layout directory.
type layout struct {
	dir   string
	index manifest
}

func openLayout(dir string) (*layout, error) {
	data, err := os.ReadFile(filepath.Join(dir, "index.json"))
	if err != nil {
		return nil, fmt.Errorf("not an OCI image layout: %w", err)
	}
	l := &layout{dir: dir}
	if err := json.Unmarshal(data, &l.index); err != nil {
		return nil, fmt.Errorf("parsing %s/index.json: %w", dir, err)
	}
	return l, nil
}

func (l *layout) blobPath(digest string) (string, error) {
	algo, hexDigest, ok := strings.Cut(digest, ":")
	if !ok || algo != "sha256" || len(hexDigest) != 64 {
		return "", fmt.Errorf("unsupported digest %q", digest)
	}
	return filepath.Join(l.dir, "blobs", algo, hexDigest), nil
}

// readBlob returns the blob's content after checking it hashes to digest.
func (l *layout) readBlob(digest string) ([]byte, error) {
	p, err := l.blobPath(digest)
	if err != nil {
		return nil, err
	}
	data, err := os.ReadFile(p)
	if err != nil {
		return nil, err
	}
	if got := sha256Hex(data); "sha256:"+got != digest {
		return nil, fmt.Errorf("blob %s has content sha256:%s", digest, got)
	}
	return data, nil
}

// checkBlob hashes a possibly large blob without loading it into memory.
func (l *layout) checkBlob(d descriptor) error {
	p, err := l.blobPath(d.Digest)
	if err != nil {
		return err
	}
	f, err := os.Open(p)
	if err != nil {
		return fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	defer f.Close()
	h := sha256.New()
	n, err := io.Copy(h, f)
	if err != nil {
		return fmt.Errorf("blob %s: %w", d.Digest, err)
	}
	if got := "sha256:" + hex.EncodeToString(h.Sum(nil)); got != d.Digest {
		return fmt.Errorf("blob %s has content %s", d.Digest, got)
	}
	if d.Size != 0 && n != d.Size {
		return fmt.Errorf("blob %s is %d bytes, descriptor says %d", d.Digest, n, d.Size)
	}
	return nil
}

func (l *layout) readManifest(digest string) (manifest, error) {
	var m manifest
	data, err := l.readBlob(digest)
	if err != nil {
		return m, err
	}
	if err := json.Unmarshal(data, &m); err != nil {
		return m, fmt.Errorf("parsing manifest %s: %w", digest, err)
	}
	return m, nil
}

// target picks the image to verify: digest if given, otherwise the only
// top-level manifest that is not a referrer of another one.
func (l *layout) target(digest string) (string, error) {
	var candidates []string
	for _, d := range l.index.Manifests {
		if digest != "" {
			if d.Digest == digest {
				return digest, nil
			}
			continue
		}
		m, err := l.readManifest(d.Digest)
		if err != nil {
			return "", err
		}
		if m.Subject == nil {
			candidates = append(candidates, d.Digest)
		}
	}
	if digest != "" {
		return "", fmt.Errorf("%s is not in the layout's index.json", digest)
	}
	if len(candidates) != 1 {
		return "", fmt.Errorf("layout holds %d images, select one with -digest", len(candidates))
	}
	return candidates[0], nil
}

// checkContent verifies that every blob the manifest or index at digest
// references, recursively, is present and hashes to its descriptor.
func (l *layout) checkContent(digest string) (int, error) {
	m, err := l.readManifest(digest)
	if err != nil {
		return 0, err
	}
	count := 1
	for _, d := range m.Manifests {
		n, err := l.checkContent(d.Digest)
		count += n
		if err != nil {
			return count, err
		}
	}
	blobs := m.Layers
	if m.Config != nil {
		blobs = append([]descriptor{*m.Config}, blobs...)
	}
	for _, d := range blobs {
		if err := l.checkBlob(d); err != nil {
			return count, err
		}
		count++
	}
	return count, nil
}

// referrerBundle is a Sigstore bundle attached to an image as an OCI
// referrer, the form cosign 3 stores signatures and attestations in.
type referrerBundle struct {
	manifestDigest string
	json           []byte
}

func (l *layout) bundlesFor(subject string) ([]referrerBundle, error) {
	var out []referrerBundle
	for _, d := range l.index.Manifests {
		if d.Digest == subject {
			continue
		}
		m, err := l.readManifest(d.Digest)
		if err != nil {
			return nil, err
		}
		if m.Subject == nil || m.Subject.Digest != subject || m.ArtifactType != bundleMediaType {
			continue
		}
		for _, layer := range m.Layers {
			if layer.MediaType != bundleMediaType {
				continue
			}
			data, err := l.readBlob(layer.Digest)
			if err != nil {
				return nil, err
			}
			out = append(out, referrerBundle{
				manifestDigest: d.Digest,
				json:           data,
			})
		}
	}
	return out, nil
}

func sha256Hex(data []byte) string {
	sum := sha256.Sum256(data)
	return hex.EncodeToString(sum[:])
}
