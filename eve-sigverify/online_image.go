// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

package main

import (
	"bytes"
	"encoding/json"
	"fmt"
	"io"
	"os"
	"path/filepath"

	"github.com/google/go-containerregistry/pkg/authn"
	"github.com/google/go-containerregistry/pkg/name"
	v1 "github.com/google/go-containerregistry/pkg/v1"
	"github.com/google/go-containerregistry/pkg/v1/remote"
)

// maxBundleSize caps a fetched Sigstore bundle; release bundles are a few KiB.
const maxBundleSize = 4 << 20

// layoutWriter writes fetched manifests and blobs into an OCI image layout,
// for the offline checks to read back.
type layoutWriter struct {
	dir       string
	manifests []descriptor
}

func newLayoutWriter(dir string) (*layoutWriter, error) {
	if err := os.MkdirAll(filepath.Join(dir, "blobs", "sha256"), 0o755); err != nil {
		return nil, err
	}
	return &layoutWriter{dir: dir}, nil
}

func (w *layoutWriter) blob(digest v1.Hash, r io.Reader) error {
	if digest.Algorithm != "sha256" {
		return fmt.Errorf("unsupported digest %s", digest)
	}
	f, err := os.Create(filepath.Join(w.dir, "blobs", "sha256", digest.Hex))
	if err != nil {
		return err
	}
	if _, err := io.Copy(f, r); err != nil {
		f.Close()
		return err
	}
	return f.Close()
}

// manifest writes a manifest or index and lists it in index.json.
func (w *layoutWriter) manifest(d *remote.Descriptor) error {
	if err := w.blob(d.Digest, bytes.NewReader(d.Manifest)); err != nil {
		return err
	}
	w.manifests = append(w.manifests, descriptor{
		MediaType: string(d.MediaType), Digest: d.Digest.String(), Size: d.Size,
	})
	return nil
}

func (w *layoutWriter) close() error {
	data, err := json.Marshal(struct {
		SchemaVersion int          `json:"schemaVersion"`
		MediaType     string       `json:"mediaType"`
		Manifests     []descriptor `json:"manifests"`
	}{2, "application/vnd.oci.image.index.v1+json", w.manifests})
	if err != nil {
		return err
	}
	if err := os.WriteFile(filepath.Join(w.dir, "oci-layout"), []byte(`{"imageLayoutVersion":"1.0.0"}`), 0o644); err != nil {
		return err
	}
	return os.WriteFile(filepath.Join(w.dir, "index.json"), data, 0o644)
}

// fetchedImage names what fetchImage wrote: the digest REF resolved to and,
// when that is an index, the platform manifest selected from it.
type fetchedImage struct {
	top, platform string
}

// fetchImage copies the manifest REF names into an OCI layout in dir, with
// the platform manifest when REF names an index, and every Sigstore bundle
// referrer of each. With content, config and layers are copied too.
func fetchImage(ref, platform string, content bool, dir string) (fetchedImage, error) {
	var out fetchedImage
	r, err := name.ParseReference(ref)
	if err != nil {
		return out, fmt.Errorf("%w: %v", errUsage, err)
	}
	plat, err := v1.ParsePlatform(platform)
	if err != nil {
		return out, fmt.Errorf("%w: -platform: %v", errUsage, err)
	}
	opts := []remote.Option{remote.WithAuthFromKeychain(authn.DefaultKeychain)}
	w, err := newLayoutWriter(dir)
	if err != nil {
		return out, err
	}
	repo := r.Context()
	top, err := remote.Get(r, opts...)
	if err != nil {
		return out, fmt.Errorf("%w: %s: %v", errUsage, ref, err)
	}
	if d, ok := r.(name.Digest); ok && d.DigestStr() != top.Digest.String() {
		return out, fmt.Errorf("registry returned %s for %s", top.Digest, ref)
	}
	out.top = top.Digest.String()
	if err := w.manifest(top); err != nil {
		return out, err
	}
	subjects := []*remote.Descriptor{top}
	if top.MediaType.IsIndex() {
		idx, err := v1.ParseIndexManifest(bytes.NewReader(top.Manifest))
		if err != nil {
			return out, fmt.Errorf("index %s: %v", top.Digest, err)
		}
		var child *v1.Descriptor
		for i, m := range idx.Manifests {
			if m.Platform != nil && m.Platform.Satisfies(*plat) {
				child = &idx.Manifests[i]
				break
			}
		}
		if child == nil {
			return out, fmt.Errorf("%w: index %s has no %s manifest", errUsage, top.Digest, platform)
		}
		pm, err := remote.Get(repo.Digest(child.Digest.String()), opts...)
		if err != nil {
			return out, fmt.Errorf("%w: %s: %v", errUsage, child.Digest, err)
		}
		if pm.Digest != child.Digest {
			return out, fmt.Errorf("registry returned %s for %s", pm.Digest, child.Digest)
		}
		out.platform = pm.Digest.String()
		if err := w.manifest(pm); err != nil {
			return out, err
		}
		subjects = append(subjects, pm)
	}
	for _, s := range subjects {
		if content && s.MediaType.IsImage() {
			if err := fetchBlobs(repo, s, w, opts); err != nil {
				return out, err
			}
		}
		if err := fetchReferrers(repo, s.Digest, w, opts); err != nil {
			return out, err
		}
	}
	return out, w.close()
}

func fetchBlobs(repo name.Repository, d *remote.Descriptor, w *layoutWriter, opts []remote.Option) error {
	m, err := v1.ParseManifest(bytes.NewReader(d.Manifest))
	if err != nil {
		return fmt.Errorf("manifest %s: %v", d.Digest, err)
	}
	for _, b := range append([]v1.Descriptor{m.Config}, m.Layers...) {
		if err := fetchBlob(repo, b.Digest, -1, w, opts); err != nil {
			return err
		}
	}
	return nil
}

// fetchBlob copies one blob; limit, when not negative, caps its size. The
// offline checks hash every blob they read.
func fetchBlob(repo name.Repository, digest v1.Hash, limit int64, w *layoutWriter, opts []remote.Option) error {
	l, err := remote.Layer(repo.Digest(digest.String()), opts...)
	if err != nil {
		return err
	}
	rc, err := l.Compressed()
	if err != nil {
		return fmt.Errorf("blob %s: %v", digest, err)
	}
	defer rc.Close()
	var r io.Reader = rc
	if limit >= 0 {
		r = io.LimitReader(rc, limit)
	}
	return w.blob(digest, r)
}

// fetchReferrers copies every referrer of subject whose artifact type is a
// Sigstore bundle, with its bundle layers.
func fetchReferrers(repo name.Repository, subject v1.Hash, w *layoutWriter, opts []remote.Option) error {
	idx, err := remote.Referrers(repo.Digest(subject.String()), opts...)
	if err != nil {
		return fmt.Errorf("referrers of %s: %v", subject, err)
	}
	im, err := idx.IndexManifest()
	if err != nil {
		return err
	}
	for _, d := range im.Manifests {
		if d.ArtifactType != bundleMediaType {
			continue
		}
		rd, err := remote.Get(repo.Digest(d.Digest.String()), opts...)
		if err != nil {
			return fmt.Errorf("referrer %s: %v", d.Digest, err)
		}
		if err := w.manifest(rd); err != nil {
			return err
		}
		m, err := v1.ParseManifest(bytes.NewReader(rd.Manifest))
		if err != nil {
			return fmt.Errorf("referrer %s: %v", d.Digest, err)
		}
		for _, layer := range m.Layers {
			if string(layer.MediaType) != bundleMediaType {
				continue
			}
			if err := fetchBlob(repo, layer.Digest, maxBundleSize, w, opts); err != nil {
				return err
			}
		}
	}
	return nil
}

// verifyImageOnline fetches ref into dir and verifies it. For an index, the
// index and its platform manifest must both be signed for the same release.
func (v *verifier) verifyImageOnline(ref, platform string, content bool, dir string) error {
	f, err := fetchImage(ref, platform, content, dir)
	if err != nil {
		return err
	}
	l, err := openLayout(dir)
	if err != nil {
		return err
	}
	top, err := v.checkImage(l, f.top, content)
	if err != nil {
		return err
	}
	if f.platform == "" {
		fmt.Printf("OK: image %s (%s) of release %s signed by %s%s\n", f.top, ref, top.tag, top.signer, top.approved)
		return nil
	}
	pm, err := v.checkImage(l, f.platform, content)
	if err != nil {
		return err
	}
	if pm.tag != top.tag {
		return fmt.Errorf("index %s is signed for release %s, its %s manifest %s for %s",
			f.top, top.tag, platform, f.platform, pm.tag)
	}
	fmt.Printf("OK: image %s (%s, index %s) of release %s signed by %s%s\n",
		f.platform, platform, f.top, pm.tag, pm.signer, pm.approved)
	return nil
}
