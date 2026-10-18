// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// eve-sigverify checks the Sigstore keyless signatures EVE's release
// workflow puts on an EVE image and on the release assets, and optionally a
// maintainer's approval of the release. Offline it reads an OCI layout or
// downloaded assets and a trusted_root.json; online it fetches them, then
// runs the same checks. docs/SIGNING.md describes what is signed and by whom.
//
// Exit status: 0 verified, 1 verification failed, 2 usage or input error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"path/filepath"
	"runtime"
	"strings"

	"github.com/sigstore/sigstore-go/pkg/root"
)

const usage = `usage:
  eve-sigverify image   [common flags] [-digest sha256:...] OCI_LAYOUT_DIR
  eve-sigverify image   [common flags] [-platform OS/ARCH] [-content] REF
  eve-sigverify assets  [common flags] [-approval FILE] DIR SHA256SUMS
  eve-sigverify release [common flags] [-variant ARCH.HV.PLATFORM]... [-asset NAME]...
                        [-allow-mutable] [-github-trusted-root FILE] TAG
  eve-sigverify trusted-root -o FILE     (fetch Sigstore's trusted root via TUF)

A REF or TAG is fetched (image from its registry, release from GitHub) into a
temporary directory, or into -keep DIR, and then verified as offline.

common flags:
  -trusted-root FILE       Sigstore trusted_root.json (default: fetch via TUF)
  -keep DIR                keep fetched inputs, including trusted roots, in DIR

policy flags:
  -repo OWNER/NAME         GitHub repository that signed (default lf-edge/eve); sets
                           the default identity, source repository and approval type
  -signer-ref REF          ref of release-sign.yml in the identity (default ` + defaultSignerRef + `)
  -tag TAG                 require this release tag (default: any release tag)
  -environment NAME        required deployment environment of the signing job
                           (default ` + releaseEnv + `; empty accepts any)
  -maintainer EMAILS       require an approval of the release signed by one of these
                           comma-separated maintainer emails
  -identity URI            exact certificate identity (workflow@ref)
  -identity-regexp RE      certificate identity regexp
  -repository URI          certificate source repository (default https://github.com/OWNER/NAME)
  -issuer URL              OIDC issuer (default ` + githubIssuer + `)
`

// errUsage marks input errors, which exit 2 rather than 1.
var errUsage = errors.New("usage error")

func main() {
	if len(os.Args) < 2 {
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	var err error
	switch os.Args[1] {
	case "image", "assets", "release":
		err = runVerify(os.Args[1], os.Args[2:])
	case "trusted-root":
		err = runTrustedRoot(os.Args[2:])
	default:
		fmt.Fprint(os.Stderr, usage)
		os.Exit(2)
	}
	if err == nil {
		return
	}
	fmt.Fprintf(os.Stderr, "FAIL: %v\n", err)
	if errors.Is(err, errUsage) {
		os.Exit(2)
	}
	os.Exit(1)
}

// multiFlag collects a repeatable string flag.
type multiFlag []string

func (m *multiFlag) String() string     { return strings.Join(*m, ",") }
func (m *multiFlag) Set(v string) error { *m = append(*m, v); return nil }

func runVerify(kind string, args []string) error {
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	trustedRoot := fs.String("trusted-root", "", "Sigstore trusted_root.json (default: fetch via TUF)")
	keep := fs.String("keep", "", "keep fetched inputs in this directory")
	repo := fs.String("repo", "lf-edge/eve", "GitHub repository that signed")
	ref := fs.String("signer-ref", defaultSignerRef, "ref of release-sign.yml in the identity")
	tag := fs.String("tag", "", "required release tag")
	env := fs.String("environment", releaseEnv, "required deployment environment")
	maintainers := fs.String("maintainer", "", "comma-separated maintainer emails")
	approval := fs.String("approval", "", "maintainer approval bundle (assets mode)")
	identity := fs.String("identity", "", "exact certificate identity")
	identityRegexp := fs.String("identity-regexp", "", "certificate identity regexp")
	issuer := fs.String("issuer", githubIssuer, "OIDC issuer")
	repository := fs.String("repository", "", "source repository URI (default https://github.com/<repo>)")
	digest := fs.String("digest", "", "image digest to verify (image mode, OCI layout)")
	platform := fs.String("platform", "linux/"+runtime.GOARCH, "platform manifest to verify in an index (image mode, REF)")
	content := fs.Bool("content", false, "also fetch and hash config and layers (image mode, REF)")
	var variants, assets multiFlag
	fs.Var(&variants, "variant", "sha256sums variant to verify, repeatable (release mode; default all)")
	fs.Var(&assets, "asset", "further asset to download and check, repeatable (release mode)")
	allowMutable := fs.Bool("allow-mutable", false, "accept a release that is not immutable (release mode)")
	ghRoot := fs.String("github-trusted-root", "", "GitHub's trusted_root.json (release mode; default: fetch via TUF)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	p := defaultPolicy(*repo, *ref)
	p.issuer = *issuer
	p.environment = *env
	if *tag != "" {
		p.ref = "refs/tags/" + *tag
	}
	for _, m := range strings.Split(*maintainers, ",") {
		if m = strings.TrimSpace(m); m != "" {
			p.maintainers = append(p.maintainers, m)
		}
	}
	if *repository != "" {
		p.repository = *repository
	}
	if *identity != "" || *identityRegexp != "" {
		p.identity, p.identityRegexp = *identity, *identityRegexp
	}

	online := kind == "release"
	if kind == "image" && fs.NArg() == 1 {
		_, err := os.Stat(filepath.Join(fs.Arg(0), "index.json"))
		online = err != nil
	}
	if online {
		if fs.NArg() != 1 {
			return fmt.Errorf("%w: %s takes one argument", errUsage, kind)
		}
		if kind == "release" {
			if *tag != "" && *tag != fs.Arg(0) {
				return fmt.Errorf("%w: -tag %s differs from the release %s", errUsage, *tag, fs.Arg(0))
			}
			p.ref = "refs/tags/" + fs.Arg(0)
		}
	}
	dir := *keep
	if online || dir != "" {
		var err error
		if dir == "" {
			if dir, err = os.MkdirTemp("", "eve-sigverify-"); err != nil {
				return err
			}
			defer os.RemoveAll(dir)
		} else if err = os.MkdirAll(dir, 0o755); err != nil {
			return fmt.Errorf("%w: %v", errUsage, err)
		}
	}
	var tr *root.TrustedRoot
	var err error
	if *trustedRoot != "" {
		tr, err = root.NewTrustedRootFromPath(*trustedRoot)
	} else {
		tr, err = sigstoreRoot("", *keep)
	}
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	v, err := newVerifier(tr, p)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	switch {
	case kind == "release":
		return v.verifyReleaseOnline(fs.Arg(0), releaseOptions{
			variants: variants, assets: assets, allowMutable: *allowMutable, githubRoot: *ghRoot,
		}, dir)
	case kind == "image" && online:
		if *digest != "" {
			return fmt.Errorf("%w: give the digest in REF (name@sha256:...), not -digest", errUsage)
		}
		return v.verifyImageOnline(fs.Arg(0), *platform, *content, filepath.Join(dir, "image"))
	case kind == "image":
		if fs.NArg() != 1 {
			return fmt.Errorf("%w: image takes one OCI layout directory or reference", errUsage)
		}
		return v.verifyImage(fs.Arg(0), *digest)
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("%w: assets takes a directory and a sha256sums file", errUsage)
	}
	return v.verifyAssets(fs.Arg(0), fs.Arg(1), *approval)
}
