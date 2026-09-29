// Copyright (c) 2026 Zededa, Inc.
// SPDX-License-Identifier: Apache-2.0

// eve-sigverify checks the Sigstore keyless signatures EVE's release
// workflow puts on an EVE image and on the release assets, and optionally a
// maintainer's approval of the release, offline, against a
// trusted_root.json. docs/SIGNING.md describes what is signed and by whom.
//
// Exit status: 0 verified, 1 verification failed, 2 usage or input error.
package main

import (
	"errors"
	"flag"
	"fmt"
	"os"
	"strings"
)

const usage = `usage:
  eve-sigverify image  -trusted-root FILE [policy flags] [-digest sha256:...] OCI_LAYOUT_DIR
  eve-sigverify assets -trusted-root FILE [policy flags] [-approval FILE] DIR SHA256SUMS
  eve-sigverify trusted-root -o FILE     (online: fetch Sigstore's trusted root via TUF)

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
	case "image", "assets":
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

func runVerify(kind string, args []string) error {
	fs := flag.NewFlagSet(kind, flag.ContinueOnError)
	trustedRoot := fs.String("trusted-root", "", "Sigstore trusted_root.json")
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
	digest := fs.String("digest", "", "image digest to verify (image mode)")
	if err := fs.Parse(args); err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if *trustedRoot == "" {
		return fmt.Errorf("%w: -trusted-root is required", errUsage)
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
	v, err := newVerifier(*trustedRoot, p)
	if err != nil {
		return fmt.Errorf("%w: %v", errUsage, err)
	}
	if kind == "image" {
		if fs.NArg() != 1 {
			return fmt.Errorf("%w: image takes one OCI layout directory", errUsage)
		}
		return v.verifyImage(fs.Arg(0), *digest)
	}
	if fs.NArg() != 2 {
		return fmt.Errorf("%w: assets takes a directory and a sha256sums file", errUsage)
	}
	return v.verifyAssets(fs.Arg(0), fs.Arg(1), *approval)
}
