# eve-sigverify

Verifies the Sigstore keyless signatures that EVE's release workflow puts on
an EVE image and on the release assets, and optionally a maintainer's
approval of the release, as described in EVE's
[docs/SIGNING.md](https://github.com/lf-edge/eve/blob/master/docs/SIGNING.md).
Given a downloaded OCI layout or assets, it verifies offline. Given an image
reference or a release tag, it fetches the inputs first and then runs the
same checks.

Build it with Go 1.25 or later:

```sh
go build -o eve-sigverify .
```

Each run prints one `OK:` or `FAIL:` verdict line. Exit status is 0 when
verified, 1 when verification fails, and 2 on a usage or input error.

```text
eve-sigverify image   [common flags] [-digest sha256:...] OCI_LAYOUT_DIR
eve-sigverify image   [common flags] [-platform OS/ARCH] [-content] REF
eve-sigverify assets  [common flags] [-approval FILE] DIR SHA256SUMS
eve-sigverify release [common flags] [-variant ARCH.HV.PLATFORM]... [-asset NAME]...
                      [-allow-mutable] [-github-trusted-root FILE] TAG
eve-sigverify trusted-root -o FILE
```

The examples below verify releases of the `eriknordmark/eve` fork, whose
signing workflow runs from its `sign-master` branch, hence
`-repo eriknordmark/eve -signer-ref refs/heads/sign-master`. Drop both flags
for an `lf-edge/eve` release.

## Trusted root

Verification needs Sigstore's public-good `trusted_root.json` (Fulcio CA,
Rekor and CT log keys, timestamp authorities). `-trusted-root FILE` names a
local copy. Without it, every mode fetches the file through Sigstore's TUF
repository, keeping TUF metadata under the user cache directory
(`eve-sigverify/tuf`), so expired metadata and a rolled-back root are
refused. `trusted-root` saves a copy for offline use:

```console
$ eve-sigverify trusted-root -o trusted_root.json
OK: wrote trusted_root.json
```

The file changes only when Sigstore rotates keys, so a copy can be carried to
an offline host.

## Policy

A signature must come from `release-sign.yml` on `master` of `lf-edge/eve`,
issued by GitHub Actions OIDC, with the certificate's Source Repository Ref a
release tag and its Deployment Environment `release`. That one workflow signs
every image, index, SBOM attestation and sums file of a release, for the tag
that called it.

| Flag | Checks |
|---|---|
| `-repo owner/name` | repository of the workflow and of the source (default `lf-edge/eve`) |
| `-signer-ref ref` | ref of `release-sign.yml` in the identity (default `refs/heads/master`) |
| `-tag tag` | the release tag exactly, instead of any release tag |
| `-environment name` | the signing job's deployment environment (default `release`; empty accepts any) |
| `-maintainer emails` | an approval of the same release signed by one of these comma-separated emails, issuer `https://github.com/login/oauth` |
| `-identity`, `-identity-regexp`, `-repository`, `-issuer` | override parts of the workflow identity |

A maintainer approval is an in-toto statement of type
`https://github.com/<repo>/release-approval/v1` whose subjects are every image
and sums file of a release and whose predicate names the repository and
release; it must name the tag that the workflow signature names.

## Online

`image REF` and `release TAG` download into a temporary directory, or into
`-keep DIR`, which then holds an OCI layout (`DIR/image`) or the release
assets, plus the trusted roots used, for a later offline re-check.

```console
$ eve-sigverify image -repo eriknordmark/eve -signer-ref refs/heads/sign-master -tag 9.9.0-rc9 -maintainer erik@zededa.com \
    docker.io/eriknordmark/eve-signtest@sha256:feb39ffaa5216a79d1a808ebea974383772de7f4e73a207fde1a635e41039d42
OK: image sha256:feb39ffaa5216a79d1a808ebea974383772de7f4e73a207fde1a635e41039d42 (docker.io/eriknordmark/eve-signtest@sha256:feb39ffaa5216a79d1a808ebea974383772de7f4e73a207fde1a635e41039d42) of release 9.9.0-rc9 signed by https://github.com/eriknordmark/eve/.github/workflows/release-sign.yml@refs/heads/sign-master at 2026-09-30T19:55:38Z (Tlog), approved by erik@zededa.com at 2026-09-30T22:35:47Z (Tlog)
```

- `image REF` fetches the manifest and its Sigstore bundle referrers through
  the OCI referrers API. For an index, both the index and its `-platform`
  manifest (default: the host's) must be signed for the same release. The
  signature covers the manifest digest, which pins every layer; `-content`
  also downloads and hashes the config and layers. The verdict names the
  verified digest; deploy by that digest, not by tag. Registry credentials
  are read from the Docker config when present.
- `release TAG` reads the release from the GitHub API, downloads every
  `*.sha256sums` (or those `-variant` names), their bundles, each variant's
  `images.txt`, any `-asset`, and with `-maintainer` the approval bundle, and
  verifies each sums file as `assets` does. `GH_TOKEN`, when set, is sent to
  `api.github.com` only.
- A release must be a GitHub immutable release. Its release attestation,
  signed by GitHub (`https://dotcom.releases.github.com`) under GitHub's own
  trusted root (fetched from `https://tuf-repo.github.com`, anchored on the
  root the GitHub CLI embeds, or `-github-trusted-root FILE`), must name the
  repository and tag, put the tag at the commit the signing run built, and
  list every downloaded asset with its sha256. `-allow-mutable` accepts a
  release that is not immutable and says so in the verdict:

```console
$ eve-sigverify release -repo eriknordmark/eve -signer-ref refs/heads/sign-master 0.0.1-rc13
OK: amd64.kvm.generic.sha256sums of release 0.0.1-rc13 signed by https://github.com/eriknordmark/eve/.github/workflows/release-sign.yml@refs/heads/sign-master at 2026-10-09T17:39:33Z (Tlog); 1 assets match, 7 listed but not present
OK: arm64.kvm.generic.sha256sums of release 0.0.1-rc13 signed by https://github.com/eriknordmark/eve/.github/workflows/release-sign.yml@refs/heads/sign-master at 2026-10-09T17:39:36Z (Tlog); 1 assets match, 7 listed but not present
FAIL: release 0.0.1-rc13 is not immutable; -allow-mutable accepts it
```

## Image

The input is an OCI image layout holding the image and its referrers, where
cosign 3 stores the signature and SBOM attestation bundles and where the
maintainer approval is attached. `oras` copies them; `cosign save` does not
include referrers.

```console
$ oras copy --recursive --to-oci-layout \
    docker.io/eriknordmark/eve-signtest@sha256:feb39ffaa5216a79d1a808ebea974383772de7f4e73a207fde1a635e41039d42 ./layout
$ eve-sigverify image -trusted-root trusted_root.json -repo eriknordmark/eve -signer-ref refs/heads/sign-master \
    -tag 9.9.0-rc9 -maintainer erik@zededa.com ./layout
OK: image sha256:feb39ffaa5216a79d1a808ebea974383772de7f4e73a207fde1a635e41039d42 (3 blobs) of release 9.9.0-rc9 signed by https://github.com/eriknordmark/eve/.github/workflows/release-sign.yml@refs/heads/sign-master at 2026-09-30T19:55:38Z (Tlog), approved by erik@zededa.com at 2026-09-30T22:35:47Z (Tlog)
```

Every blob of the image is hashed against its manifest, and at least one
referrer must be a `cosign sign` signature over the manifest digest matching
the policy; an SBOM attestation alone does not count. Use `-digest` when the
layout holds more than one image.

The same image without an approval by the named maintainer fails:

```console
$ eve-sigverify image -trusted-root trusted_root.json -repo eriknordmark/eve -signer-ref refs/heads/sign-master \
    -maintainer nordmark@sonic.net ./layout
rejected bundle sha256:d05c2cac…: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SAN value "https://github.com/eriknordmark/eve/.github/workflows/release-sign.yml@refs/heads/sign-master", got "erik@zededa.com"
FAIL: image sha256:feb39ffaa5216a79d1a808ebea974383772de7f4e73a207fde1a635e41039d42: no approval of release 9.9.0-rc9 by nordmark@sonic.net
```

## Release assets

Each release variant has a `<arch>.<hv>.<platform>.sha256sums` asset and its
signature bundle `<sums>.sigstore.json`. The sums file is verified against the
bundle, then every listed asset present in `DIR` against the signed sums.
Listed assets that were not downloaded are counted, not failed. With
`-maintainer`, the approval bundle (`-approval`, default
`DIR/<tag>.maintainer.sigstore.json`) must list the sums file as a subject.

```console
$ eve-sigverify assets -trusted-root trusted_root.json -repo eriknordmark/eve -signer-ref refs/heads/sign-master \
    rc10 rc10/amd64.kvm.generic.sha256sums
OK: amd64.kvm.generic.sha256sums of release 0.0.1-rc10 signed by https://github.com/eriknordmark/eve/.github/workflows/release-sign.yml@refs/heads/sign-master at 2026-10-01T06:48:30Z (Tlog); 2 assets match, 6 listed but not present
```

The `images.txt` asset names the `eve` and `eve-sources` image digests the
assets were extracted from, so the sums signature also binds those images.
A changed asset fails, and so does a signature for another tag:

```console
$ eve-sigverify assets -trusted-root trusted_root.json -repo eriknordmark/eve -signer-ref refs/heads/sign-master \
    tampered tampered/amd64.kvm.generic.sha256sums
FAIL: amd64.kvm.generic.images.txt: sha256 3b2951ca4d87b1c05cd570ca697d5f61106af5a0e2f76ca3813699d44d4d9f4c, signed sums say d0d25e5e8214a902ce9fe2d0d2b8e24e642b2d03dd6c07e9f1e3bfec91b0bb69
$ eve-sigverify assets -trusted-root trusted_root.json -repo eriknordmark/eve -signer-ref refs/heads/sign-master \
    -tag 0.0.1-rc9 rc10 rc10/amd64.kvm.generic.sha256sums
FAIL: amd64.kvm.generic.sha256sums: signature does not match identity https://github.com/eriknordmark/eve/.github/workflows/release-sign.yml@refs/heads/sign-master, repository https://github.com/eriknordmark/eve, ref refs/tags/0.0.1-rc9: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SourceRepositoryRef to be "refs/tags/0.0.1-rc9", got "refs/tags/0.0.1-rc10"
```
