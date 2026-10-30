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

The examples below verify EVE 17.12.0. For a fork's release, name the fork
with `-repo` and the branch its signing workflow runs from with `-signer-ref`.

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
assets, plus the trusted roots used, for a later offline re-check; an image
re-check needs `-content`, since it hashes every blob.

```console
$ eve-sigverify image -tag 17.12.0 docker.io/lfedge/eve:17.12.0-kvm-amd64
info: verified https://spdx.dev/Document attestation by https://github.com/lf-edge/eve/.github/workflows/release-sign.yml@refs/heads/master at 2026-10-30T18:50:12Z (Tlog)
OK: image sha256:76e5b795105f44b1dd8ae452c8b5d5c8ad0d3bb2e79ff19f458144394d1a9a8b (docker.io/lfedge/eve:17.12.0-kvm-amd64) of release 17.12.0 signed by https://github.com/lf-edge/eve/.github/workflows/release-sign.yml@refs/heads/master at 2026-10-30T18:43:12Z (Tlog)
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
$ eve-sigverify release -variant amd64.kvm.generic 17.12.0
OK: amd64.kvm.generic.sha256sums of release 17.12.0 signed by https://github.com/lf-edge/eve/.github/workflows/release-sign.yml@refs/heads/master at 2026-10-30T18:52:01Z (Tlog); 1 assets match, 7 listed but not present
warning: release 17.12.0 has no 17.12.0.tagger.sigstore.json; who pushed the tag is not recorded
info: release environment approved by christoph-zededa (GitHub user ID 121871801), recorded only by GitHub in https://github.com/lf-edge/eve/actions/runs/41071947071/attempts/1
warning: no maintainer approval checked; -maintainer requires 17.12.0.maintainer.sigstore.json
OK: release 17.12.0 is immutable: GitHub attests tag 17.12.0 at commit ed75ebb94fd7c65e6cbe3fb5d883c062b1956b7f with these 3 assets
```

The asset that matches is `images.txt`; name others with `-asset`, e.g.
`-asset amd64.kvm.generic.installer.raw.zst`, to download and check them too.
Flags go before the tag.

`release` also reports who pushed the tag and who approved its signing:

- The tagger comes from `<tag>.tagger.sigstore.json`, an in-toto statement of
  type `https://github.com/<repo>/release-tagger/v1` that `release-sign.yml`
  signs over every sums file, naming the tag, commit and the pusher's GitHub
  login and user ID. It is in Rekor. An invalid statement fails; a missing one
  is a warning.
- The approvers of the signing run's deployment environment come from GitHub's
  run approvals API. GitHub keeps them only with the run, so a deleted run
  loses them. None found is a warning, and so is a tagger who also approved.

## Image

The input is an OCI image layout holding the image and its referrers, where
cosign 3 stores the signature and SBOM attestation bundles and where the
maintainer approval is attached. `oras` copies them; `cosign save` does not
include referrers.

```console
$ oras copy --recursive --to-oci-layout docker.io/lfedge/eve:17.12.0-kvm-amd64 ./layout
$ eve-sigverify image -trusted-root trusted_root.json -tag 17.12.0 ./layout
info: verified https://spdx.dev/Document attestation by https://github.com/lf-edge/eve/.github/workflows/release-sign.yml@refs/heads/master at 2026-10-30T18:50:12Z (Tlog)
OK: image sha256:76e5b795105f44b1dd8ae452c8b5d5c8ad0d3bb2e79ff19f458144394d1a9a8b (11 blobs) of release 17.12.0 signed by https://github.com/lf-edge/eve/.github/workflows/release-sign.yml@refs/heads/master at 2026-10-30T18:43:12Z (Tlog)
```

Every blob of the image is hashed against its manifest, and at least one
referrer must be a `cosign sign` signature over the manifest digest matching
the policy; an SBOM attestation alone does not count. Use `-digest` when the
layout holds more than one image.

An image without an approval by the named maintainer fails:

```console
$ eve-sigverify image -trusted-root trusted_root.json -maintainer someone@example.com ./layout
info: verified https://spdx.dev/Document attestation by https://github.com/lf-edge/eve/.github/workflows/release-sign.yml@refs/heads/master at 2026-10-30T18:50:12Z (Tlog)
FAIL: image sha256:76e5b795105f44b1dd8ae452c8b5d5c8ad0d3bb2e79ff19f458144394d1a9a8b: no approval of release 17.12.0 by someone@example.com
```

### An image pulled with docker

`docker pull` keeps no signatures, but the image is stored under the digest
the registry served. Verify that digest, then run the image by it:

```sh
d=$(docker image inspect --format '{{index .RepoDigests 0}}' lfedge/eve:17.12.0-kvm-amd64)
eve-sigverify image -tag 17.12.0 "docker.io/$d"
docker run --rm "$d" installer_raw > installer.raw
```

What `docker run` writes is as trustworthy as the image it ran. `rootfs` and
`sbom` produce the same bytes as the release's `rootfs.img` and
`rootfs.spdx.json`, so they can also be checked against the signed sums;
`installer_raw`, `installer_iso` and `live` create file systems with random
volume IDs and differ on every run.

## Release assets

Each release variant has a `<arch>.<hv>.<platform>.sha256sums` asset and its
signature bundle `<sums>.sigstore.json`. The sums file is verified against the
bundle, then every listed asset present in `DIR` against the signed sums.
Listed assets that were not downloaded are counted, not failed. With
`-maintainer`, the approval bundle (`-approval`, default
`DIR/<tag>.maintainer.sigstore.json`) must list the sums file as a subject.

```console
$ gh release download 17.12.0 -R lf-edge/eve -D 17.12.0 -p 'amd64.kvm.generic.sha256sums*' \
    -p amd64.kvm.generic.images.txt -p amd64.kvm.generic.rootfs.spdx.json
$ eve-sigverify assets -trusted-root trusted_root.json 17.12.0 17.12.0/amd64.kvm.generic.sha256sums
OK: amd64.kvm.generic.sha256sums of release 17.12.0 signed by https://github.com/lf-edge/eve/.github/workflows/release-sign.yml@refs/heads/master at 2026-10-30T18:52:01Z (Tlog); 2 assets match, 6 listed but not present
```

The `images.txt` asset names the `eve` and `eve-sources` image digests the
assets were extracted from, so the sums signature also binds those images.
A changed asset fails, and so does a signature for another tag:

```console
$ eve-sigverify assets -trusted-root trusted_root.json tampered tampered/amd64.kvm.generic.sha256sums
FAIL: amd64.kvm.generic.images.txt: sha256 cdeb4e4b2dd2a71434a7b04d8b549aa41226efc55eefe38dc04ab37b59fba277, signed sums say ed4b6eca7ba651063062b2c03671ff3dbe28803f973d7c5561c0d554816138a2
$ eve-sigverify assets -trusted-root trusted_root.json -tag 17.11.0 17.12.0 17.12.0/amd64.kvm.generic.sha256sums
FAIL: amd64.kvm.generic.sha256sums: signature does not match identity https://github.com/lf-edge/eve/.github/workflows/release-sign.yml@refs/heads/master, repository https://github.com/lf-edge/eve, ref refs/tags/17.11.0: failed to verify certificate identity: no matching CertificateIdentity found, last error: expected SourceRepositoryRef to be "refs/tags/17.11.0", got "refs/tags/17.12.0"
```
