# Release operations

The current release is **v0.1.0-rc.2**, a preview. The release provides a multiarch
image, OCI Helm chart, Docker installation ZIP/TAR, source ZIP and signed checksums.
The maintainer controls source visibility and registry publication. Release
automation never changes repository visibility or declares production readiness.

## Verify a release

Download the assets from the versioned [release page](https://github.com/grantlinehq/grantline/releases/tag/v0.1.0-rc.2).
`release.json` records the exact source commit, image digest, chart digest and
architectures. Installation packages pin the application digest in `.env`.

Install Cosign from its [official releases](https://github.com/sigstore/cosign/releases)
to verify the workflow identity and signed checksum file:

```sh
SIGNER=https://github.com/grantlinehq/grantline/.github/workflows/release.yml@refs/heads/main
ISSUER=https://token.actions.githubusercontent.com
cosign verify-blob --bundle SHA256SUMS.sigstore.json --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER" SHA256SUMS
sha256sum --check --ignore-missing SHA256SUMS
```

Run this in the download directory with the selected assets present. The checksum
command skips assets you did not download; it does not verify missing files.
On Windows use `Get-FileHash -Algorithm SHA256` and compare each downloaded asset
with its entry in the authenticated `SHA256SUMS` file.

Use the exact digests from `release.json` to verify the registry artifacts:

```sh
cosign verify ghcr.io/grantlinehq/grantline@sha256:IMAGE_DIGEST --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER"
cosign verify ghcr.io/grantlinehq/charts/grantline@sha256:CHART_DIGEST --certificate-identity "$SIGNER" --certificate-oidc-issuer "$ISSUER"
```

Replace `IMAGE_DIGEST` and `CHART_DIGEST` with their hex values. BuildKit attaches
runtime/frontend SPDX SBOMs and provenance to the multiarch image. Signature
verification establishes the publisher and content digest; it does not replace
the compatibility or security acceptance record.

## Source preparation

1. Use the source allowlist: `python3 scripts/package-source.py --list`. Exclude
   private workstation/lab notes, reports, secret files and build outputs.
2. Review staged paths and run Gitleaks on source and all Git history. Revoke a real
   exposed credential; deleting a file alone does not repair history or exposure.
3. Push the reviewed source and require a successful actual Checks workflow.
   Fresh-clone the pushed commit and follow README. Test updated Compose and Helm
   against new disposable data; retain evidence without credentials.
4. Review supported scope, permissions, screenshots, metadata handling, license,
   dependency notices and the acceptance record. Do not present fixtures as live data.

## Candidate artifacts

The manual **Release candidate** workflow defaults `publish` to false and accepts
explicit `0.1.0-rc.N` versions. Its build
uses Go/Node version constraints, lockfiles and SHA-pinned actions. Base images in
the Dockerfile are pinned to multiarchitecture digests; dependency updates must be
reviewed and tested. Tool versions and vulnerability databases have different
lifecycles: scanners are versioned, while advisory data is fetched at scan time.

The workflow runs the shared Checks suite, builds linux/amd64 and linux/arm64
images with BuildKit SBOM/provenance, scans both registry architectures and tests
clean Compose installation. It signs the image and chart digests, verifies the
chart downloaded from GHCR, generates digest-pinned ZIP/TAR packages and signs
their checksums before creating a GitHub prerelease. Existing release tags and
image versions must not be overwritten; use a new candidate version for changes.
With publication disabled only the OCI archive, chart and checksums are uploaded
as CI artifacts; no registry package or GitHub release is created.
When publishing, the workflow creates or verifies the tag against the exact source
commit before writing registry artifacts. GitHub Releases uses that existing tag
without asking the release API to create a ref on a historical commit. A failure
preserves the signed CI artifact; resume only with the existing image/chart digests,
or choose a new version for changed source. Never move an existing release tag.
Release artifacts are not normal Git files. Local `scripts/package-local-candidate.py`
can assemble already-built image/chart/source artifacts under ignored `bin/`.

Review the exact commit, version, platform manifests, frontend/runtime SBOMs,
checksum coverage and scan results. Verify both documented install paths. Preview
limitations stay visible; outstanding product acceptance gates prohibit a stable
production-ready label.

## Public launch and registry publication

Public launch requires an explicit maintainer decision after the final history,
sanitization, CI, fresh-clone and documentation review. Enable GitHub private
vulnerability reporting and confirm its link works. Configure available branch,
Dependabot and scanning protections; private Free-plan limitations must be recorded,
not presented as enabled controls.

Registry publication is another explicit action. The workflow checks the configured
`ALLOW_REGISTRY_PUBLISH` repository variable before allowing `publish=true` and uses
the `release` environment. Keep that variable disabled until publication is intended.
Where the plan supports it, configure required reviewers for that environment.
On publication, Cosign signs the image, chart and checksums using GitHub OIDC. Verify the expected
repository/workflow identity and issuer before trusting a signature; a valid
signature alone does not demonstrate application safety.

After launch verify README rendering, images, links, detected license, security
alerts, topics, Issues/Discussions and a clean public clone. Publishing the chart
does not run database upgrades for users; preserve the backup/compatibility guidance.
