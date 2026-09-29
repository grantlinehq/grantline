# Release operations

The current candidate is a preview. Source visibility, image/chart publication and
production-readiness approval are separate decisions. No automation turns a private
repository public. The maintainer controls that transition.

## Private preparation

1. Use the source allowlist: `python3 scripts/package-source.py --list`. Exclude
   private workstation/lab notes, reports, secret files and build outputs.
2. Review staged paths and run Gitleaks on source and all Git history. Revoke a real
   exposed credential; deleting a file alone does not repair history or exposure.
3. Push to the private repository and require a successful actual Checks workflow.
   Fresh-clone the pushed commit and follow README. Test updated Compose and Helm
   against new disposable data; retain evidence without credentials.
4. Review supported scope, permissions, screenshots, metadata handling, license,
   dependency notices and the acceptance record. Do not present fixtures as live data.

## Candidate artifacts

The manual **Release candidate** workflow defaults `publish` to false. Its build
uses Go/Node version constraints, lockfiles and SHA-pinned actions. Base images in
the Dockerfile are pinned to multiarchitecture digests; dependency updates must be
reviewed and tested. Tool versions and vulnerability databases have different
lifecycles: scanners are versioned, while advisory data is fetched at scan time.

The workflow builds linux/amd64 and linux/arm64 images with BuildKit SBOM/provenance,
packages the Helm chart and Compose installation bundle, and generates checksums.
With publication disabled the OCI archive is a downloadable CI artifact, not a
published registry image. Load it before using that candidate's installation bundle.
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
On publication, cosign signs the image digest using GitHub OIDC. Verify the expected
repository/workflow identity and issuer before trusting a signature; a valid
signature alone does not demonstrate application safety.

After launch verify README rendering, images, links, detected license, security
alerts, topics, Issues/Discussions and a clean public clone. Publishing the chart
does not run database upgrades for users; preserve the backup/compatibility guidance.
