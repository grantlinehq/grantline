"""Package a verified candidate for GitHub Releases without publishing anything."""
import argparse
import hashlib
import importlib.util
import io
import json
from pathlib import Path
import re
import shutil
import tarfile
import zipfile

ROOT = Path(__file__).resolve().parents[1]


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--version', required=True)
    parser.add_argument('--commit', required=True)
    parser.add_argument('--image-digest', required=True)
    parser.add_argument('--chart-digest', required=True)
    parser.add_argument('--chart', type=Path, required=True)
    parser.add_argument('--output', type=Path, required=True)
    args = parser.parse_args()
    if not re.fullmatch(r'0\.1\.0-rc\.[1-9][0-9]*', args.version):
        parser.error('Use an explicit 0.1.0-rc.N candidate version')
    if not re.fullmatch(r'[0-9a-f]{40}', args.commit):
        parser.error('Use the exact source commit SHA')
    for digest in [args.image_digest, args.chart_digest]:
        if not re.fullmatch(r'sha256:[0-9a-f]{64}', digest):
            parser.error('Image and chart digests must be sha256 values')
    if not args.chart.is_file():
        parser.error('The verified Helm chart archive is missing')
    args.output.mkdir(parents=True, exist_ok=True)
    spec = importlib.util.spec_from_file_location('source_package', ROOT / 'scripts/package-source.py')
    package = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(package)
    files = package.public_paths()
    source_name = f'grantline-source-{args.version}.zip'
    with zipfile.ZipFile(args.output / source_name, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in files:
            archive.write(path, 'grantline/' + path.relative_to(ROOT).as_posix())

    image = 'ghcr.io/grantlinehq/grantline@' + args.image_digest
    chart_ref = 'ghcr.io/grantlinehq/charts/grantline@' + args.chart_digest
    instructions = f'''# Grantline {args.version}

Preview / release candidate. Review docs/guide/reference/compatibility.md before deployment.

1. Extract the installation ZIP or TAR into a new directory.
2. Run: docker compose up -d --wait
3. Open http://127.0.0.1:8080
4. Read your one-time setup token in your own terminal:
   docker compose exec app cat /var/lib/grantline/secrets/setup-token
5. Create your Owner account and enroll a TOTP authenticator.

Requirements: Docker with Compose, Linux containers, network access and free port 8080.
Go, Node.js and a source build are not required. The application image is pinned by
digest in .env. PostgreSQL and generated secret files persist in named volumes.
Use docker compose down to stop; do not use down -v on data you need to retain.

See docs/guide/install/docker.md for HTTPS and alternate ports. For Kubernetes,
start with the included charts/grantline/examples/production.yaml and use:
helm upgrade --install grantline oci://ghcr.io/grantlinehq/charts/grantline --version {args.version} -n grantline -f my-values.yaml --wait

Provision the namespace, database and private Secret first, following
docs/guide/install/kubernetes.md. The chart never generates your encryption key.
Release checksums and signature instructions are in docs/guide/operations/releases.md.
'''
    roots = ('deploy/', 'docs/guide/', 'third_party/licenses/', 'web/public/brand/',
             'charts/grantline/examples/')
    named = {'compose.yaml', 'README.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md',
             'CONTRIBUTING.md', 'CODE_OF_CONDUCT.md', 'SECURITY.md', 'CHANGELOG.md',
             'docs/PRODUCTION_WORK.md', 'docs/architecture.md', 'docs/permissions.md',
             'docs/metadata-handling.md', 'docs/owasp-nhi-mapping.md', 'docs/supported-sources.md'}
    selected = {p.relative_to(ROOT).as_posix(): p for p in files
                if p.relative_to(ROOT).as_posix() in named
                or p.relative_to(ROOT).as_posix().startswith(roots)}
    generated = {'.env': f'GRANTLINE_IMAGE={image}\n'.encode(),
                 'README-FIRST.md': instructions.encode()}
    tar_name = f'grantline-install-{args.version}.tar.gz'
    zip_name = f'grantline-install-{args.version}.zip'
    with tarfile.open(args.output / tar_name, 'w:gz') as tar, \
            zipfile.ZipFile(args.output / zip_name, 'w', zipfile.ZIP_DEFLATED) as zipped:
        for name, path in sorted(selected.items()):
            tar.add(path, arcname=name, recursive=False)
            zipped.write(path, name)
        for name, data in generated.items():
            entry = tarfile.TarInfo(name)
            entry.size, entry.mode = len(data), 0o644
            tar.addfile(entry, io.BytesIO(data))
            zipped.writestr(name, data)
    chart_name = f'grantline-{args.version}.tgz'
    destination = args.output / chart_name
    if args.chart.resolve() != destination.resolve():
        shutil.copyfile(args.chart, destination)
    metadata = {'version': args.version, 'source_commit': args.commit,
                'image': image, 'image_tag': f'ghcr.io/grantlinehq/grantline:{args.version}',
                'chart': chart_ref, 'chart_version': args.version,
                'platforms': ['linux/amd64', 'linux/arm64'], 'release_status': 'prerelease'}
    (args.output / 'release.json').write_text(json.dumps(metadata, indent=2) + '\n', encoding='utf-8')
    (args.output / 'README-FIRST.md').write_text(instructions, encoding='utf-8')
    notes = f'''Grantline **{args.version}** is a preview for self-hosted non-human identity investigation.

Download `grantline-install-{args.version}.zip` (Windows/macOS/Linux) or
`grantline-install-{args.version}.tar.gz` (Linux/macOS), extract it, and run
`docker compose up -d --wait`. Open http://127.0.0.1:8080 and follow README-FIRST.md.
The bundle pins the application digest; no Go/Node installation or source build is required.

- Container: `ghcr.io/grantlinehq/grantline:{args.version}` (amd64 and arm64).
- Image digest: `{args.image_digest}`.
- Helm: `oci://ghcr.io/grantlinehq/charts/grantline --version {args.version}`.
- Chart digest: `{args.chart_digest}`.
- Source commit: `{args.commit}`.
- `SHA256SUMS` covers every payload, with a Sigstore bundle authenticating the checksums.
- Image and chart digest signatures use this repository's release workflow identity.

Single organization and one active application instance. Provider access is read-only.
This candidate is not labeled production ready: the full live-provider/IdP/SMTP and
WCAG acceptance matrix remains open. See the compatibility and security documentation.
'''
    (args.output / 'RELEASE-NOTES.md').write_text(notes, encoding='utf-8')
    checksums = []
    for path in sorted(args.output.iterdir()):
        if path.is_file() and path.name not in {'SHA256SUMS', 'SHA256SUMS.sigstore.json'}:
            with path.open('rb') as source:
                digest = hashlib.file_digest(source, 'sha256').hexdigest()
            checksums.append(digest + '  ' + path.name)
    (args.output / 'SHA256SUMS').write_text('\n'.join(checksums) + '\n', encoding='utf-8')
    print(f'Packaged {args.version}: digest-pinned Compose ZIP/TAR, source, chart and checksums.')


if __name__ == '__main__':
    main()
