"""Assemble local candidate artifacts. This command never uploads or publishes."""
import hashlib
import io
import shutil
import subprocess
import sys
import tarfile
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
VERSION = '0.1.0-rc.1'
output = ROOT / 'bin' / ('release-' + VERSION)
output.mkdir(exist_ok=True)
subprocess.run([sys.executable, str(ROOT / 'scripts/package-source.py')], check=True)
artifacts = [
    (ROOT / 'bin/grantline-source-candidate.zip', 'grantline-source-' + VERSION + '.zip'),
    (ROOT / ('bin/grantline-' + VERSION + '.oci.tar'), 'grantline-' + VERSION + '.oci.tar'),
    (ROOT / ('bin/grantline-' + VERSION + '.tgz'), 'grantline-' + VERSION + '.tgz'),
]
for source, name in artifacts:
    if not source.is_file():
        raise SystemExit('Build the OCI image and Helm chart first: ' + source.name)
    shutil.copyfile(source, output / name)

instructions = '''# Grantline local release candidate

This package has not been published and is not yet approved as production ready.
Read docs/PRODUCTION_WORK.md in the source archive for verification and open gates.

1. Load the included multiarch image: docker load -i grantline-0.1.0-rc.1.oci.tar
2. Extract grantline-install-0.1.0-rc.1.tar.gz into a new directory.
3. In that directory run: docker compose up -d
4. Open http://127.0.0.1:8080 and follow docs/guide/install/docker.md for Owner setup.

The image includes the web application, fonts and /docs. No Go/Node installation
or source checkout is required. PostgreSQL's image is pulled by Docker on first
start. Data and generated secret files persist in named volumes.

For Helm, load the image into your cluster's container runtime or private registry,
prepare independent Secrets and use the included chart with image.repository and
image.tag set to that available image. Follow docs/guide/install/kubernetes.md.
Public GHCR image/chart references become usable only after the publication step.
'''
with tarfile.open(output / ('grantline-install-' + VERSION + '.tar.gz'), 'w:gz') as archive:
    for name in ['compose.yaml', 'deploy', 'README.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'docs/guide', 'docs/PRODUCTION_WORK.md', 'web/public/brand']:
        archive.add(ROOT / name, arcname=name)
    for name, value in [('.env', 'GRANTLINE_IMAGE=grantline:' + VERSION + '\n'), ('README-FIRST.md', instructions)]:
        data = value.encode()
        entry = tarfile.TarInfo(name)
        entry.size = len(data)
        entry.mode = 0o644
        archive.addfile(entry, io.BytesIO(data))
(output / 'README-FIRST.md').write_text(instructions, encoding='utf-8')
lines = []
for path in sorted(output.iterdir()):
    if path.name != 'SHA256SUMS' and path.is_file():
        with path.open('rb') as stream:
            checksum = hashlib.file_digest(stream, 'sha256').hexdigest()
        lines.append(checksum + '  ' + path.name)
(output / 'SHA256SUMS').write_text('\n'.join(lines) + '\n', encoding='utf-8')
print('Local candidate bundle: ' + str(output))
