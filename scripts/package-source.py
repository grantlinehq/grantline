"""Create a reviewable public source archive using an explicit allowlist.

Use --list to inspect paths before staging. Nothing is committed or published.
"""
import argparse
from pathlib import Path
import zipfile

ROOT = Path(__file__).resolve().parents[1]
DIRECTORIES = [
    'cmd', 'internal', 'schema', 'testdata', 'charts', 'deploy', 'scripts',
    'third_party', 'web/src', 'web/public', 'web/scripts', 'docs/guide', '.github',
]
FILES = [
    'README.md', 'LICENSE', 'NOTICE', 'THIRD_PARTY_NOTICES.md', 'CONTRIBUTING.md',
    'CODE_OF_CONDUCT.md', 'SECURITY.md', 'CHANGELOG.md', 'go.mod', 'go.sum',
    'Dockerfile', '.dockerignore', '.gitignore', '.gitleaks.toml', '.gitattributes',
    'compose.yaml', 'compose.build.yaml', 'compose.dev.yaml', 'web/assets.go', 'web/package.json',
    'web/pnpm-lock.yaml', 'web/pnpm-workspace.yaml', 'web/index.html',
    'web/design-preview.html', 'web/vite.config.ts', 'web/tsconfig.json',
    'web/tsconfig.app.json', 'web/tsconfig.node.json', 'docs/.vitepress/config.mts',
    'docs/PRODUCTION_WORK.md', 'docs/architecture.md', 'docs/permissions.md',
    'docs/metadata-handling.md', 'docs/owasp-nhi-mapping.md', 'docs/supported-sources.md',
]
EXCLUDED = {'__pycache__', 'node_modules', '.git', '.secrets', 'coverage', '.cache'}


def public_paths():
    paths = [ROOT / name for name in FILES if (ROOT / name).is_file()]
    for name in DIRECTORIES:
        paths.extend(p for p in (ROOT / name).rglob('*') if p.is_file()
                     and not EXCLUDED.intersection(p.relative_to(ROOT).parts))
    result = sorted(set(paths))
    for path in result:
        if path.is_symlink() or not path.resolve().is_relative_to(ROOT):
            raise ValueError('Source allowlist cannot contain links outside the project')
        if path.stat().st_size > 10 * 1024 * 1024:
            raise ValueError('Review large source file: ' + str(path.relative_to(ROOT)))
        if path.suffix.lower() in {'.key', '.pem', '.pfx', '.p12', '.log', '.pyc'}:
            raise ValueError('Review unexpected source file: ' + str(path.relative_to(ROOT)))
    return result


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--list', action='store_true')
    args = parser.parse_args()
    paths = public_paths()
    if args.list:
        for path in paths:
            print(path.relative_to(ROOT).as_posix())
        return
    dest = ROOT / 'bin/grantline-source-candidate.zip'
    dest.parent.mkdir(parents=True, exist_ok=True)
    with zipfile.ZipFile(dest, 'w', zipfile.ZIP_DEFLATED) as archive:
        for path in paths:
            archive.write(path, 'grantline/' + path.relative_to(ROOT).as_posix())
    print(f'Public source candidate: {len(paths)} files, {dest.stat().st_size} bytes. Nothing published.')


if __name__ == '__main__':
    main()
