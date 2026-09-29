"""Check relative Markdown links in publishable source, not private local notes."""
import importlib.util
import re
from pathlib import Path
from urllib.parse import unquote, urlsplit

root = Path(__file__).resolve().parents[1]
spec = importlib.util.spec_from_file_location('source_package', root / 'scripts/package-source.py')
package = importlib.util.module_from_spec(spec)
spec.loader.exec_module(package)
published = set(package.public_paths())
errors = []
count = 0
for path in sorted(published):
    if path.suffix != '.md' or 'third_party' in path.parts:
        continue
    text = re.sub(r'```.*?```', '', path.read_text(encoding='utf-8'), flags=re.S)
    for raw in re.findall(r'!?\[[^\]]*\]\(([^)]+)\)', text):
        target = raw.split(' "')[0].strip('<>')
        if not target or target.startswith('#') or urlsplit(target).scheme:
            continue
        url = unquote(urlsplit(target).path)
        if url.startswith('/'):
            candidates = [root / 'docs/guide/public' / url.lstrip('/'), root / 'web/public' / url.lstrip('/')]
        else:
            base = path.parent / url
            candidates = [base, Path(str(base) + '.md'), base / 'index.md']
            # VitePress serves guide/public at the documentation URL root.
            if path.is_relative_to(root / 'docs/guide'):
                relative = base.relative_to(root / 'docs/guide')
                candidates.append(root / 'docs/guide/public' / relative)
        count += 1
        if not any(p.resolve() in published for p in candidates):
            errors.append(f'{path.relative_to(root)}: {target}')
if errors:
    raise SystemExit('Broken/unpublished documentation links:\n' + '\n'.join(errors))
print(f'Checked {count} relative documentation links: all resolve inside public source.')
