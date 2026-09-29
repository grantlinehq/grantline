"""Collect dependency license texts for the distributable, without source code."""
import json, subprocess, shutil
from pathlib import Path
ROOT=Path(__file__).resolve().parents[1]
out=ROOT/'third_party/licenses'
out.mkdir(parents=True,exist_ok=True)
raw=subprocess.check_output(['go','list','-m','-json','all'],cwd=ROOT,text=True)
decoder=json.JSONDecoder();modules=[]
while raw.strip():
    value,end=decoder.raw_decode(raw.lstrip());modules.append(value);raw=raw.lstrip()[end:]
manifest=[]
def collect(name,version,directory,kind):
    candidates=[p for p in directory.iterdir() if p.is_file() and p.name.lower().startswith(('license','licence','copying','notice','ofl','copyright'))]
    if not candidates:return
    target=out/kind/(name.replace('/','__').replace('@','')+'@'+version)
    target.mkdir(parents=True,exist_ok=True)
    for path in candidates:shutil.copyfile(path,target/path.name)
    manifest.append({'name':name,'version':version,'ecosystem':kind,'files':[str((target/p.name).relative_to(out)) for p in candidates]})
for module in modules:
    if not module.get('Main') and module.get('Dir'):collect(module['Path'],module['Version'],Path(module['Dir']),'go')
store=ROOT/'web/node_modules/.pnpm'
for package in sorted(store.glob('*/node_modules/*')):
    for folder in package.iterdir() if package.name.startswith('@') else [package]:
        path=folder/'package.json'
        if not path.is_file():continue
        try:
            p=json.loads(path.read_text(encoding='utf-8'));collect(p['name'],p['version'],folder,'npm')
        except (KeyError,OSError,ValueError):continue
(out/'manifest.json').write_text(json.dumps(manifest,indent=2)+'\n',encoding='utf-8')
print(f'Collected notices for {len(manifest)} dependencies.')
