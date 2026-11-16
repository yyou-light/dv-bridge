#!/usr/bin/env python3
"""Build an explicit, reproducible public-source ZIP; never walks private data."""
import argparse
import hashlib
import json
from pathlib import Path, PurePosixPath
import re
import sys
import zipfile

ROOT=Path(__file__).resolve().parents[1]
REPOSITORY='https://github.com/yyou-light/etx-clipboard-bridge'
FORBIDDEN=re.compile(r'\bsh-etxn[0-9]+\b|/nfs/(?:workspace[0-9]*|regression)/[A-Za-z_][A-Za-z0-9_.-]+|[A-Z]:[/\\]Users[/\\][A-Za-z_][A-Za-z0-9_.-]+',re.I)
SECRET=re.compile(r'-----BEGIN (?:RSA |EC |ENCRYPTED )?PRIVATE KEY-----\s+[A-Za-z0-9+/=]{24,}|(?:ghp_|github_pat_)[A-Za-z0-9_]{20,}')
DENIED={'.private','.work','.git','bootstrap','state','identity','queue','jobs','runs','logs','backups','__pycache__'}


def files():
    names=[line.strip() for line in (ROOT/'release-files.txt').read_text(encoding='utf-8').splitlines()
        if line.strip() and not line.startswith('#')]
    if len(names)!=len(set(names)):raise ValueError('DUPLICATE_RELEASE_PATH')
    for name in names:
        path=PurePosixPath(name)
        if path.is_absolute() or '..' in path.parts or DENIED.intersection(path.parts):
            raise ValueError('UNSAFE_RELEASE_PATH: '+name)
        target=ROOT/name
        if any(p.is_symlink() for p in (target,*target.parents)) or not target.is_file():
            raise ValueError('RELEASE_FILE_NOT_REGULAR: '+name)
        raw=target.read_bytes()
        text=raw.decode('utf-8').replace(REPOSITORY,'')
        if FORBIDDEN.search(text) or SECRET.search(text):raise ValueError('SITE_OR_SECRET_LITERAL: '+name)
        if b'\r\n' in raw:raise ValueError('RELEASE_REQUIRES_LF: '+name)
    return sorted(names)


def main():
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--check',action='store_true')
    parser.add_argument('--output',type=Path)
    args=parser.parse_args()
    names=files();version=(ROOT/'VERSION').read_text().strip()
    hashes={name:hashlib.sha256((ROOT/name).read_bytes()).hexdigest() for name in names}
    manifest={'version':1,'project':'etx-clipboard-bridge','release':version,'files':hashes}
    path=ROOT/'config/release.json'
    if args.check:
        if json.loads(path.read_bytes())!=manifest:raise ValueError('RELEASE_MANIFEST_OUT_OF_DATE')
        print(json.dumps({'checked_files':len(names),'site_literal_or_secret_matches':0}))
        return
    path.parent.mkdir(exist_ok=True)
    path.write_text(json.dumps(manifest,ensure_ascii=False,sort_keys=True,indent=2)+'\n',encoding='utf-8',newline='\n')
    output=(args.output or ROOT/'.work/dist').absolute();output.mkdir(parents=True,exist_ok=True)
    archive=output/('etx-clipboard-bridge-'+version+'.zip')
    with zipfile.ZipFile(archive,'w',zipfile.ZIP_DEFLATED) as bundle:
        for name in [*names,'config/release.json']:
            info=zipfile.ZipInfo(name,date_time=(2026,11,15,0,0,0))
            info.compress_type=zipfile.ZIP_DEFLATED;info.create_system=3
            info.external_attr=(0o100755 if name.endswith('.sh') else 0o100644)<<16
            bundle.writestr(info,(ROOT/name).read_bytes())
    digest=hashlib.sha256(archive.read_bytes()).hexdigest()
    (output/(archive.name+'.sha256')).write_text(digest+'  '+archive.name+'\n',encoding='ascii')
    print(json.dumps({'files':len(names)+1,'archive':str(archive),'sha256':digest}))


if __name__=='__main__':
    try:main()
    except Exception as error:
        print('BUILD_FAILED: '+str(error),file=sys.stderr)
        raise SystemExit(1)
