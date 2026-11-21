"""Rebuild the local verification copy of the Zenodo record published on 2026-11-21."""
import argparse
import hashlib
import json
import os
from pathlib import Path
import re
from tempfile import NamedTemporaryFile
import zipfile

HERE=Path(__file__).resolve().parent
EDITION=HERE.parent


def json_bytes(data):
    return (json.dumps(data,indent=2,ensure_ascii=False)+'\n').encode('utf-8')


def sha(data):
    return hashlib.sha256(data).hexdigest()


def add_pdf(files,source,target):
    data=source.read_bytes()
    if not data.startswith(b'%PDF-') or b'%%EOF' not in data[-2048:]:
        raise ValueError(f'Invalid PDF stream: {source}')
    if any(data==r for r in files.values()):
        raise ValueError(f'Duplicate supplied PDF: {source}')
    files['paper/files/'+target]=data


def add_edition(files,edition,language,explicit):
    full=explicit or edition/f'FULL_{language}.pdf'
    if not full.is_file():
        raise FileNotFoundError(f'Missing final integrated PDF: {full}')
    add_pdf(files,full,f'FULL_{language}.pdf')


def validate_doi(value):
    if not re.fullmatch(r'10\.5281/zenodo\.[1-9][0-9]+',value,re.I):
        raise argparse.ArgumentTypeError('Expected the assigned Zenodo version DOI, e.g. 10.5281/zenodo.<digits>')
    return value.lower()


def build(args):
    files={'README_ES.md':(HERE/'README_ES.md').read_bytes()}
    paper=json.loads((HERE/'metadata-paper.json').read_text())
    software=json.loads((HERE/'metadata-software.json').read_text())
    if args.paper_doi and args.paper_doi!=paper['doi']:
        raise ValueError('Supplied DOI differs from the published Zenodo record.')
    if not args.metadata_only:
        for lang,path in [('EN',args.paper_en),('ES',args.paper_es)]:
            add_edition(files,args.edition_dir,lang,path)
        for public in paper['published_files']:
            local=files['paper/files/'+public['local_filename']]
            if sha(local)!=public['sha256'] or len(local)!=public['bytes']:
                raise ValueError('Local PDF differs from published Zenodo file '+public['public_filename'])
    files['paper/metadata.json']=json_bytes(paper)
    files['reference/software.json']=json_bytes(software)
    files['MANIFEST.json']=json_bytes({
        'status':'published','version':'1.1','publication_date':paper['publication_date'],
        'publication_record':paper['public_record_url'],'doi':paper['doi'],
        'file_sets':{'paper':'metadata-only' if args.metadata_only else 'PDFs included',
                     'software':'public URL only'},
        'files':{name:{'bytes':len(data),'sha256':sha(data)} for name,data in sorted(files.items())}})
    return files


def write_zip(files,dest):
    dest.parent.mkdir(parents=True,exist_ok=True)
    with NamedTemporaryFile(dir=dest.parent,delete=False) as tmp:
        target=Path(tmp.name)
    try:
        with zipfile.ZipFile(target,'w') as z:
            for name,data in sorted(files.items()):
                info=zipfile.ZipInfo(name,date_time=(2026,11,21,0,0,0))
                info.create_system=3
                info.external_attr=0o100644<<16
                z.writestr(info,data,compress_type=zipfile.ZIP_DEFLATED,compresslevel=6)
        with zipfile.ZipFile(target) as z:
            if sorted(z.namelist())!=sorted(files) or z.testzip():
                raise ValueError('Verification archive failed verification.')
            for name,data in files.items():
                if z.read(name)!=data: raise ValueError(f'Verification content mismatch: {name}')
        os.replace(target,dest)
    finally:
        target.unlink(missing_ok=True)


def main():
    p=argparse.ArgumentParser(description=__doc__)
    p.add_argument('--edition-dir',type=Path,default=EDITION)
    p.add_argument('--paper-en',type=Path,help='integrated English PDF')
    p.add_argument('--paper-es',type=Path,help='integrated Spanish PDF')
    p.add_argument('--paper-doi',type=validate_doi,help='published version DOI')
    p.add_argument('--metadata-only',action='store_true',help='build a separate metadata-only verification copy')
    p.add_argument('--out',type=Path,help='output destination for the local verification ZIP')
    args=p.parse_args()
    dest=args.out or HERE/('zenodo-metadata-1.1.zip' if args.metadata_only else 'zenodo-deposit-1.1.zip')
    files=build(args)
    write_zip(files,dest)
    print(f'{dest} ({len(files)} entries) SHA-256 {sha(dest.read_bytes())}')


if __name__=='__main__':
    main()
