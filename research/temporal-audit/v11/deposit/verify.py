"""Verify the local paper-delivery ZIP and, optionally, the two final manuscript PDFs."""
import argparse
import hashlib
import json
from pathlib import Path
import zipfile

HERE=Path(__file__).resolve().parent
PDFS=('FULL_EN.pdf','FULL_ES.pdf')
EXPECTED={'MANIFEST.json','README_ES.md','paper/metadata.json','reference/software.json',
          *('paper/files/'+n for n in PDFS)}


def verify(archive,edition=None):
    with zipfile.ZipFile(archive) as z:
        names=z.namelist()
        if len(names)!=len(EXPECTED) or set(names)!=EXPECTED or z.testzip():
            raise ValueError('Unexpected, duplicated or damaged delivery files.')
        meta=json.loads(z.read('paper/metadata.json'))
        if meta['creators']!=[{'type':'person','family_name':'Abella','given_names':'Rubén'}]:
            raise ValueError('Paper personal authorship differs from the authorized record.')
        if meta['doi']!='10.5281/zenodo.24424024' or meta['version']!='1.1':
            raise ValueError('Published DOI or documentary version differs.')
        if (meta.get('public_record_url')!='https://zenodo.org/records/24424024'
                or meta.get('publication_date')!='2026-11-21'):
            raise ValueError('Published date or record URL differs.')
        if meta['rights']['id']!='cc-by-4.0' or 'Trademarks' not in meta['rights']['scope']:
            raise ValueError('Paper rights differ from the approved scope.')
        software=json.loads(z.read('reference/software.json'))
        if software['rights']['spdx_family']!='BUSL-1.1':
            raise ValueError('Linked software rights differ from the repository.')
        files=json.loads(z.read('MANIFEST.json'))['files']
        if set(files)!=EXPECTED-{'MANIFEST.json'}:
            raise ValueError('Manifest membership differs from the delivery.')
        result={}
        for name,record in files.items():
            data=z.read(name)
            digest=hashlib.sha256(data).hexdigest()
            if record!={'bytes':len(data),'sha256':digest}:
                raise ValueError(f'Checksum or size mismatch: {name}')
            if name.startswith('paper/files/'):
                if not data.startswith(b'%PDF-') or b'%%EOF' not in data[-2048:]:
                    raise ValueError(f'Invalid PDF stream: {name}')
                if edition and (edition/Path(name).name).read_bytes()!=data:
                    raise ValueError(f'Archived file differs from final manuscript: {name}')
                result[Path(name).name]=digest
    public={r['local_filename']:r['sha256'] for r in meta['published_files']}
    if result!=public:
        raise ValueError('Local archive differs from the published PDF fingerprints.')
    return result


if __name__=='__main__':
    parser=argparse.ArgumentParser()
    parser.add_argument('archive',type=Path,nargs='?',default=HERE/'zenodo-deposit-1.1.zip')
    parser.add_argument('--edition-dir',type=Path,help='compare exact bytes against both final PDFs')
    args=parser.parse_args()
    print(json.dumps(verify(args.archive,args.edition_dir),indent=2))
