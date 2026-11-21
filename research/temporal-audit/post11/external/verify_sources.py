"""Check attribution, case joins, exact text locators and optionally local primary-source HTML."""
import argparse
import hashlib
import json
from collections import Counter
from datetime import date
from html.parser import HTMLParser
from pathlib import Path
from urllib.parse import unquote

HERE = Path(__file__).resolve().parent


class Blocks(HTMLParser):
    """Preserve inline text inside headings, paragraphs and list items."""
    tags = {'h1', 'h2', 'h3', 'p', 'li'}

    def __init__(self):
        super().__init__(convert_charrefs=True)
        self.open_blocks = []
        self.complete = []
        self.text = []

    def handle_starttag(self, tag, attrs):
        if tag in self.tags:
            self.open_blocks.append((tag, []))

    def handle_data(self, data):
        self.text.append(data)
        for _, parts in self.open_blocks:
            parts.append(data)

    def handle_endtag(self, tag):
        for i in range(len(self.open_blocks)-1,-1,-1):
            if self.open_blocks[i][0] == tag:
                elem, parts = self.open_blocks.pop(i)
                self.complete.append((elem,' '.join(''.join(parts).split())))
                return


def read(name):
    return json.loads((HERE/name).read_text())


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--html',type=Path,help='Optional directory containing ID.html public source pages.')
    args = parser.parse_args()
    cases = {r['id']:r for r in read('cases.json')}
    events = {r['id']:r for r in read('events.json')}
    refs = {r['event_id']:r for r in read('event_sources.json')}
    sources = read('source_index.json')
    if set(refs) != set(events) or len(sources) != len(cases) or {s['id'] for s in sources} != cases.keys():
        raise ValueError('Incomplete provenance joins')
    source_urls = {s['url'] for s in sources}
    if len(source_urls) != len(sources) or source_urls & {r['url'] for r in refs.values()}:
        raise ValueError('Repeated sample page or reused event reference')
    verified = []
    for item in sources:
        case = cases[item['id']]
        ref = refs[case['event_id']]
        event = events[case['event_id']]
        words = len(case['text'].split())
        delta = abs((date.fromisoformat(case['cutoff'])-date.fromisoformat(event['event_date'])).days)
        valid = (words == item['words'] and 0 < words <= 18 and case['language'] == 'en'
                 and item['rights_policy'] in ('NIST','USGS') and bool(item['publisher'])
                 and bool(date.fromisoformat(item['public_date'])) and delta == 1
                 and bool(date.fromisoformat(ref['displayed_publication_date']))
                 and str(event['event_date']) == ref['event_date'] and ref['url'] == event['source_url']
                 and unquote(item['text_fragment'].split('#:~:text=',1)[1]) == case['text'])
        if not valid:
            raise ValueError(f'Invalid source inventory: {item["id"]}')
        if args.html:
            path = args.html/(item['id']+'.html')
            if not path.exists():
                continue
            parsed = Blocks()
            parsed.feed(path.read_text(encoding='utf-8-sig'))
            if 'block_sha256' in item:
                block_matches = any(tag == item['block_element'] and case['text'] in text and
                                    hashlib.sha256(text.encode()).hexdigest() == item['block_sha256']
                                    for tag,text in parsed.complete)
            else:
                block_matches = case['text'] in ' '.join(' '.join(parsed.text).split())
            if not block_matches:
                raise ValueError(f'Primary page differs: {item["id"]}')
            verified.append(item['id'])
    print(f'{len(sources)} case/source pairs, {len(refs)} distinct event references, {sum(s["words"] for s in sources)} words')
    if args.html:
        if not verified:
            raise ValueError('No matching ID.html files supplied')
        print(f'{len(verified)}/{len(sources)} source HTML files supplied and checked')


if __name__=='__main__':
    main()
