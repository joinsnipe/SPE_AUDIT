"""Assemble and verify the two complete, navigable editions from the published PDFs."""
import argparse
from collections import Counter
import hashlib
from io import BytesIO
from pathlib import Path
import tempfile
from xml.sax.saxutils import escape

import pymupdf as fitz
from reportlab.lib.colors import HexColor
from reportlab.pdfgen.canvas import Canvas
from reportlab.lib.utils import ImageReader
from reportlab.platypus import Paragraph

from render_supplements import BLUE, DOI, INK, MUTED, ROOT, load_renderer


AUTHOR = 'Rubén Abella'
CC = 'https://creativecommons.org/licenses/by/4.0/'
CODE = 'https://github.com/joinsnipe/SPE_AUDIT/blob/main/LICENSE'
LANG = {
    'ES': {'title':'Auditoría temporal de las respuestas de IA', 'edition':'EDICIÓN INTEGRADA 1.1',
           'day':'21 de noviembre de 2026', 'part':'Contenido del volumen','page':'Página',
           's':'Suplemento de investigación 1.1','p':'Artículo de investigación 1.0',
           's_short':'Evidencia, lenguas y decisiones de revisión.',
           'p_short':'Auditoría por petición, resultados y antecedentes técnicos.',
           'nav':'Los enlaces y marcadores permiten abrir cada parte. Sus índices conservan los folios impresos originales.',
           'rights':'© 2026 Rubén Abella. CC BY 4.0 se aplica únicamente al texto y las figuras originales. El código se rige por la Business Source License 1.1. Se excluyen las marcas, entre ellas el nombre y el logotipo SPE Audit. Los materiales de terceros conservan sus condiciones.',
           'soft':'Licencia del software', 'front':'Portada e índice del volumen'},
    'EN': {'title':'Temporal auditing of AI outputs','edition':'INTEGRATED EDITION 1.1',
           'day':'21 November 2026','part':'Contents of this volume','page':'Page',
           's':'Research supplement 1.1','p':'Research paper 1.0',
           's_short':'Evidence, languages and review decisions.',
           'p_short':'Request-level auditing, study results and prior art.',
           'nav':'Use the links and bookmarks to open either part. Each contents page retains the original printed folios.',
           'rights':'© 2026 Rubén Abella. CC BY 4.0 covers only original text and original figures. The code is governed by the Business Source License 1.1. Trademarks, including the SPE Audit name and logo, are excluded. Third-party materials retain their own terms.',
           'soft':'Software license','front':'Volume cover and contents'},
}


def front_page(labels, starts, edition, logo):
    data=BytesIO(); w,h=edition.A4; margin=edition.M
    c=Canvas(data,pagesize=edition.A4,invariant=1)
    c.drawImage(ImageReader(logo),margin,h-90,width=46,height=46,mask='auto')
    c.setFillColor(HexColor(INK));c.setFont('BodyB',22);c.drawString(margin+58,h-74,'SPE Audit')
    c.setFillColor(HexColor(BLUE));c.setFont('BodyB',10);c.drawRightString(w-margin,h-70,labels['edition'])
    c.setStrokeColor(HexColor(BLUE));c.setLineWidth(2);c.line(margin,h-116,w-margin,h-116)
    title=Paragraph(escape(labels['title']),edition.style('Volume title','BodyB',35,41,textColor=HexColor(INK)))
    _, th=title.wrap(edition.AREA,150);title.drawOn(c,margin,h-146-th)
    y=h-171-th;c.setFillColor(HexColor(INK));c.setFont('BodyB',13);c.drawString(margin,y,AUTHOR)
    c.setFont('Body',10);c.setFillColor(HexColor(MUTED));c.drawString(margin,y-21,labels['day'])
    c.setFont('Body',10);c.setFillColor(HexColor(BLUE));doi='DOI '+DOI;c.drawRightString(w-margin,y-21,doi)
    c.linkURL('https://doi.org/'+DOI,(w-margin-c.stringWidth(doi,'Body',10),y-24,w-margin,y-10),thickness=0)
    c.setFont('BodyB',15);c.setFillColor(HexColor(INK));c.drawString(margin,457,labels['part'])
    targets=[]
    for (text_key,detail_key),baseline,offset in zip([('s','s_short'),('p','p_short')],[400,321],starts):
        c.setStrokeColor(HexColor('#C7CEDA'));c.setLineWidth(.65);c.line(margin,baseline+24,w-margin,baseline+24)
        c.setFont('BodyB',15);c.setFillColor(HexColor(BLUE));c.drawString(margin,baseline,labels[text_key]);c.setFont('Body',10)
        c.drawRightString(w-margin,baseline,labels['page']+' '+str(offset+1));c.setFillColor(HexColor(MUTED));c.drawString(margin,baseline-20,labels[detail_key]);
        targets.append((fitz.Rect(margin,h-baseline-22,w-margin,h-baseline+25),offset))
    nav=Paragraph(escape(labels['nav']),edition.style('Navigation','Body',10,15,textColor=HexColor(MUTED)));_, nh=nav.wrap(edition.AREA,70);nav.drawOn(c,margin,261-nh)
    rights=Paragraph(escape(labels['rights']),edition.style('Usage rights','Body',9.6,14,textColor=HexColor(MUTED)));_, rh=rights.wrap(edition.AREA,100);rights.drawOn(c,margin,158-rh)
    c.setFont('BodyB',9.5);c.setFillColor(HexColor(BLUE)); x=margin
    for name,uri in [('CC BY 4.0',CC),(labels['soft'],CODE)]:
        tw=c.stringWidth(name,'BodyB',9.5);c.drawString(x,71,name);c.linkURL(uri,(x,69,x+tw,82),thickness=0);x+=tw+26
    c.showPage();c.save();return data.getvalue(),targets


def xml_metadata(lang, title, rights):
    return f'''<x:xmpmeta xmlns:x="adobe:ns:meta/"><rdf:RDF xmlns:rdf="http://www.w3.org/1999/02/22-rdf-syntax-ns#"><rdf:Description rdf:about="" xmlns:dc="http://purl.org/dc/elements/1.1/" xmlns:prism="http://prismstandard.org/namespaces/basic/2.0/" xmlns:xmp="http://ns.adobe.com/xap/1.0/" prism:doi="{DOI}" xmp:CreateDate="2026-11-21T00:00:00Z" xmp:ModifyDate="2026-11-21T00:00:00Z"><dc:title><rdf:Alt><rdf:li xml:lang="x-default">{escape(title)}</rdf:li></rdf:Alt></dc:title><dc:creator><rdf:Seq><rdf:li>{AUTHOR}</rdf:li></rdf:Seq></dc:creator><dc:identifier>https://doi.org/{DOI}</dc:identifier><dc:language><rdf:Bag><rdf:li>{lang.lower()}</rdf:li></rdf:Bag></dc:language><dc:rights><rdf:Alt><rdf:li xml:lang="x-default">{escape(rights)}</rdf:li></rdf:Alt></dc:rights></rdf:Description></rdf:RDF></x:xmpmeta>'''


def link_signature(link, offset=0):
    area=tuple(round(v,1) for v in link['from']); kind=link['kind']
    if kind==fitz.LINK_GOTO:
        return kind,area,link['page']+offset,tuple(round(v,1) for v in link['to'])
    if kind==fitz.LINK_URI: return kind,area,link['uri']
    raise ValueError(f'Unsupported source link type {kind}')


def merge(lang, source, base, output, edition):
    labels=LANG[lang]; paths=[source/f'SUPPLEMENT_{lang}.pdf',base/f'PAPER_{lang}.pdf']
    with fitz.open(paths[0]) as supplement,fitz.open(paths[1]) as paper,fitz.open() as full:
        components=[supplement,paper]; starts=[1,1+len(supplement)]
        for part in components:
            if part.metadata.get('author')!=AUTHOR: raise ValueError('Incorrect component author metadata')
        raw,targets=front_page(labels,starts,edition,str(base/'assets/logo.png'))
        with fitz.open(stream=raw,filetype='pdf') as intro:full.insert_pdf(intro)
        outline=[[1,labels['front'],1]]
        for component,start,key in zip(components,starts,('s','p')):
            full.insert_pdf(component,links=True,annots=True)
            outline.append([1,labels[key],start+1]);
            for depth,text,page,dest in component.get_toc(False):
                if dest['kind']!=fitz.LINK_GOTO:raise ValueError('Unexpected external bookmark')
                adjusted={k:v for k,v in dest.items() if k!='xref'};adjusted['page']+=start
                outline.append([depth+1,text,page+start,adjusted])
        full.set_toc(outline,collapse=1)
        for rect,dest in targets:full[0].insert_link({'kind':fitz.LINK_GOTO,'from':rect,'page':dest,'to':fitz.Point(0,0)})
        full.set_page_labels([{'startpage':0,'prefix':'','style':'D','firstpagenum':1}])
        title=labels['title']+' · '+labels['edition'].capitalize()
        full.set_metadata({'title':title,'author':AUTHOR,'subject':labels['s_short']+' '+labels['p_short']+' DOI '+DOI,
                           'keywords':'SPE Audit, DOI '+DOI,'creator':'SPE Audit','producer':'PyMuPDF',
                           'creationDate':'D:20261121000000Z','modDate':'D:20261121000000Z'})
        full.set_xml_metadata(xml_metadata(lang,title,labels['rights']));full.xref_set_key(full.pdf_catalog(),'Lang','('+lang.lower()+')')
        full.save(output,garbage=3,deflate=True,no_new_id=True)
        with fitz.open(output) as result:
            if len(result)!=1+sum(map(len,components)) or result.get_toc()!=[[e[0],e[1],e[2]] for e in outline]:
                raise ValueError('Incomplete volume or incorrectly nested index')
            for component,start in zip(components,starts):
                for idx,page in enumerate(component):
                    joined=result[start+idx]
                    if page.get_text()!=joined.get_text():raise ValueError(f'Page text changed: {lang} {start+idx+1}')
                    if Counter(link_signature(l,start) for l in page.get_links())!=Counter(link_signature(l) for l in joined.get_links()):
                        raise ValueError(f'Page link changed: {lang} {start+idx+1}')
            if result.metadata['author']!=AUTHOR or DOI not in result.metadata['subject'] or DOI not in result.get_xml_metadata():
                raise ValueError('Metadata does not match the publication')
            if {link['page'] for link in result[0].get_links() if link['kind']==fitz.LINK_GOTO}!=set(starts):raise ValueError('Volume navigation mismatch')
            if not {CC,CODE,'https://doi.org/'+DOI} <= {l.get('uri') for l in result[0].get_links()}:raise ValueError('Front-matter rights or DOI links missing')
            print(f'{output.name}: {len(result)} pages, {len(outline)} bookmarks, {sum(len(p.get_links()) for p in result)} links; SHA-256 {hashlib.sha256(output.read_bytes()).hexdigest()}')


def main():
    ap=argparse.ArgumentParser(description=__doc__); ap.add_argument('--base-dir',type=Path,default=ROOT);ap.add_argument('--source-dir',type=Path,default=ROOT/'v11');ap.add_argument('--output-dir',type=Path)
    args=ap.parse_args();base=args.base_dir.resolve();source=args.source_dir.resolve();dest=(args.output_dir or source).resolve();dest.mkdir(parents=True,exist_ok=True)
    edition=load_renderer(base)
    with tempfile.TemporaryDirectory(prefix='.integrated-',dir=dest) as tmp:
        for lang in ('EN','ES'):merge(lang,source,base,Path(tmp)/f'FULL_{lang}.pdf',edition)
        for lang in ('EN','ES'):(Path(tmp)/f'FULL_{lang}.pdf').replace(dest/f'FULL_{lang}.pdf')

if __name__=='__main__':
    main()
