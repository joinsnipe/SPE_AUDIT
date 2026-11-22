"""Typeset the full SPE Audit volume in both languages from the repository originals.

From a checkout, run python research/temporal-audit/v121/build_volume.py.
Dependencies: Pandoc, ReportLab, PyMuPDF, Open Sans and DejaVu fonts.
"""
from collections import Counter
import csv
from dataclasses import dataclass
import hashlib
from io import BytesIO
import json
import os
from pathlib import Path
import subprocess
import sys
import tempfile
from xml.sax.saxutils import escape, quoteattr

import pymupdf as fitz
from reportlab import rl_config
from reportlab.lib.colors import HexColor, white
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase.pdfmetrics import stringWidth
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import CondPageBreak, LongTable, Paragraph, Spacer, TableStyle

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
sys.path.insert(0, str(BASE / 'v11/report'))
import build_full as previous
import render_supplements as original

DOI = '10.5281/zenodo.24448090'
URL = 'https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/'
DATA = URL + 'v12/candidate_events.csv'
BLUE = HexColor(original.BLUE)
INK = HexColor(original.INK)
MUTED = HexColor(original.MUTED)
LINE = HexColor(original.HAIRLINE)
WORDS = {
 'ES': dict(analysis='Qué cambió entre los 96, 16 y 48 casos', reader='Un lector semántico local reproducible', design='Diseño para una réplica externa', follow='Seguimiento científico de la edición 1.1', roll='Diseño de réplica y registro prospectivo', edition='EDICIÓN INTEGRADA 1.2.1', day='22 de noviembre de 2026', front='Portada del volumen', contents='Índice general', inside='Contenido del volumen', pages='Páginas', article='Estudio 1.2 · El ensayo con y sin fecha', historic='Edición integrada 1.1 · Facsímil completo', note='Nota científica posterior a la edición 1.1', catalogue='Catálogo de antecedentes 1.2', register='Registro prospectivo de sucesos', short=['Las 224 inferencias y la comparación de métodos.', 'Artículo original 1.0, suplemento 1.1, figuras e índices originales.', 'Lector local, 48 respuestas y 17 pasajes de terceros.', 'Las 116 referencias, agrupadas por su función.', '34 sucesos documentados para una evaluación futura.'], nav='Los rangos se refieren a las páginas de este PDF. Cada facsímil conserva su propia numeración y sus enlaces.', notehead='Nota editorial', catalogue_note='El apéndice bibliográfico de la edición original conserva la selección histórica. El catálogo 1.2 reorganiza los mismos 116 registros y expone qué fechas y fuentes se pudieron corroborar. La edición 1.2.1 reúne los materiales y mantiene los resultados de la 1.2.', act='Abrir índice general', paper='Estudio de investigación 1.2', original='Artículo de investigación 1.0', supplement='Suplemento de investigación 1.1', vol='Volumen integrado 1.2.1', groups=['Finanzas, empresas y comercio', 'Normas, tribunales y elecciones', 'Cultura, transporte y actividad pública'], prospect='Estos 34 sucesos se seleccionaron para diseñar una prueba futura. Se documentan 28 sucesos realizados, cinco cancelaciones y un aplazamiento. Ninguno tiene todavía respuestas evaluadas ni etiquetas de referencia. Las páginas fuente están en inglés (19), español (10), francés (4) y alemán (1). Algunos sucesos comparten una misma perturbación histórica.', target='La fecha identifica el hito nombrado en cada fila. El CSV conserva el tipo de fecha, la jurisdicción y las notas sobre fechas alternativas.', csv='Descargar el registro original (CSV)', protocol='Diseño del estudio siguiente', source='Fuente', state='Estado y fuente', event='Suceso', identifier='Identificador', date='Fecha', status={'occurred':'Realizado','cancelled':'Cancelado','postponed':'Aplazado'}, globalpage='páginas del PDF', indices='Los apartados del estudio 1.2', rights='Licencias y atribución'),
 'EN': dict(analysis='What changed across the 96, 16 and 48 cases', reader='A reproducible local semantic reader', design='Design for independent replication', follow='Scientific follow-up to edition 1.1', roll='Replication design and prospective register', edition='INTEGRATED EDITION 1.2.1', day='22 November 2026', front='Volume cover', contents='Global contents', inside='Contents of this volume', pages='Pages', article='Research paper 1.2 · Reading with and without the date', historic='Integrated edition 1.1 · Complete facsimile', note='Research note following edition 1.1', catalogue='Prior-art catalogue 1.2', register='Prospective event register', short=['The 224 inferences and the comparison of methods.', 'Original paper 1.0, supplement 1.1, figures and original contents.', 'A local reader, 48 responses and 17 third-party passages.', 'All 116 references, organised by their role in the study.', '34 documented events for a future evaluation.'], nav='Ranges refer to pages of this PDF. Each facsimile retains its printed page numbers and links.', notehead='Editorial note', catalogue_note='The original bibliographic appendix preserves the historical selection. The 1.2 catalogue reorganises those same 116 records and reports which dates and sources could be corroborated. Edition 1.2.1 brings the materials together and retains the results of 1.2.', act='Open the global contents', paper='Research paper 1.2', original='Research paper 1.0', supplement='Research supplement 1.1', vol='Integrated volume 1.2.1', groups=['Finance, companies and trade', 'Law, courts and elections', 'Culture, transport and public events'], prospect='These 34 events were selected for the design of a future evaluation. The register documents 28 completed events, five cancellations and one postponement. None has evaluated responses or reference labels. The source pages are in English (19), Spanish (10), French (4) and German (1). Some events share a historical shock.', target='The date identifies the milestone named in each row. The CSV retains date types, jurisdictions and notes on alternative dates.', csv='Download the original register (CSV)', protocol='Design of the next study', source='Source', state='Status and source', event='Event', identifier='Identifier', date='Date', status={'occurred':'Occurred','cancelled':'Cancelled','postponed':'Postponed'}, globalpage='PDF pages', indices='Sections of the 1.2 study', rights='Rights and attribution'),
}
GROUPS = [('article',['article']), ('historic',['historic']), ('follow',['note','analysis','reader']), ('catalogue',['catalogue']), ('roll',['design','register'])]


def group_parts(parts):
    by_key = {part.key:part for part in parts}
    return [(key,[by_key[p] for p in names]) for key,names in GROUPS]


def decoration(c, doc, e, lang, label, offset):
    w, h = e.A4
    c.saveState()
    c.setFillColor(INK); c.setFont('BodyB', 8); c.drawString(e.M, h-31, 'SPE AUDIT')
    c.setFillColor(MUTED); c.setFont('Body', 8); c.drawRightString(w-e.M, h-31, label)
    c.setStrokeColor(LINE); c.setLineWidth(.65); c.line(e.M, h-42, w-e.M, h-42); c.line(e.M, 39, w-e.M, 39)
    c.drawString(e.M, 24, 'Rubén Abella · SPE Audit  ·  2026')
    c.setFillColor(BLUE); c.setFont('BodyB',9); c.drawRightString(w-e.M, 24, str(offset + doc.page))
    c.restoreState()


def article_pdf(path, source, base_dir, heading, offset, lang, e):
    label = WORDS[lang]
    e.REPO = URL + base_dir.relative_to(BASE).as_posix() + '/'
    # The compact edition used abbreviated labels. Only the layout and headings change.
    if lang == 'ES':
        source = source.replace('| Ref. | Anual | Fechada | Sin | Con |','| Referencia | Regla anual | Regla con fecha | Modelo sin fecha | Modelo con fecha |')
        source = source.replace('«Sin» y «con» indican', '«Modelo sin fecha» y «Modelo con fecha» indican')
    else:
        source = source.replace('| Ref. | Year | Dated | Without | With |','| Reference | Year rule | Dated rule | Model without date | Model with date |')
        source = source.replace('“Without” and “with” refer', '“Model without date” and “model with date” refer')
    tree = json.loads(subprocess.check_output(['pandoc','-f','gfm+tex_math_dollars','-t','json'], input=source.encode()))
    layout = original.make_render(tree, base_dir, e)
    doc = e.PaperDoc(path, layout.title, label['article'], lang=='ES', None)
    doc.pageTemplates[0].onPage = lambda c, d: decoration(c,d,e,lang,heading,offset)
    flows = [Paragraph(layout.title, e.HEAD[1])]
    for block in tree['blocks']:
        elem = layout.flow([block])
        if block['t'] == 'Header' and block['c'][0] == 2:
            flows.append(CondPageBreak(117))
        if block['t'] == 'Table':
            # A complete header must fit its column without breaking any word.
            for tab in [x for x in elem if isinstance(x, LongTable)]:
                if len(tab._colWidths) == 7:
                    widths = [95,105,61,48,60,64,e.AREA-433]
                    tab._colWidths = widths; tab._argW = widths; tab._width_calculated_once = 0
                for width, cell in zip(tab._colWidths,tab._cellvalues[0]):
                    p=cell[0] if isinstance(cell,(tuple,list)) else cell
                    p.style = p.style.clone('Full table heading',splitLongWords=0)
                    for word in p.getPlainText().split():
                        if stringWidth(word,p.style.fontName,p.style.fontSize) > width-11.99:
                            raise ValueError(f'Header word exceeds width: {word} ({width:.1f} pt)')
        flows.extend(elem)
    doc.build(flows)
    return tree


def draw_par(c, text, e, x, top, width, font='Body', size=10, leading=15, color=MUTED):
    p=Paragraph(text,e.style('Volume copy',font,size,leading,textColor=color,spaceAfter=0,splitLongWords=0))
    _,height=p.wrap(width,1000); p.drawOn(c,x,top-height)
    return top-height


def link_text(c, label, url, x, y, font='BodyB', size=9):
    c.setFillColor(BLUE); c.setFont(font,size); c.drawString(x,y,label)
    tw=c.stringWidth(label,font,size); c.linkURL(url,(x,y-2,x+tw,y+size+2),thickness=0)
    return x+tw


def event_appendix(path, lang, e, offset):
    t=WORDS[lang]; w,h=e.A4; m=e.M
    with (BASE/'v12/candidate_events.csv').open(encoding='utf-8',newline='') as source:
        rows=list(csv.DictReader(source))
    if len(rows)!=34 or len({r['id'] for r in rows})!=34: raise ValueError('Unexpected event register')
    groups=[rows[:12],rows[12:24],rows[24:]]
    c=Canvas(str(path),pagesize=e.A4,invariant=1)
    for i,(group,name) in enumerate(zip(groups,t['groups'])):
        decoration(c,type('Sheet',(),{'page':i+1}),e,lang,t['register'],offset)
        c.bookmarkPage(f'g{i}'); c.addOutlineEntry(name,f'g{i}',0)
        y=draw_par(c,t['register'] if i==0 else name,e,m,h-62,e.AREA,'Display',22,27,INK)-8
        if i==0:
            y=draw_par(c,t['prospect'],e,m,y,e.AREA)-5
            y=draw_par(c,t['target'],e,m,y,e.AREA)-9
            y=draw_par(c,name,e,m,y,e.AREA,'BodyB',13,17,BLUE)-8
        widths=[129,64,e.AREA-269,76]
        head=[t['identifier'],t['date'],t['event'],t['state']]
        styleh=e.CELLH.clone('Register columns',splitLongWords=0)
        cells=[[Paragraph(escape(v),styleh) for v in head]]
        for row in group:
            code=row['id']; event=row['event_'+lang.lower()]; date=row['target_date']
            anchor=f'<a color="{original.BLUE}" href={quoteattr(row["official_url"])}><u>{t["source"]} · {row["language"].upper()}</u></a>'
            if stringWidth(code,'Body',8.25)>widths[0]-12: raise ValueError(f'Event identifier wraps: {code}')
            cells.append([Paragraph(escape(code),e.CELL),Paragraph(date,e.CELL),Paragraph(escape(event),e.CELL),Paragraph(t['status'][row['status']]+'<br/>'+anchor,e.CELL)])
        table=LongTable(cells,colWidths=widths,style=TableStyle([('BACKGROUND',(0,0),(-1,0),HexColor('#252e43')),('ROWBACKGROUNDS',(0,1),(-1,-1),[white,HexColor(original.PALE)]),('VALIGN',(0,0),(-1,-1),'MIDDLE'),('LINEBELOW',(0,-1),(-1,-1),.55,LINE),('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6),('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5)]))
        _,th=table.wrap(e.AREA,h); bottom=y-th
        if bottom<89: raise ValueError(f'{lang} register page {i+1} overflows: {bottom}')
        table.drawOn(c,m,bottom)
        end=link_text(c,t['csv'],DATA,m,bottom-22)
        link_text(c,t['protocol'],URL+'v12/NEXT_STUDY.md',end+18,bottom-22)
        c.showPage()
    c.save()


@dataclass
class Part:
    key: str
    src: fitz.Document
    first: int = 0
    last: int|None = None
    start: int = 0  # global, zero-based

    @property
    def count(self):
        return (len(self.src) if self.last is None else self.last+1)-self.first

    def outline(self):
        return [r for r in self.src.get_toc(False) if self.first<=r[2]-1<self.first+self.count]


def draw_front(path,parts,lang,e):
    t=WORDS[lang]; prev=previous.LANG[lang]; w,h=e.A4; m=e.M; targets=[[],[]]
    c=Canvas(str(path),pagesize=e.A4,invariant=1)
    # Same master and identity as the integrated 1.1 cover.
    c.drawImage(ImageReader(str(BASE/'assets/logo.png')),m,h-90,width=46,height=46,mask='auto')
    c.setFillColor(INK); c.setFont('BodyB',22); c.drawString(m+58,h-74,'SPE Audit')
    c.setFillColor(BLUE); c.setFont('BodyB',10); c.drawRightString(w-m,h-70,t['edition'])
    c.setStrokeColor(BLUE); c.setLineWidth(2); c.line(m,h-116,w-m,h-116)
    title_bottom=draw_par(c,escape(prev['title']),e,m,h-146,e.AREA,'BodyB',35,41,INK)
    y=title_bottom-25; c.setFillColor(INK); c.setFont('BodyB',13); c.drawString(m,y,'Rubén Abella')
    c.setFillColor(MUTED); c.setFont('Body',10); c.drawString(m,y-21,t['day'])
    doi='DOI '+DOI; link_text(c,doi,'https://doi.org/'+DOI,w-m-c.stringWidth(doi,'Body',10),y-21,'Body',10)
    y=y-75; c.setFillColor(INK); c.setFont('BodyB',15); c.drawString(m,y,t['inside'])
    for j,(key,pieces) in enumerate(group_parts(parts)):
        part,end=pieces[0],pieces[-1]
        y-=48 if j==0 else 51
        c.setStrokeColor(LINE); c.setLineWidth(.65); c.line(m,y+18,w-m,y+18)
        c.setFillColor(BLUE); c.setFont('BodyB',12); c.drawString(m,y,t[key]); c.setFont('Body',10)
        span=f'{part.start+1}–{end.start+end.count}'; c.drawRightString(w-m,y,span)
        c.setFillColor(MUTED); c.drawString(m,y-15,t['short'][j]); targets[0].append((fitz.Rect(m,h-y-15,w-m,h-y+18),part.start))
    y-=49; c.setFillColor(BLUE); c.setFont('BodyB',10); c.drawString(m,y,t['act'])
    targets[0].append((fitz.Rect(m,h-y-11,m+190,h-y+4),1))
    y-=20; y=draw_par(c,t['nav'],e,m,y,e.AREA,'Body',9,13)-12
    y=draw_par(c,prev['rights'],e,m,y,e.AREA,'Body',8.65,12)-17
    if y<37: raise ValueError(f'{lang} cover overflow: {y}')
    end=link_text(c,'CC BY 4.0',previous.CC,m,y);link_text(c,prev['soft'],previous.CODE,end+25,y)
    c.showPage()
    decoration(c,type('Sheet',(),{'page':2}),e,lang,t['vol'],0)
    y=draw_par(c,t['contents'],e,m,h-64,e.AREA,'Display',22,27,INK)-7
    y=draw_par(c,t['nav'],e,m,y,e.AREA)-10
    def toc_line(name,num,depth=0):
        nonlocal y
        font='Body' if depth else 'BodyB';size=9.55 if depth else 11.35
        if not depth:
            y-=7; c.setStrokeColor(LINE); c.setLineWidth(.55); c.line(m,y+3,w-m,y+3)
        y-=13 if depth else 15
        c.setFillColor(MUTED if depth else BLUE);c.setFont(font,size); x=m+(12 if depth else 0)
        if c.stringWidth(name,font,size)>w-2*m-62:raise ValueError(f'Contents label too long: {name}')
        c.drawString(x,y,name); c.drawRightString(w-m,y,str(num[0]+1) if depth else f'{num[0]+1}–{num[1]}');targets[1].append((fitz.Rect(x,h-y-10,w-m,h-y+3),num[0]))
        y-=2
    for part in parts:
        toc_line(t[part.key],(part.start,part.start+part.count))
        for depth,name,local,details in part.outline():
            if depth!=1: continue
            if part.key=='historic' and local==1:continue
            if part.key not in ('article','historic','register'):continue
            toc_line(name,(part.start+local-1-part.first,None),1)
    y-=22; y=draw_par(c,t['notehead'],e,m,y,e.AREA,'BodyB',11,15,INK)-2
    y=draw_par(c,t['catalogue_note'],e,m,y,e.AREA,'Body',9.5,14)
    if y<48:raise ValueError(f'{lang} index overflow: {y}')
    c.showPage();c.save();return targets


def next_design(lang):
    source=(BASE/'v12/NEXT_STUDY.md').read_text(encoding='utf-8')
    spanish,english=source.split('## English\n',1)
    if lang=='EN': return '# '+WORDS[lang]['design']+'\n\n'+english
    fields='''## Campos del CSV

| Campo | Significado |
|---|---|
| id, domain, jurisdiction | Identificador del registro, dominio y jurisdicción o sede. |
| language | Idioma de la página oficial enlazada. |
| status | Categoría documentada del hito propuesto: realizado, cancelado o aplazado. |
| event_es, event_en | Hito concreto en español e inglés. |
| target_date, date_kind | Fecha de calendario en formato ISO y operación a la que corresponde. |
| official_url | Fuente de la institución responsable del registro. |
| secondary_date_note | Distinciones entre hitos, como anuncio y entrada en vigor, y límites pertinentes. |
'''
    return '# '+WORDS[lang]['design']+'\n\n'+spanish.split('## Español\n',1)[1]+'\n'+fields


def count_pdf(path):
    with fitz.open(path) as doc:
        return len(doc)


def prepare_parts(lang, dest, e):
    t=WORDS[lang]; offset=2; parts=[]
    def add(key,path,first=0,last=None):
        nonlocal offset
        part=Part(key,fitz.open(path),first,last,offset);parts.append(part);offset+=part.count
    def typeset(key,filepath,content=None):
        source=filepath.read_text(encoding='utf-8') if content is None else content
        pdf=dest/f'{key}_{lang}.pdf'
        article_pdf(pdf,source,filepath.parent,t[key],offset,lang,e);add(key,pdf)
    typeset('article',BASE/'v12'/f'PAPER_{lang}.md')
    add('historic',BASE/'v11'/f'FULL_{lang}.pdf')
    first=0 if lang=='ES' else 3
    add('note',BASE/'post11/brief/BRIEF_ES_EN.pdf',first,first+2)
    typeset('analysis',BASE/'post11/generalization'/f'analysis_{lang.lower()}.md')
    typeset('reader',BASE/'post11/reference_reader'/f'reader_{lang.lower()}.md')
    add('catalogue',BASE/'v12/Prior_art_catalogue.pdf')
    typeset('design',BASE/'v12/NEXT_STUDY.md',next_design(lang))
    appendix=dest/f'events_{lang}.pdf'; event_appendix(appendix,lang,e,offset);add('register',appendix)
    return parts


def shifted_outline(part):
    rows=[];shift=part.start-part.first
    for depth,title,page,detail in part.outline():
        if detail['kind']==fitz.LINK_GOTO:
            shifted={k:v for k,v in detail.items() if k!='xref'}
            shifted['page']+=shift
        elif detail['kind']==fitz.LINK_NAMED and detail.get('view')=='Fit' and int(detail['page'])==page:
            shifted={'kind':fitz.LINK_GOTO,'page':page+shift-1,'to':fitz.Point(0,0),'zoom':0,'source_fit':True}
        else:
            raise ValueError('Unsupported bookmark in source')
        rows.append([depth+1,title,page+shift,shifted])
    return rows


def compare_page(source, target, delta):
    if source.rect!=target.rect or source.get_text()!=target.get_text():
        raise ValueError(f'Facsimile page text or geometry mismatch: {source.number+1}')
    # A pixel comparison verifies figures, layout, fonts and colour as well as text.
    if source.get_pixmap(alpha=False).digest!=target.get_pixmap(alpha=False).digest:
        raise ValueError(f'Facsimile page image mismatch: {source.number+1}')
    def sig(link,offset):
        if link['kind']==fitz.LINK_NAMED and link.get('view')=='Fit':
            return 'page-fit',tuple(round(v,1) for v in link['from']),int(link['page'])+offset
        return previous.link_signature(link,offset)
    if Counter(sig(link,delta) for link in source.get_links())!=Counter(sig(link,0) for link in target.get_links()):
        raise ValueError(f'Page link changed: {source.number+1}')


def inspect(result,parts,targets,outline,lang):
    assert result.metadata['author']=='Rubén Abella' and DOI in result.metadata['subject']
    assert DOI in result.get_xml_metadata() and result[0].get_images()
    assert len(result)==2+sum(p.count for p in parts)
    actual=result.get_toc(False)
    assert [row[:3] for row in actual]==[row[:3] for row in outline]
    for wanted,got in zip(outline,actual):
        if len(wanted)==4:
            a,b=wanted[3],got[3]
            if a.get('source_fit'):
                assert b.get('view')=='Fit' and int(b['page'])==a['page']+1
            else:
                assert a['kind']==b['kind']==fitz.LINK_GOTO and a['page']==b['page']
                assert abs(a['to']-b['to'])<=.05
    for part in parts:
        for i in range(part.count):
            compare_page(part.src[part.first+i],result[part.start+i],part.start-part.first)
    for pg,items in enumerate(targets):
        dest=[l['page'] for l in result[pg].get_links() if l['kind']==fitz.LINK_GOTO]
        assert Counter(dest)==Counter(d for _,d in items)
    docs=''.join(page.get_text() for page in result)
    assert not any(ch in docs for ch in ('\ufffd','\x00'))
    # The former 9-page edition could split the date-rule header. Check complete words in the actual PDF.
    article=parts[0];headers=['Referencia','Regla','Modelo','fecha'] if lang=='ES' else ['Reference','Year','Dated','Model','without']
    example=next(pg for pg in article.src if 'perseverance-04' in pg.get_text() and 'h16' in pg.get_text())
    collected={word[4] for word in example.get_text('words')}
    assert all(token in collected for token in headers),collected
    assert not any(token=='Fechad' for token in collected)
    with (BASE/'v12/candidate_events.csv').open(encoding='utf-8',newline='') as file: rows=list(csv.DictReader(file))
    reg=parts[-1]; reg_text=''.join(result[j].get_text() for j in range(reg.start,reg.start+reg.count))
    reg_links={link.get('uri') for j in range(reg.start,reg.start+reg.count) for link in result[j].get_links()}
    assert all(row['id'] in reg_text and row['official_url'] in reg_links for row in rows)
    for page in result:
        if any(l['kind']==fitz.LINK_GOTO and not 0<=l['page']<len(result) for l in page.get_links()):
            raise ValueError(f'Unresolved internal link on page {page.number+1}')
    for part in parts:
        if part.key in ('article','analysis','reader','design','register'):
            for pg in part.src:
                if any(word[0]<45 or word[2]>551 for word in pg.get_text('words')):
                    raise ValueError(f'Text outside A4 margins, {lang} {part.key} {pg.number+1}')
    for pg in [result[1],*(p for p in result if p.get_text().splitlines()[4:5] in (['Índice'],['Contents']))]:
        if any(128<=ord(c)<=159 for c in pg.get_text()):raise ValueError('Control symbols in contents')


def set_fit(doc,xref,page_number):
    doc.xref_set_key(xref,'A','null')
    doc.xref_set_key(xref,'Dest',f'[{doc.page_xref(page_number)} 0 R /Fit]')


def build(lang,work,e):
    t=WORDS[lang];parts=prepare_parts(lang,work,e)
    try:
        front=work/f'front_{lang}.pdf'; targets=draw_front(front,parts,lang,e)
        outpath=work/f'FULL_{lang}.pdf'
        with fitz.open() as result:
            with fitz.open(front) as src: result.insert_pdf(src)
            outline=[[1,t['front'],1],[1,t['contents'],2]]
            for part in parts:
                result.insert_pdf(part.src,from_page=part.first,to_page=part.first+part.count-1,links=True,annots=True)
                outline.append([1,t[part.key],part.start+1]);outline.extend(shifted_outline(part))
            result.set_toc(outline,collapse=1)
            # PyMuPDF omits full-page /Fit links on insertion. Recreate the exact
            # destination mode, page and hit area in the joined PDF.
            for part in parts:
                for i in range(part.count):
                    pg=result[part.start+i]
                    for link in part.src[part.first+i].get_links():
                        if link['kind']!=fitz.LINK_NAMED:continue
                        assert link['view']=='Fit'
                        dest=int(link['page'])-1+part.start-part.first
                        before=set(x[0] for x in pg.annot_xrefs()); pg.insert_link({'kind':fitz.LINK_GOTO,'from':link['from'],'page':dest,'to':fitz.Point(0,0)})
                        new_xref,=set(x[0] for x in pg.annot_xrefs())-before
                        set_fit(result,new_xref,dest)
            for supplied,added in zip(outline,result.get_toc(False)):
                if len(supplied)==4 and supplied[3].get('source_fit'):
                    set_fit(result,added[3]['xref'],supplied[2]-1)
            for pg,items in enumerate(targets):
                for rect,dest in items:
                    result[pg].insert_link({'kind':fitz.LINK_GOTO,'from':rect,'page':dest,'to':fitz.Point(0,0)})
            result.set_page_labels([{'startpage':0,'prefix':'','style':'D','firstpagenum':1}])
            title=previous.LANG[lang]['title']+' · '+t['edition'].capitalize(); date='D:20261122000000Z'
            result.set_metadata(dict(title=title,author='Rubén Abella',subject=t['vol']+' · DOI '+DOI,creator='SPE Audit',producer='PyMuPDF',keywords='SPE Audit, DOI '+DOI,creationDate=date,modDate=date))
            xml=previous.xml_metadata(lang,title,previous.LANG[lang]['rights']).replace(previous.DOI,DOI).replace('2026-11-21','2026-11-22')
            result.set_xml_metadata(xml);result.xref_set_key(result.pdf_catalog(),'Lang','('+lang.lower()+')')
            result.save(outpath,garbage=3,deflate=True,no_new_id=True)
        with fitz.open(outpath) as result:
            inspect(result,parts,targets,outline,lang)
            print(f'{lang}: {len(result)} A4 pages, {len(outline)} bookmarks, {sum(len(pg.get_links()) for pg in result)} links, SHA-256 {hashlib.sha256(outpath.read_bytes()).hexdigest()}',flush=True)
            print('; '.join(f'{p.key} {p.start+1}–{p.start+p.count}' for p in parts),flush=True)
        return outpath
    finally:
        for part in parts:part.src.close()


if __name__=='__main__':
    os.environ.setdefault('SOURCE_DATE_EPOCH','1795305600');rl_config.invariant=1
    ed=original.load_renderer(BASE)
    with tempfile.TemporaryDirectory(prefix='spe-complete-edition-') as tmp:
        work=Path(tmp); files=[build(l,work,ed) for l in ('ES','EN')]
        for pdf in files:pdf.replace(HERE/pdf.name)
