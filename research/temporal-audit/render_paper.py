"""Build the bilingual SPE Audit print edition. Requires Pandoc and ReportLab.

Usage: python render_paper.py PAPER_EN.md PAPER_EN.pdf
On Debian, install fonts-open-sans and fonts-dejavu-core.
"""
import argparse
import html
import json
import math
import os
import re
import subprocess
from pathlib import Path
from xml.sax.saxutils import escape, quoteattr
from urllib.parse import urljoin

from reportlab import rl_config
from reportlab.lib import colors
from reportlab.lib.enums import TA_LEFT
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.lib.utils import ImageReader
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.platypus import (
    BaseDocTemplate, Frame, HRFlowable, LongTable,
    PageBreak, PageTemplate, Paragraph, Spacer, TableStyle,
)
from reportlab.platypus.tableofcontents import TableOfContents

W, H = A4
M = 47
AREA = W - 2 * M
INK = '#152322'
MUTED = '#425451'
TEAL = '#006958'
LIGHT = '#A4FFDF'
PAPER = '#FAFCFB'
REPO = 'https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/'
COLOR = colors.HexColor


def register_fonts():
    base = Path('/usr/share/fonts/truetype')
    family = base / 'open-sans'
    fallback = base / 'dejavu'
    for alias, fn, alt in [
        ('Body','Regular',''), ('BodyB','Bold','-Bold'),
        ('BodyI','Italic','-Oblique'), ('BodyBI','BoldItalic','-BoldOblique'),
    ]:
        path = family / f'OpenSans-{fn}.ttf'
        if not path.exists():
            path = fallback / f'DejaVuSans{alt}.ttf'
        pdfmetrics.registerFont(TTFont(alias, str(path)))
    pdfmetrics.registerFontFamily('Body', normal='Body', bold='BodyB', italic='BodyI', boldItalic='BodyBI')
    pdfmetrics.registerFont(TTFont('Display',str(fallback / 'DejaVuSerif.ttf')))
    pdfmetrics.registerFont(TTFont('Mono',str(fallback / 'DejaVuSansMono.ttf')))
    pdfmetrics.registerFontFamily('Mono', normal='Mono', bold='Mono', italic='Mono', boldItalic='Mono')
    pdfmetrics.registerFont(TTFont('Math',str(fallback / 'DejaVuSans.ttf')))


def style(name, font='Body', size=10, leading=15, **kwargs):
    defaults = dict(fontName=font, fontSize=size, leading=leading, textColor=COLOR(INK),
                    alignment=TA_LEFT, spaceAfter=7, splitLongWords=1, allowWidows=0, allowOrphans=0)
    defaults.update(kwargs)
    return ParagraphStyle(name, **defaults)


BODY = style('BodyText')
QUOTE = style('Quote','BodyI',10,15,leftIndent=17, borderColor=COLOR('#92CEBD'),
              borderPadding=5)
CELL = style('Cell','Body',8.25,11.3,spaceAfter=0,allowWidows=1,allowOrphans=1)
CELLH = style('Column','BodyB',8.25,11.3,spaceAfter=0,textColor=colors.white)
HEAD = {
    1: style('Major','Display',22,27,spaceBefore=13,spaceAfter=8,keepWithNext=True),
    2: style('Section','Display',20,25,spaceBefore=14,spaceAfter=8,keepWithNext=True),
    3: style('Detail','BodyB',13,17,spaceBefore=11,spaceAfter=5,keepWithNext=True),
    4: style('Minor','BodyB',10.5,14,spaceBefore=9,spaceAfter=4,keepWithNext=True,textColor=COLOR(TEAL)),
}
CODE = style('Code','Mono',8,11,backColor=COLOR('#EFF6F3'),leftIndent=6,spaceBefore=3,spaceAfter=6)


def plain(nodes):
    if isinstance(nodes, list):
        return ''.join(plain(n) for n in nodes)
    t, c = nodes['t'], nodes.get('c')
    if t == 'Str': return c
    if t in ('Space','SoftBreak','LineBreak'): return ' '
    if t in ('Code','Math','RawInline'): return c[1]
    if t in ('Link','Image','Span','Cite'): return plain(c[1])
    if t == 'Quoted': return '“' + plain(c[1]) + '”'
    if t == 'Note': return ''
    if isinstance(c, list): return plain(c)
    raise ValueError(f'Unexpected inline node {t}')


def math_text(text):
    for src, dst in {
        r'\delta':'δ',r'\Delta':'Δ',r'\leq':'≤',r'\geq':'≥',r'\le':'≤',r'\ge':'≥',
        r'\infty':'∞',r'\times':'×',r'\in':'∈',r'\to':'→',r'\cdot':'·',
        r'\left':'',r'\right':'',r'\,':' ',r'\;':' ',r'\%':'%',
    }.items():
        text = text.replace(src, dst)
    return re.sub(r'\\(?:mathrm|text|operatorname|mathbf)\{([^{}]+)\}',r'\1',text)


class PaperDoc(BaseDocTemplate):
    def __init__(self, path, title, subtitle, es, logo):
        super().__init__(str(path),pagesize=A4,title=title,author='SPE Audit · Capriciousecret S.L.',
                         creator='SPE Audit',subject=subtitle,
                         leftMargin=M,rightMargin=M,topMargin=57,bottomMargin=53)
        self.title_text, self.subtitle, self.es, self.logo = title, subtitle, es, logo
        frame = Frame(M,53,AREA,H-110,id='body',leftPadding=0,rightPadding=0,
                      topPadding=0,bottomPadding=0)
        self.addPageTemplates(PageTemplate(id='research',frames=frame,onPage=self.decorate))

    def beforeDocument(self):
        self.outline_level = -1

    def decorate(self,c,doc):
        c.saveState()
        if doc.page == 1:
            c.setFillColor(COLOR('#101714')); c.rect(0,0,W,H,fill=1,stroke=0)
            c.setFillColor(COLOR('#0B0D0C')); c.rect(0,H-259,W,259,fill=1,stroke=0)
            c.drawImage(self.logo,M-6,H-190,width=146,height=146,mask='auto')
            c.setFillColor(colors.white); c.setFont('BodyB',26)
            c.drawString(M+141,H-127,'SPE Audit')
            c.setFillColor(COLOR(LIGHT)); c.rect(M,H-260,48,2,fill=1,stroke=0)
            c.setFont('BodyB',10); c.drawString(M,H-294,'ESTUDIO ABIERTO' if self.es else 'OPEN RESEARCH PAPER')
            cover = Paragraph(escape(self.title_text),style('Cover','Display',42,53,
                              spaceAfter=0,textColor=colors.white))
            _, height = cover.wrap(AREA-8,350)
            cover.drawOn(c,M,H-345-height)
            sub = escape(self.subtitle)
            p = Paragraph(sub,style('CoverSub','Body',14,21,textColor=COLOR('#BBD4C9')))
            _, sh = p.wrap(AREA-30,120); p.drawOn(c,M,H-365-height-sh)
            c.setStrokeColor(COLOR('#466258')); c.line(M,107,W-M,107)
            c.setFillColor(colors.white); c.setFont('BodyB',11)
            c.drawString(M,80,'SPE Audit · Capriciousecret S.L.')
            c.setFont('Body',9); c.setFillColor(COLOR('#BBD4C9'))
            c.drawString(M,59,'21 de noviembre de 2026' if self.es else '21 November 2026')
            c.drawRightString(W-M,59,'EDICIÓN DE INVESTIGACIÓN 1.0  ·  ES' if self.es else 'RESEARCH EDITION 1.0  ·  EN')
        else:
            c.setFillColor(COLOR(PAPER)); c.rect(0,0,W,H,fill=1,stroke=0)
            c.setFont('BodyB',8); c.setFillColor(COLOR(TEAL))
            c.drawString(M,H-31,'SPE AUDIT')
            c.setFont('Body',8); c.setFillColor(COLOR(MUTED))
            c.drawRightString(W-M,H-31,self.title_text)
            c.setStrokeColor(COLOR('#C8DAD1')); c.line(M,H-42,W-M,H-42)
            c.line(M,39,W-M,39)
            c.drawString(M,24,'Capriciousecret S.L.  ·  2026')
            c.setFont('BodyB',8); c.drawRightString(W-M,24,str(doc.page))
        c.restoreState()

    def afterFlowable(self, f):
        if not hasattr(f, 'heading_key'): return
        label, key, depth = f.heading_label, f.heading_key, f.heading_depth
        self.canv.bookmarkHorizontalAbsolute(key, self.frame._y + f.height)
        outline = min(max(0, depth-2),self.outline_level+1)
        self.canv.addOutlineEntry(label,key,outline,closed=outline>=1)
        self.outline_level = outline
        if depth <= 2:
            self.notify('TOCEntry',(0,escape(label),self.page,key))


class Render:
    def __init__(self, doc):
        self.ids = {b['c'][1][0]: f's{n}' for n,b in enumerate(doc['blocks'])
                    if b['t']=='Header'}
        self.first = next(b for b in doc['blocks'] if b['t']=='Header' and b['c'][0]==1)
        self.title = plain(self.first['c'][2])

    def inline(self, nodes):
        def render(n):
            t, c = n['t'], n.get('c')
            if t=='Str': return escape(c)
            if t in ('Space','SoftBreak'): return ' '
            if t=='LineBreak': return '<br/>'
            if t=='Code': return '<font name="Mono">'+escape(c[1])+'</font>'
            if t=='Math': return '<font name="Math">'+escape(math_text(c[1]))+'</font>'
            if t in ('Strong','Emph','Strikeout','Underline','Superscript','Subscript','SmallCaps'):
                tag={'Strong':'b','Emph':'i','Strikeout':'strike','Underline':'u',
                     'Superscript':'super','Subscript':'sub','SmallCaps':'b'}[t]
                return f'<{tag}>'+self.inline(c)+f'</{tag}>'
            if t in ('Span','Cite'): return self.inline(c[1])
            if t=='Quoted': return '“'+self.inline(c[1])+'”'
            if t=='Link':
                href=c[2][0]; label=self.inline(c[1])
                if href.startswith('#'):
                    key=self.ids.get(href[1:])
                    if key is None: return label
                    href='#'+key
                else:
                    href=urljoin(REPO,href)
                return f'<a href={quoteattr(href)} color="{TEAL}"><u>{label}</u></a>'
            if t=='Image': return self.inline(c[1])
            if t=='Note':
                return ' ('+' '.join(self.block_text(b) for b in c)+')'
            if t=='RawInline':
                if c[0]=='html' and re.fullmatch(r'<br\s*/?>',c[1],re.I): return '<br/>'
                return escape(c[1])
            raise ValueError(f'Unexpected inline node {t}')
        return ''.join(render(n) for n in nodes)

    def block_text(self,b):
        t,c=b['t'],b.get('c')
        if t in ('Plain','Para'): return self.inline(c)
        if t=='Header': return self.inline(c[2])
        if t=='CodeBlock': return '<font name="Mono">'+escape(c[1]).replace('\n','<br/>')+'</font>'
        if t in ('BulletList','OrderedList'):
            items = c if t=='BulletList' else c[1]
            return '<br/>'.join('• '+' '.join(self.block_text(k) for k in item) for item in items)
        raise ValueError(f'Unexpected text block {t}')

    def table(self,c):
        _,caption,cols,header,bodies,footer=c
        rows=list(header[1]); heads=len(rows)
        for body in bodies: rows.extend(body[2]); rows.extend(body[3])
        rows.extend(footer[1])
        n=len(cols); content=[]; lengths=[[] for _ in cols]
        captions=[Paragraph(self.block_text(k),BODY) for k in caption[1]]
        for i, row in enumerate(rows):
            line=[]
            for j, cell in enumerate(row[1]):
                if cell[2:4] != [1,1]: raise ValueError('Merged cells need explicit print widths.')
                val='<br/>'.join(self.block_text(b) for b in cell[4])
                line.append(Paragraph(val,CELLH if i<heads else CELL))
                lengths[j].append(len(html.unescape(re.sub(r'<[^>]*>','',val))))
            if len(line)!=n: raise ValueError('Source table has missing cells.')
            content.append(line)
        if not content: return captions
        weights=[math.sqrt(max(8,min(180,.65*sum(x)/len(x)+.35*max(x)))) for x in lengths]
        floor=min(56,AREA/n*.65); space=AREA-n*floor
        widths=[floor+space*w/sum(weights) for w in weights]
        tbl=LongTable(content,colWidths=widths,repeatRows=heads,splitByRow=1,splitInRow=0,hAlign='LEFT')
        fmt=[('VALIGN',(0,0),(-1,-1),'TOP'),
             ('ROWBACKGROUNDS',(0,heads),(-1,-1),[colors.white,COLOR('#F0F5F2')]),
             ('LINEBELOW',(0,-1),(-1,-1),.55,COLOR('#BDCEC5')),
             ('TOPPADDING',(0,0),(-1,-1),5),('BOTTOMPADDING',(0,0),(-1,-1),5),
             ('LEFTPADDING',(0,0),(-1,-1),6),('RIGHTPADDING',(0,0),(-1,-1),6)]
        if heads: fmt.append(('BACKGROUND',(0,0),(-1,heads-1),COLOR('#1C4B41')))
        tbl.setStyle(TableStyle(fmt))
        return captions+[tbl,Spacer(1,9)]

    def flow(self,blocks,base=BODY):
        result=[]
        for b in blocks:
            t,c=b['t'],b.get('c')
            if b is self.first: continue
            if t=='Header':
                d,attr,nodes=c; p=Paragraph(self.inline(nodes),HEAD[min(4,d)])
                p.heading_depth=d; p.heading_key=self.ids[attr[0]]; p.heading_label=plain(nodes)
                result.append(p)
            elif t in ('Para','Plain'):
                para=Paragraph(self.inline(c),base)
                if c and c[0]['t']=='Strong' and re.match(r'^[BM]\d{2,3}\b',plain(c[0]['c'])):
                    para.keepWithNext=True
                result.append(para)
            elif t=='Table': result.extend(self.table(c))
            elif t=='HorizontalRule': result.append(HRFlowable(width='100%',color=COLOR('#B8D2C5'),spaceAfter=8))
            elif t=='BlockQuote': result.extend(self.flow(c,QUOTE))
            elif t=='CodeBlock':
                lines=c[1].split('\n')
                for line in lines:
                    result.append(Paragraph(escape(line).replace(' ','&#160;') or '&#160;',CODE))
            elif t in ('BulletList','OrderedList'):
                start,items=(0,c) if t=='BulletList' else (c[0][0],c[1])
                for idx,item in enumerate(items):
                    mark='•' if t=='BulletList' else f'{start+idx}.'
                    st=style('List','Body',10,15,leftIndent=19,firstLineIndent=-14)
                    if item and item[0]['t'] in ('Para','Plain'):
                        result.append(Paragraph(escape(mark)+'&#160; '+self.inline(item[0]['c']),st))
                        result.extend(self.flow(item[1:]))
                    else:
                        result.append(Paragraph(escape(mark),st)); result.extend(self.flow(item))
            elif t=='DefinitionList':
                for term, defs in c:
                    result.append(Paragraph('<b>'+self.inline(term)+'</b>',base))
                    for d in defs: result.extend(self.flow(d,base))
            elif t=='Div': result.extend(self.flow(c[1],base))
            elif t=='RawBlock':
                if c[0]=='html' and c[1].strip().startswith('<!--'): continue
                result.append(Paragraph(escape(c[1]),base))
            elif t=='Null': continue
            else: raise ValueError(f'Unexpected block node {t}')
        return result


def main():
    ap=argparse.ArgumentParser(description=__doc__)
    ap.add_argument('source',type=Path); ap.add_argument('output',type=Path); args=ap.parse_args()
    src=args.source.resolve(); dest=args.output.resolve()
    tree=json.loads(subprocess.check_output(['pandoc','-f','gfm+tex_math_dollars','-t','json',str(src)]))
    register_fonts(); rl_config.warnOnMissingFontGlyphs=1; rl_config.invariant=1
    # Pin the PDF metadata to this edition date for reproducible typesetting.
    os.environ.setdefault('SOURCE_DATE_EPOCH', '1795219200')
    render=Render(tree); es=src.stem.upper().endswith('_ES')
    potential=[src.parent/'assets/logo.png',Path(__file__).resolve().parent/'brand/spe.png']
    logo=next((p for p in potential if p.is_file()),None)
    if logo is None: raise FileNotFoundError('Expected assets/logo.png alongside the manuscript')
    dest.parent.mkdir(parents=True,exist_ok=True)
    front=tree['blocks']; first=front.index(render.first)
    subtitle=''; content=front
    if (len(front)>first+2 and front[first+1]['t']=='Para' and front[first+2]['t']=='Para'
            and 'Capriciousecret' in plain(front[first+2]['c'])):
        subtitle=plain(front[first+1]['c']); content=front[:first]+front[first+3:]
    out=PaperDoc(dest,render.title,subtitle,es,ImageReader(str(logo)))
    toc=TableOfContents(); toc.dotsMinLevel=0
    toc.levelStyles=[style('ContentsItem','Body',10,15,spaceBefore=5,spaceAfter=0,rightIndent=30)]
    story=[Spacer(1,1),PageBreak(),Paragraph('Índice' if es else 'Contents',HEAD[1]),toc,PageBreak()]
    story.extend(render.flow(content))
    out.multiBuild(story)
    print(f'{dest.name}: {out.page} pages, {len(render.ids)-1} section destinations')


if __name__ == '__main__':
    main()
