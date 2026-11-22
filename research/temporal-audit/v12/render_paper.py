"""Build both reading editions from their Markdown. Requires ReportLab and Linux Noto/Open Sans fonts."""
import argparse
import html
import os
import re
from pathlib import Path

from reportlab.lib import colors
from reportlab.lib.enums import TA_CENTER, TA_LEFT
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen import canvas
from reportlab.platypus import Paragraph, Table, TableStyle

ROOT = Path(__file__).resolve().parent
WIDTH, HEIGHT = 460, 646
MARGIN, CONTENT = 35, WIDTH - 70
INK = colors.HexColor("#182d27")
MUTED = colors.HexColor("#41554c")
GREEN = colors.HexColor("#245b49")
PAPER = colors.HexColor("#fbfaf7")
HAIR = colors.HexColor("#b9c5b9")
FONT_DIR = Path("/usr/share/fonts/truetype")


def fonts():
    family = {
        "Body": "open-sans/OpenSans-Regular.ttf",
        "BodyBold": "open-sans/OpenSans-Semibold.ttf",
        "BodyItalic": "open-sans/OpenSans-Italic.ttf",
        "Title": "noto/NotoSerifDisplay-Regular.ttf",
        "Mono": "dejavu/DejaVuSansMono.ttf",
    }
    for name, path in family.items():
        pdfmetrics.registerFont(TTFont(name, FONT_DIR / path))
    pdfmetrics.registerFontFamily("Body", normal="Body", bold="BodyBold", italic="BodyItalic", boldItalic="BodyItalic")


def rich(line):
    line = html.escape(line, quote=False)
    line = re.sub(r"\[([^]]+)\]\((https://[^)\s]+)\)", r'<a href="\2" color="#245b49"><u>\1</u></a>', line)
    line = re.sub(r"\*\*(.+?)\*\*", r"<b>\1</b>", line)
    line = re.sub(r"\*(.+?)\*", r"<i>\1</i>", line)
    return re.sub(r"`([^`]+)`", r'<font name="Mono">\1</font>', line)


def block(kind, line, scale, align=TA_LEFT):
    styles = {
        "title": ("Title", 35, 40, INK), "heading": ("Title", 24.5, 29, INK),
        "subheading": ("BodyBold", 12.2, 16, GREEN), "author": ("Body", 12.4, 17, INK),
        "label": ("BodyBold", 10.2, 14, GREEN), "para": ("Body", 11.8, 16.9, INK),
        "link": ("Body", 9.6, 14, MUTED), "table_text": ("Body", 10.3, 14.2, INK),
        "table_num": ("Body", 9.7, 13.5, INK), "table_header": ("BodyBold", 9.7, 12.9, INK),
        "small_header": ("BodyBold", 9.2, 11.8, INK), "hash": ("Mono", 8, 11, MUTED),
    }
    font, size, leading, color = styles[kind]
    settings = ParagraphStyle(kind, fontName=font, fontSize=size*scale, leading=leading*scale,
                              textColor=color, alignment=align, splitLongWords=1, spaceBefore=0, spaceAfter=0)
    formatted = rich(line).replace("\n","<br/>")
    return Paragraph(formatted, settings)


def parse(page, first):
    items = []
    lines = iter(page.strip().splitlines())
    for line in lines:
        line = line.strip()
        if not line:
            continue
        if line.startswith("|"):
            table = [line]
            for more in lines:
                if not more.strip():
                    break
                table.append(more.strip())
            rows = [[cell.strip() for cell in row.strip("|").split("|")] for row in table]
            items.append(("table", [rows[0], *rows[2:]]))
        elif line.startswith("# "):
            items.append(("title", line[2:]))
        elif line.startswith("## "):
            items.append(("label" if first else "heading", line[3:]))
        elif line.startswith("### "):
            items.append(("subheading", line[4:]))
        elif line.startswith("**Rubén Abella"):
            items.append(("author", line + "\n" + next(lines).strip()))
        elif line.startswith("SHA-256 `"):
            items.append(("hash", line))
        elif line.startswith("["):
            items.append(("link", line))
        else:
            items.append(("para", line))
    return items


def make_table(rows, scale):
    n = len(rows[0])
    widths = {2: (.30,.70), 4: (.22,.27,.26,.25), 6: (.258,.149,.138,.149,.157,.149),
              7: (.224,.248,.078,.073,.092,.162,.123)}[n]
    wrapped = []
    for i, row in enumerate(rows):
        cells = []
        for j, cell in enumerate(row):
            numeric = n > 2 and j >= (2 if n == 7 else 1)
            if not i:
                kind = "small_header" if n >= 6 else "table_header"
            elif numeric or n == 7:
                kind = "table_num"
            else:
                kind = "table_text"
            cells.append(block(kind, cell, scale, TA_CENTER if numeric else TA_LEFT))
        wrapped.append(cells)
    pad = (4 if n >= 6 else 6)*scale
    horizontal = (2 if n >= 6 else 5)*scale
    table = Table(wrapped, colWidths=[CONTENT*w for w in widths], hAlign="LEFT")
    table.setStyle(TableStyle([
        ("VALIGN",(0,0),(-1,-1),"MIDDLE"), ("BACKGROUND",(0,0),(-1,0),colors.HexColor("#e4ece3")),
        ("LINEABOVE",(0,0),(-1,0),.8,GREEN), ("LINEBELOW",(0,0),(-1,0),.6,GREEN),
        ("LINEBELOW",(0,1),(-1,-1),.35,HAIR),
        ("LEFTPADDING",(0,0),(-1,-1),horizontal), ("RIGHTPADDING",(0,0),(-1,-1),horizontal),
        ("TOPPADDING",(0,0),(-1,-1),pad), ("BOTTOMPADDING",(0,0),(-1,-1),pad),
    ]))
    return table


def flow(items, scale):
    result = []
    gap = {"title":14, "heading":10, "subheading":5, "author":12, "label":4, "table":10, "para":9, "link":7, "hash":5}
    for kind, data in items:
        item = make_table(data,scale) if kind == "table" else block(kind,data,scale)
        width,height = item.wrap(CONTENT, HEIGHT)
        result.append((kind,item,height,gap[kind]*scale))
    return result


def draw_masthead(c, first, lang, page, total):
    if first:
        c.setFillColor(colors.HexColor("#f5f4ec"))
        c.rect(0,0,WIDTH,HEIGHT,fill=1,stroke=0)
    else:
        c.setFillColor(PAPER)
        c.rect(0,0,WIDTH,HEIGHT,fill=1,stroke=0)
    c.setStrokeColor(GREEN)
    c.setLineWidth(1)
    y = HEIGHT - 31
    c.line(MARGIN,y+5,MARGIN,y-4)
    c.line(MARGIN,y+5,MARGIN+4,y+5)
    c.line(MARGIN,y-4,MARGIN+4,y-4)
    c.line(MARGIN+17,y+5,MARGIN+17,y-4)
    c.line(MARGIN+17,y+5,MARGIN+13,y+5)
    c.line(MARGIN+17,y-4,MARGIN+13,y-4)
    c.setFillColor(GREEN)
    c.circle(MARGIN+8.5,y+.5,1.6,fill=1,stroke=0)
    c.setFont("BodyBold",10)
    c.drawString(MARGIN+25,y-3,"SPE Audit")
    c.setFont("Body",9)
    c.drawRightString(WIDTH-MARGIN,y-3, "Investigación  /  1.2" if lang=="ES" else "Research  /  1.2")
    c.setStrokeColor(HAIR)
    c.setLineWidth(.55)
    c.line(MARGIN,y-13,WIDTH-MARGIN,y-13)
    c.line(MARGIN,35,WIDTH-MARGIN,35)
    c.setFillColor(MUTED)
    c.setFont("Body",8.5)
    c.drawString(MARGIN,20,"Rubén Abella   ·   22.11.2026")
    c.drawRightString(WIDTH-MARGIN,20,f"{page} / {total}")


def render(directory, lang):
    md=(directory/f"PAPER_{lang}.md").read_text(encoding="utf-8")
    pages = md.split("<!-- page -->")
    target=directory/f"PAPER_{lang}.pdf"
    os.environ.setdefault("SOURCE_DATE_EPOCH", "1795305600")  # UTC date of this edition.
    c=canvas.Canvas(str(target),pagesize=(WIDTH,HEIGHT),pageCompression=1,invariant=1,lang=lang.lower())
    title=md.splitlines()[0][2:]
    c.setTitle(title)
    c.setAuthor("Rubén Abella · SPE Audit")
    c.setSubject("Research edition 1.2 · DOI 10.5281/zenodo.24447732")
    total=len(pages)
    for number, page in enumerate(pages,1):
        first=number==1
        items=parse(page, first)
        y=HEIGHT-68 if first else HEIGHT-63
        available=y-44
        scale=1.00
        while True:
            blocks=flow(items,scale)
            used=sum(h+g for _,_,h,g in blocks)-blocks[-1][3]
            if used <= available:
                break
            scale -= .015
            if scale < .84:
                raise ValueError(f"{lang} p.{number} needs editorial shortening; content height {used:.1f}")
        draw_masthead(c,first,lang,number,total)
        key=f"chapter-{number}"
        c.bookmarkPage(key)
        c.addOutlineEntry(items[0][1],key,level=0,closed=False)
        for kind, item, height, after in blocks:
            y-=height
            item.drawOn(c,MARGIN,y)
            y-=after
        print(f"{lang} page {number}: body {11.8*scale:.1f} pt; lower margin {y+blocks[-1][3]:.1f} pt")
        c.showPage()
    c.save()


if __name__ == "__main__":
    parser=argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--directory",type=Path,default=ROOT)
    opts=parser.parse_args()
    fonts()
    for language in ("ES","EN"):
        render(opts.directory,language)
