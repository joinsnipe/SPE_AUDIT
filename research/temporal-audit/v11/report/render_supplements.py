"""Build and verify the two SPE Audit 1.1 PDFs. Run python3 v11/report/render_supplements.py."""

import argparse
import hashlib
import importlib.util
import json
import os
from pathlib import Path
import re
import subprocess
import tempfile
import unicodedata
from urllib.parse import unquote, urljoin, urlsplit
from xml.sax.saxutils import escape

import pymupdf
from reportlab import rl_config
from reportlab.lib import colors
from reportlab.lib.utils import ImageReader
from reportlab.platypus import CondPageBreak, Image, KeepTogether, LongTable, PageBreak, Paragraph, Spacer, TableStyle
from reportlab.platypus.tableofcontents import TableOfContents


ROOT = Path(__file__).resolve().parents[2]
PUBLIC = 'https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/v11/'
INK = '#14181f'
BLUE = '#1838a6'
MUTED = '#424d61'
HAIRLINE = '#c7ceda'
PALE = '#f1f4f9'
VERSION = '1.1'
DOI = '10.5281/zenodo.24424024'


def load_renderer(base):
    path = base / 'render_paper.py'
    if not path.is_file():
        raise FileNotFoundError(f'Expected the published SPE Audit renderer at {path}. Supply --base-dir when staging.')
    spec = importlib.util.spec_from_file_location('spe_print_edition', path)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    module.register_fonts()
    module.REPO = PUBLIC
    module.INK, module.TEAL = INK, BLUE
    module.BODY.textColor = colors.HexColor(INK)
    for depth, style in module.HEAD.items():
        style.textColor = colors.HexColor(BLUE if depth > 2 else INK)
    module.CODE.backColor = colors.HexColor(PALE)
    module.QUOTE.borderColor = colors.HexColor(BLUE)
    return module


def nodes(document):
    if isinstance(document, dict):
        if 't' in document:
            yield document
        for value in document.values():
            yield from nodes(value)
    elif isinstance(document, list):
        for item in document:
            yield from nodes(item)


def normalized(text):
    return re.sub(r'[^\w]|_', '', unicodedata.normalize('NFKC', text).casefold())


def get_subtitle(tree, edition):
    value = tree.get('meta', {}).get('subtitle')
    if not value:
        return ''
    if value['t'] == 'MetaString':
        return value['c']
    if value['t'] == 'MetaInlines':
        return edition.plain(value['c'])
    raise ValueError('Use a single line for the optional YAML subtitle.')


def cover_text(canvas, text, x, top, width, size, font, color, edition, maximum=None):
    """Fit and draw a title or other cover line, returning its remaining vertical space."""
    while True:
        style = edition.style('Cover line', font, size, size * 1.15, textColor=colors.HexColor(color))
        paragraph = Paragraph(escape(text), style)
        _, height = paragraph.wrap(width, 800)
        if maximum is None or height <= maximum:
            paragraph.drawOn(canvas, x, top - height)
            return top - height
        if size <= 20:
            raise ValueError('The cover title is too long to fit.')
        size -= 1


def page_decoration(canvas, doc, edition):
    width, height = edition.A4
    margin = edition.M
    canvas.saveState()
    if doc.page == 1:
        canvas.drawImage(doc.logo, margin, height - 110, width=65, height=65, mask='auto')
        canvas.setFillColor(colors.HexColor(INK))
        canvas.setFont('BodyB', 24)
        canvas.drawString(margin + 78, height - 85, 'SPE Audit')
        canvas.setFillColor(colors.HexColor(BLUE))
        canvas.rect(margin, height - 166, width - 2 * margin, 2, fill=True, stroke=False)
        canvas.setFont('BodyB', 10)
        canvas.drawString(margin, height - 193, 'SUPLEMENTO CIENTÍFICO' if doc.es else 'RESEARCH SUPPLEMENT')
        canvas.drawRightString(width - margin, height - 193, f'{VERSION}  /  ES' if doc.es else f'{VERSION}  /  EN')
        bottom = cover_text(canvas, doc.title_text, margin, height - 260, edition.AREA,
                            40, 'BodyB', INK, edition, maximum=220)
        if doc.subtitle:
            cover_text(canvas, doc.subtitle, margin, bottom - 20, edition.AREA - 15,
                       16, 'Body', MUTED, edition, maximum=110)
        canvas.setStrokeColor(colors.HexColor(HAIRLINE))
        canvas.line(margin, 103, width - margin, 103)
        canvas.setFillColor(colors.HexColor(INK))
        canvas.setFont('BodyB', 11)
        canvas.drawString(margin, 78, 'Rubén Abella · SPE Audit')
        canvas.setFillColor(colors.HexColor(MUTED))
        canvas.setFont('Body', 10)
        canvas.drawString(margin, 56, '21 de noviembre de 2026' if doc.es else '21 November 2026')
        canvas.setFillColor(colors.HexColor(BLUE))
        label = 'DOI ' + DOI
        canvas.drawRightString(width - margin, 56, label)
        canvas.linkURL('https://doi.org/' + DOI, (width - margin - canvas.stringWidth(label, 'Body', 10), 53, width - margin, 67), thickness=0)
    else:
        canvas.setFillColor(colors.HexColor(INK))
        canvas.setFont('BodyB', 8)
        canvas.drawString(margin, height - 31, 'SPE AUDIT')
        canvas.setFillColor(colors.HexColor(MUTED))
        canvas.setFont('Body', 8)
        label = 'Suplemento científico' if doc.es else 'Research supplement'
        canvas.drawRightString(width - margin, height - 31, f'{label}  {VERSION}')
        canvas.setStrokeColor(colors.HexColor(HAIRLINE))
        canvas.line(margin, height - 42, width - margin, height - 42)
        canvas.line(margin, 39, width - margin, 39)
        canvas.setFont('Body', 8)
        canvas.drawString(margin, 24, 'SPE Audit · 2026')
        canvas.setFont('BodyB', 9)
        canvas.setFillColor(colors.HexColor(BLUE))
        canvas.drawRightString(width - margin, 24, str(doc.page))
    canvas.restoreState()


def make_render(tree, source_dir, edition):
    class SupplementRender(edition.Render):
        def __init__(self, tree):
            super().__init__(tree)
            self.cell_columns = {}

        def inline(self, values):
            result = []
            for value in values:
                if value['t'] == 'Str' and re.search('[←→↑↓]', value['c']):
                    result.append(re.sub(r'([←→↑↓])', r'<font name="Math">\1</font>', escape(value['c'])))
                else:
                    result.append(super().inline([value]))
            return ''.join(result)

        def flow(self, blocks, base=edition.BODY):
            result = []
            for block in blocks:
                # Pandoc GFM emits one Image in a paragraph for a standalone illustration.
                content = block.get('c')
                if block['t'] == 'Para' and len(content) == 1 and content[0]['t'] == 'Image':
                    _, caption, target = content[0]['c']
                    uri = urlsplit(target[0])
                    if uri.scheme or uri.netloc or not uri.path:
                        raise ValueError(f'Use a local PNG or JPEG for a print figure: {target[0]}')
                    path = source_dir / unquote(uri.path)
                    if path.suffix.lower() not in {'.png', '.jpg', '.jpeg'}:
                        raise ValueError(f'Unsupported print figure format: {path}')
                    width, height = ImageReader(str(path)).getSize()
                    scale = min(edition.AREA / width, 350 / height, 1.0)
                    figure = Image(str(path), width=width * scale, height=height * scale)
                    parts = [figure]
                    if caption:
                        parts.append(Paragraph(self.inline(caption), edition.style('Caption', 'BodyI', 9, 13)))
                    result.extend([KeepTogether(parts), Spacer(1, 7)])
                else:
                    if block['t'] == 'Para' and any(n['t'] == 'Image' for n in nodes(content)):
                        raise ValueError('Place each figure in its own paragraph so the image appears in print.')
                    result.extend(super().flow([block], base))
            return result

        def table(self, cells):
            flows = super().table(cells)
            for table in flows:
                if isinstance(table, LongTable):
                    first_body = table.repeatRows
                    table.wrap(edition.AREA, 10_000_000)
                    repeated_height = sum(table._rowHeights[:first_body])
                    frame_height = edition.H - 110
                    table.splitInRow = int(any(h > frame_height - repeated_height
                                               for h in table._rowHeights[first_body:]))
                    commands = [
                        ('ROWBACKGROUNDS', (0, first_body), (-1, -1), [colors.white, colors.HexColor(PALE)]),
                        ('LINEBELOW', (0, -1), (-1, -1), .55, colors.HexColor(HAIRLINE)),
                    ]
                    if first_body:
                        commands.append(('BACKGROUND', (0, 0), (-1, first_body - 1), colors.HexColor('#252e43')))
                    table.setStyle(TableStyle(commands))
                    # Record column bounds for the text audit of unusually tall cells.
                    # A repeated header or neighbouring cell can interrupt their PDF text order.
                    if table.splitInRow:
                        rows = list(cells[3][1])
                        for body in cells[4]:
                            rows.extend(body[2])
                            rows.extend(body[3])
                        rows.extend(cells[5][1])
                        left = edition.M
                        for col, width in enumerate(table._colWidths):
                            header_text = [edition.plain(block['c']) for row in rows[:first_body]
                                           for block in row[1][col][4] if block['t'] in ('Plain', 'Para')]
                            heading = normalized(' '.join(header_text))
                            bounds = (left, left + width, heading)
                            for row in rows[first_body:]:
                                for block in nodes(row[1][col][4]):
                                    if block['t'] in ('Plain', 'Para', 'CodeBlock'):
                                        self.cell_columns[id(block)] = bounds
                            left += width
            return flows

    return SupplementRender(tree)


def paginate_tables(flows, edition):
    # Reserving an entire long table with its heading can waste most of a page.
    # Reserve just enough space for the headings, repeated header and first row.
    output = []
    for i, flow in enumerate(flows):
        if i + 1 < len(flows) and hasattr(flow, 'heading_key') and isinstance(flows[i + 1], LongTable):
            table = flows[i + 1]
            _, heading_height = flow.wrap(edition.AREA, edition.H)
            table.wrap(edition.AREA, edition.H)
            rows = table._rowHeights[:table.repeatRows + 1]
            required = min(edition.H / 2, sum(rows) + heading_height + flow.getSpaceAfter() + 6)
            output.append(CondPageBreak(required))
            flow.keepWithNext = False
        output.append(flow)
    return output


def verify_pdf(pdf_path, tree, render, edition):
    with pymupdf.open(pdf_path) as pdf:
        if pdf.metadata.get('author') != 'Rubén Abella' or 'Rubén Abella' not in pdf[0].get_text():
            raise ValueError('The supplement must credit Rubén Abella on the cover and in PDF metadata.')
        expected_heads = [edition.plain(b['c'][2]) for b in tree['blocks'] if b['t'] == 'Header' and b is not render.first]
        outline = pdf.get_toc()
        if [entry[1] for entry in outline] != expected_heads:
            raise ValueError('PDF bookmarks differ from the source heading sequence.')
        if not pdf[0].get_images() or VERSION not in pdf[0].get_text():
            raise ValueError('Cover mark or edition identifier missing.')
        if normalized(render.title) not in normalized(pdf[0].get_text()):
            raise ValueError('The cover does not contain the complete source title.')
        urls, text = set(), []
        for page in pdf:
            for link in page.get_links():
                if link['kind'] == pymupdf.LINK_URI:
                    urls.add(link['uri'])
            body = page.get_text(clip=pymupdf.Rect(edition.M - 3, 46, edition.W - edition.M + 3, edition.H - 44))
            if not body.strip() or any(c in body for c in ('\ufffd', '\x00')):
                raise ValueError(f'Empty page or missing character on page {page.number + 1}.')
            if any(word[0] < edition.M - 2 or word[2] > edition.W - edition.M + 2 for word in page.get_text('words')):
                raise ValueError(f'Text exceeds the horizontal page margins on page {page.number + 1}.')
            text.append(body)
        if expected_heads and not pdf[1].get_links():
            raise ValueError('The table of contents has no clickable destinations.')
        corpus = normalized(' '.join(text))
        expected_urls = set()
        columns = {}
        for node in nodes(tree['blocks']):
            kind = node['t']
            if kind == 'Link' and not node['c'][2][0].startswith('#'):
                expected_urls.add(urljoin(PUBLIC, node['c'][2][0]))
            if kind == 'Link' and node['c'][2][0].startswith('#'):
                if unquote(node['c'][2][0][1:]) not in render.ids:
                    raise ValueError(f'Unknown internal source link: {node["c"][2][0]}')
            if kind not in ('Plain', 'Para', 'CodeBlock'):
                continue
            # Verify short successive excerpts in paragraphs and individual table cells.
            # Prefix/suffix checks across cells alone would miss omitted interior prose.
            raw = node['c'][1] if kind == 'CodeBlock' else edition.plain(node['c'])
            words = raw.split()
            for i in range(0, len(words), 12):
                part = normalized(edition.math_text(' '.join(words[i:i + 12])))
                if not part or part in corpus:
                    continue
                column = render.cell_columns.get(id(node))
                if column and column not in columns:
                    left, right, header = column
                    clip = pymupdf.Rect(left + 1, 46, right - 1, edition.H - 44)
                    columns[column] = ''.join(normalized(page.get_text(clip=clip)).removeprefix(header)
                                              for page in pdf)
                if not column or part not in columns[column]:
                    raise ValueError(f'Source text missing from PDF: {" ".join(words[i:i + 12])!r}')
        if expected_urls - urls:
            raise ValueError(f'PDF link targets missing: {sorted(expected_urls - urls)}')
        return len(pdf), len(outline), len(expected_urls)


def build(source, destination, edition, base):
    tree = json.loads(subprocess.check_output([
        'pandoc', '-f', 'gfm+tex_math_dollars+yaml_metadata_block', '-t', 'json', str(source)]))
    render = make_render(tree, source.parent, edition)
    es = source.stem.endswith('_ES')
    logo = base / 'assets' / 'logo.png'
    if not logo.is_file():
        raise FileNotFoundError(f'Expected published SPE Audit logo at {logo}')
    doc = edition.PaperDoc(destination, render.title, get_subtitle(tree, edition), es, ImageReader(str(logo)))
    doc.author = 'Rubén Abella'
    doc.creator = 'SPE Audit'
    doc.keywords = 'SPE Audit, DOI ' + DOI
    doc.pageTemplates[0].onPage = lambda canvas, document: page_decoration(canvas, document, edition)
    toc = TableOfContents()
    toc.dotsMinLevel = 0
    toc.levelStyles = [edition.style('Contents listing', 'Body', 10, 15,
                                      spaceBefore=5, spaceAfter=0, rightIndent=30)]
    content = [Spacer(1, 1), PageBreak(), Paragraph('Índice' if es else 'Contents', edition.HEAD[1]), toc, PageBreak()]
    content.extend(paginate_tables(render.flow(tree['blocks']), edition))
    doc.multiBuild(content)
    return verify_pdf(destination, tree, render, edition)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument('--base-dir', type=Path, default=ROOT, help='Directory with render_paper.py and assets/logo.png')
    parser.add_argument('--source-dir', type=Path, default=ROOT / 'v11', help='Directory with SUPPLEMENT_EN.md and SUPPLEMENT_ES.md')
    parser.add_argument('--output-dir', type=Path, help='Defaults to the manuscript directory')
    parser.add_argument('--language', choices=('both', 'EN', 'ES'), default='both')
    args = parser.parse_args()
    source_dir = args.source_dir.resolve()
    output_dir = (args.output_dir or source_dir).resolve()
    output_dir.mkdir(parents=True, exist_ok=True)
    edition = load_renderer(args.base_dir.resolve())
    rl_config.invariant = 1
    os.environ.setdefault('SOURCE_DATE_EPOCH', '1795219200')
    languages = ('EN', 'ES') if args.language == 'both' else (args.language,)
    with tempfile.TemporaryDirectory(prefix='.supplement-', dir=output_dir) as staging:
        results = []
        for language in languages:
            stem = 'SUPPLEMENT_' + language
            candidate = Path(staging, stem + '.pdf')
            stats = build(source_dir / (stem + '.md'), candidate, edition, args.base_dir.resolve())
            results.append((candidate, stats))
        for candidate, (pages, headings, links) in results:
            dest = output_dir / candidate.name
            digest = hashlib.sha256(candidate.read_bytes()).hexdigest()
            candidate.replace(dest)
            print(f'{dest.name}  {pages} pages  {headings} bookmarks  {links} unique source link targets  sha256={digest}')


if __name__ == '__main__':
    main()
