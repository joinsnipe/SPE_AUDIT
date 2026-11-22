"""Build the bilingual B-series catalogue with ReportLab from the published CSV files.

Run python catalogue.py from any directory. The original titles, reference IDs,
original type field and dates come from the editioned registers linked in the PDF.
"""
import csv
from collections import Counter
from dataclasses import dataclass
from pathlib import Path
from urllib.parse import urlsplit
from xml.sax.saxutils import escape

import reportlab
from reportlab.lib import colors
from reportlab.lib.pagesizes import A4
from reportlab.lib.styles import ParagraphStyle
from reportlab.pdfbase import pdfmetrics
from reportlab.pdfbase.ttfonts import TTFont
from reportlab.pdfgen.canvas import Canvas
from reportlab.platypus import Paragraph

HERE = Path(__file__).resolve().parent
BASE = HERE.parent
BASE_URL = ("https://github.com/joinsnipe/SPE_AUDIT/blob/"
            "c6126e42bc8cd0679ac3c5f5dca6270c0a1ccc6f/research/temporal-audit/")
BIB = "landscape/bibliography.csv"
SPANISH = "landscape/bibliography_notes_es.csv"
LEDGER = "v11/sources/dating_ledger.csv"
DOI = "10.5281/zenodo.24447732"

# Every literal category in the original 'kind' field is assigned once.
GROUPS = [
    ("Investigación y fuentes técnicas", "Research and technical sources",
     ("research", "patent publication", "standard", "software")),
    ("Proyectos y propuestas", "Projects and proposals",
     ("industry project", "project description", "self-published proposal")),
    ("Documentos públicos y actuaciones", "Public records and proceedings",
     ("legislation", "judicial opinion", "court pleading", "enforcement",
      "guidance", "government context")),
    ("Comentarios jurídicos", "Legal commentary",
     ("enforcement commentary", "regulatory commentary")),
    ("Mercado, administración y búsqueda", "Market, administration and discovery",
     ("market context", "administrative context", "discovery", "unresolved label")),
]
ROLE_ES = {
    "research": "Investigación", "patent publication": "Publicación de patente",
    "standard": "Norma", "software": "Software", "industry project": "Proyecto industrial",
    "project description": "Descripción de proyecto", "self-published proposal": "Propuesta de autor",
    "legislation": "Legislación", "judicial opinion": "Resolución judicial",
    "court pleading": "Escrito procesal", "enforcement": "Actuación de una autoridad",
    "guidance": "Guía", "government context": "Contexto institucional",
    "enforcement commentary": "Comentario sobre actuaciones",
    "regulatory commentary": "Comentario regulatorio", "market context": "Contexto comercial",
    "administrative context": "Contexto administrativo", "discovery": "Pista de búsqueda",
    "unresolved label": "Denominación histórica sin identificar en 1.0",
}
DATE_TYPES = {
    "publisher_date": "Fecha del editor / Publisher date",
    "archived_by": "Captura de archivo / Archived by",
    "registry_release": "Versión en registro / Registry release",
    "related_dated_edition": "Publicación relacionada / Related edition",
    "revision_only": "Revisión de la página / Page revision",
    "agency_posting": "Publicación institucional / Agency posting",
    "dated_edition": "Edición fechada / Dated edition",
    "unresolved": "Fecha pública pendiente / Public date unresolved",
}
PERIOD = {"before": "anterior / before", "after": "posterior / after", "unknown": "sin determinar / unknown"}

# Spanish editorial translations of the historical scope recorded for the 58 rechecks.
ARTICLE_DATE = "La fecha corresponde al artículo firmado. Para fechar cambios posteriores se necesita la versión correspondiente."
RECHECK_ES = {
    **dict.fromkeys("B007 B009 B014 B021 B022 B024 B025 B060 B063 B064 B072".split(), ARTICLE_DATE),
    "B006": "La captura identifica al autor. Los artículos añadidos después al perfil requieren su propia fecha.",
    "B008": "El editor fecha la modificación el 13 de mayo de 2026. Queda pendiente el cotejo con una captura del texto anterior.",
    "B010": "La fecha corresponde al anuncio del borrador de FINOS. Otra comunicación identifica la versión 1 en junio de 2025. La página fecha la versión 3 el 26 de octubre de 2026.",
    "B011": "La fecha corresponde a la entrada de Medium que expone la propuesta industrial. La implementación histórica del protocolo sigue sin comprobarse.",
    "B012": "La página indica cuándo se actualizó la explicación. El trabajo original sobre STAR-RAG tiene su propia fecha de envío en octubre. Se desconoce la primera publicación de esta página.",
    "B013": "Las diapositivas de BIMSA identifican a Alexey Zaytsev. Sus metadatos dan el 21 de abril de 2025 como fecha de creación o modificación. La fecha de difusión pública sigue abierta.",
    "B016": "La copia archivada confirma el índice. El commit del 14 de noviembre identifica el contenido de entonces. Las incorporaciones posteriores tienen otras fechas.",
    "B017": "La fuente fechada es la distribución 0.1.0 de UQLM. El repositorio y los componentes añadidos con posterioridad requieren otras versiones.",
    "B023": "El archivo confirma una versión posterior del índice. Cada artículo tiene su propia fecha. Se desconoce la primera aparición pública del índice.",
    "B026": "La página actual menciona 2026 y consigna una modificación el 28 de septiembre de 2026. El inventario de mayo citaba un título de 2025. Falta la versión vista entonces.",
    "B027": "Los metadatos indican una modificación el 29 de mayo de 2026. La redacción actual requiere una captura para atribuirla a una fecha anterior.",
    "B028": "El 15 de enero de 2026 que se ve en la página coincide con la revisión en los metadatos. La publicación inicial tiene otra fecha.",
    "B032": "La captura acredita que el proyecto tenía una presentación pública en esa fecha posterior al corte. Sigue abierta su disponibilidad en diciembre y el historial de versiones.",
    "B033": "Se localizó la página institucional actual del proyecto. Sigue sin identificarse una edición histórica fechada de esta misma página.",
    "B034": "La tienda identifica la versión 1.7.0 y la actualización del 18 de abril de 2026. Se desconoce la primera publicación de la extensión.",
    "B035": "El editor da una fecha de creación y una actualización el 9 de septiembre de 2026. Falta una copia de la lista anterior de productos.",
    "B036": "El editor consigna una actualización el 12 de noviembre de 2026. La clasificación de productos depende de la versión consultada.",
    "B037": "La página consigna una actualización el 27 de agosto de 2026. Comprobar las afirmaciones sobre rendimiento requiere pruebas del producto.",
    "B038": "La copia archivada sitúa una edición con este título en la fecha indicada. Las frases introducidas después requieren su propia comprobación.",
    "B039": "El título y el contenido son material editorial de BDO sobre finanzas públicas. El 4 de mayo corresponde al artículo.",
    "B040": "Los metadatos actuales sitúan una actualización el 15 de noviembre de 2026. Las descripciones concretas requieren una copia fechada del texto.",
    "B041": "Existía una versión de la comparativa de Levo en la fecha de la captura. Los rótulos de año y las prestaciones actuales exigen cotejo con aquella copia.",
    "B042": "La página también incluye metadatos del 3 de agosto. Ambas fechas son posteriores al inventario de mayo. Queda por identificar la edición entonces citada.",
    "B043": "Los metadatos del editor sitúan una actualización el 9 de mayo de 2026. Se trata de una fuente comercial.",
    "B044": "La página indica una revisión el 10 de junio de 2026. La fecha de publicación queda un día después de la consulta histórica registrada el 5 de mayo. Falta una versión coincidente.",
    "B045": "Los metadatos actuales indican una actualización el 15 de mayo de 2026. Sigue sin confirmarse qué texto de esta edición estaba disponible antes del corte.",
    "B046": "La página consigna una modificación el 12 de noviembre de 2026 en los metadatos del editor.",
    "B051": "La consulta devolvió una lista diaria cambiante. Para reconstruir los resultados de entonces hace falta una instantánea fechada.",
    "B053": "La captura acredita un perfil público posterior. La lista de resultados histórica y la primera fecha pública del perfil siguen pendientes.",
    "B054": "La captura identifica a la persona y la página consultada. La fecha de una obra citada y la primera aparición en el directorio requieren otras pruebas.",
    "B055": "El enlace de búsqueda registrado no devolvió una lista histórica. Se necesitan identificadores individuales para recuperar los artículos.",
    "B056": "La captura acredita una explicación publicada antes del corte. El texto jurídico actualizado necesita un cotejo con esa versión.",
    "B057": "El sitio consigna una actualización el 31 de agosto de 2026. Para comprobar la norma descrita hace falta consultar la versión oficial aplicable.",
    "B058": "La captura es posterior al corte. El reglamento original se publicó en 2024. Sigue abierta la primera publicación de esta reproducción de terceros.",
    "B059": "El sitio consigna una revisión el 18 de septiembre de 2025. El artículo comenta una norma sobre sistemas de gestión.",
    "B065": "El anuncio del Tesoro estadounidense fecha la serie. Atribuir una capacidad técnica concreta requiere documentación específica.",
    "B066": "La SEC fecha la incorporación al índice. La carta de un tercero lleva fecha de 5 de octubre de 2025 y expresa su posición. Su circulación pública anterior sigue abierta.",
    "B067": "El documento presupuestario trata el ejercicio 2027. La portada indica abril de 2026 como mes de emisión, sin precisar el día.",
    "B068": "La tabla vigente indica aplicación desde el 19 de enero de 2025 y revisión el 1 de noviembre de 2026. Falta la copia del PDF que circulaba en mayo.",
    "B069": "El PDF se capturó después del corte. La disposición final de noviembre de 2024 documenta el contexto regulatorio. Se desconoce la primera fecha pública de este archivo.",
    "B070": "El archivo devolvió un XLSX con el libro y las hojas. Acredita una versión anterior al corte y aporta contexto administrativo.",
    "B071": "También existe una captura del 5 de diciembre de 2025. La redacción anterior al corte sigue sin acreditarse con esa captura o la revisión posterior.",
    "B092": "La entrevista fechada recoge afirmaciones de la empresa sobre V-Proof. La descripción técnica actual del proveedor carece de fecha. Sigue abierta la verificación de una implementación anterior.",
    "B093": "Una captura independiente contiene el nombre desarrollado y la descripción técnica. Es una correspondencia sólida con el rótulo de mayo, que carecía de enlace original. Queda por verificar el conjunto de funciones de septiembre.",
    "B094": "La búsqueda del acrónimo, su descripción, el control causal temporal y los autocodificadores dejó la fuente sin identificar. Los resultados de otros campos no resolvieron la atribución.",
    "B095": "La presentación fechada describe públicamente aprendizaje automático con Cairo. Una captura del 26 de noviembre de 2025 acredita el sitio de Giza. La equivalencia entre versiones queda abierta.",
    "B096": "El anuncio documenta la puesta en marcha de la red principal de Aleo antes del corte. Las prestaciones y el texto de páginas posteriores requieren evidencia de cada edición.",
}

WIDTH, HEIGHT = A4
MARGIN = 49
RIGHT = WIDTH - MARGIN
INNER = RIGHT - MARGIN
COL = (INNER - 22) / 2
INK = colors.HexColor("#192923")
GREEN = colors.HexColor("#215443")
MUTED = colors.HexColor("#42534B")
LINE = colors.HexColor("#C4CEC7")


def read_rows(name):
    with (BASE / name).open(encoding="utf-8", newline="") as stream:
        return list(csv.DictReader(stream))


def checked_url(value):
    if urlsplit(value).scheme not in ("https", "http"):
        raise ValueError(f"Unexpected source locator: {value!r}")
    return value


def fonts():
    location = Path(reportlab.__file__).parent / "fonts"
    for name, file in [("SPEText", "Vera.ttf"), ("SPEBold", "VeraBd.ttf")]:
        pdfmetrics.registerFont(TTFont(name, str(location / file)))


def style(font, size, lead, color):
    return ParagraphStyle(font, fontName=font, fontSize=size, leading=lead, textColor=color,
                          allowWidows=0, allowOrphans=0)


def paragraph(value, width, s):
    p = Paragraph(escape(value), s)
    height = p.wrap(width, 800)[1]
    return p, height


def put(c, value, x, y, width, s):
    p, height = paragraph(value, width, s)
    p.drawOn(c, x, y - height)
    return y - height


def link(c, label, url, x, y, size=8):
    c.setFont("SPEText", size)
    c.setFillColor(GREEN)
    c.drawString(x, y, label)
    w = pdfmetrics.stringWidth(label, "SPEText", size)
    c.setStrokeColor(LINE)
    c.line(x, y - 1.5, x + w, y - 1.5)
    c.linkURL(checked_url(url), (x, y - 3, x + w, y + size), relative=0, thickness=0)
    return x + w


def page_base(c, page):
    c.setStrokeColor(LINE)
    c.setLineWidth(.45)
    c.line(MARGIN, HEIGHT - 45, RIGHT, HEIGHT - 45)
    c.line(MARGIN, 40, RIGHT, 40)
    c.setFillColor(MUTED)
    c.setFont("SPEBold", 8)
    c.drawString(MARGIN, HEIGHT - 36, "SPE Audit")
    c.setFont("SPEText", 8)
    c.drawRightString(RIGHT, HEIGHT - 36, "Investigación / Research   ·   1.2")
    c.drawString(MARGIN, 25, "Rubén Abella   ·   SPE Audit   ·   22.11.2026")
    c.drawRightString(RIGHT, 25, str(page))


@dataclass
class Entry:
    row: dict
    dated: dict
    note_es: str

    @property
    def identifier(self):
        return self.row["id"]

    def metadata(self):
        if self.dated:
            when = self.dated["date_of_identified_object"] or "—"
            return "1.1   " + when + "   ·   " + DATE_TYPES[self.dated["status"]] + "   ·   " + PERIOD[self.dated["object_date_vs_2025_12_04"]]
        period = self.row["period"].split()[0]
        return "1.0   " + self.row["publication_or_submission"] + "   ·   " + PERIOD[period]

    def text(self):
        return self.note_es, self.dated.get("scope_and_remaining_gap", self.row["relevance_and_limit"])

    def block(self):
        title, h1 = paragraph(self.row["source"], INNER - 47, TITLE)
        texts = [paragraph(t, COL, BODY) for t in self.text()]
        return title, h1, texts, 5 + h1 + 30 + max(h for p, h in texts) + 21

    def draw(self, c, y):
        title, title_height, texts, height = self.block()
        c.setFillColor(GREEN)
        c.setFont("SPEBold", 9)
        c.drawString(MARGIN, y - 11, self.identifier)
        title.drawOn(c, MARGIN + 47, y - title_height)
        source = self.row["primary_or_recorded_url"]
        if source:
            c.linkURL(checked_url(source), (MARGIN + 47, y - title_height - 1, RIGHT, y), thickness=0)
        c.setFillColor(MUTED)
        c.setFont("SPEText", 8)
        kind = self.row["kind"]
        c.drawString(MARGIN, y - title_height - 12, ROLE_ES[kind] + " / " + kind)
        c.drawString(MARGIN, y - title_height - 24, self.metadata())
        y0 = y - title_height - 31
        for i, (p, h) in enumerate(texts):
            p.drawOn(c, MARGIN + i * (COL + 22), y0 - h)
        ylink = y0 - max(h for p, h in texts) - 12
        if source:
            x = link(c, "Fuente / Source", source, MARGIN, ylink, 7.8)
        else:
            x = MARGIN - 17
        if self.dated:
            evidence = self.dated["evidence_url"]
            if evidence:
                label = "Evidencia de fecha / Date evidence"
                if self.dated["status"] == "unresolved":
                    label = "Documento examinado / Item checked"
                elif self.identifier == "B093":
                    label = "Versión candidata / Candidate release"
                link(c, label, evidence, x + 17, ylink, 7.8)
            else:
                link(c, "Registro de la búsqueda / Search record", BASE_URL + "v11/sources/search_log.csv", x + 17, ylink, 7.8)
        c.setStrokeColor(LINE)
        c.line(MARGIN, y - height + 2, RIGHT, y - height + 2)
        return y - height - 7


def group_pages(items):
    # Break only between complete entries. Repeat the bilingual section heading.
    available = HEIGHT - 136 - 56
    pages, current, used = [], [], 0
    for row in items:
        height = row.block()[-1] + 7
        if height > available:
            raise ValueError(f"{row.identifier} exceeds one page")
        if current and used + height > available:
            pages.append(current)
            current, used = [], 0
        current.append(row)
        used += height
    if current:
        pages.append(current)
    # Balance a sparse closing page while preserving the order and page limit.
    if len(pages) >= 2:
        last, prev = pages[-1], pages[-2]
        while len(prev) - len(last) > 1:
            candidate = prev[-1]
            if sum(r.block()[-1] + 7 for r in [candidate, *last]) > available:
                break
            last.insert(0, prev.pop())
    return pages


def overview(c, groups):
    page_base(c, 1)
    c.setFillColor(INK)
    c.setFont("Times-Roman", 30)
    c.drawString(MARGIN, HEIGHT - 95, "Catálogo de antecedentes")
    c.setFont("Times-Italic", 21)
    c.drawString(MARGIN, HEIGHT - 124, "Prior-art catalogue")
    c.setFillColor(MUTED)
    c.setFont("SPEText", 10)
    c.drawString(MARGIN, HEIGHT - 149, "Rubén Abella   ·   Edición documental / Documentary edition 1.2")
    es = ("Las 116 fichas B reúnen antecedentes técnicos, documentos jurídicos y pistas "
          "de búsqueda de los informes originales. Los títulos conservan la redacción del registro. "
          "El tipo original de cada ficha determina su sección. Busca por identificador para recuperar el orden de origen.")
    en = ("The 116 B-series entries bring together technical work, legal records and discovery leads "
          "from the original reports. Titles retain the wording of the register. Each entry’s original "
          "type determines its section. Search by identifier to recover the source order.")
    put(c, es, MARGIN, HEIGHT - 175, COL, LEDE)
    put(c, en, MARGIN + COL + 22, HEIGHT - 175, COL, LEDE)
    y = HEIGHT - 293
    c.setFont("SPEBold", 9)
    c.setFillColor(GREEN)
    c.drawString(MARGIN, y, "CONTENIDO / CONTENTS")
    c.drawRightString(RIGHT, y, "Fichas / Entries     Pág. / Page")
    page = 2
    for i, (es, en, kinds, pages) in enumerate(groups, 1):
        y -= 29
        c.setFont("SPEBold", 9)
        c.setFillColor(INK)
        c.drawString(MARGIN, y, es)
        c.setFillColor(MUTED)
        c.setFont("SPEText", 8)
        c.drawString(MARGIN, y - 11, en)
        c.setFont("SPEText", 10)
        c.drawRightString(RIGHT - 72, y - 3, str(sum(map(len, pages))))
        c.drawRightString(RIGHT, y - 3, str(page))
        c.linkRect("", f"group{i}", (MARGIN, y - 13, RIGHT, y + 9), thickness=0)
        page += len(pages)
    y -= 42
    c.setFillColor(GREEN)
    c.setFont("SPEBold", 9)
    c.drawString(MARGIN, y, "FECHAS / DATES")
    dates_es = ("El corte histórico es el 4 de diciembre de 2025. La edición 1.0 dejó 58 fechas abiertas. "
                "La revisión 1.1 situó 27 objetos antes del corte y 26 después. Cinco siguen sin fecha acreditada. "
                "Las fichas indican qué se fechó. La fecha de una captura o revisión puede ser posterior a la primera publicación.")
    dates_en = ("The historical cutoff is 4 December 2025. Edition 1.0 left 58 dates open. The 1.1 review "
                "placed 27 identified objects before the cutoff and 26 after it. Five still lack a supported public date. "
                "Each entry identifies the dating basis. A capture or revision may postdate first publication.")
    bottom = min(put(c, dates_es, MARGIN, y - 12, COL, LEDE),
                 put(c, dates_en, MARGIN + COL + 22, y - 12, COL, LEDE))
    y = bottom - 26
    c.setFont("SPEBold", 9)
    c.setFillColor(GREEN)
    c.drawString(MARGIN, y, "DOCUMENTACIÓN / SOURCE FILES")
    for label, url in [
        ("116 fichas B / B-series CSV", BASE_URL + BIB),
        ("58 comprobaciones de fecha / Dating ledger", BASE_URL + LEDGER),
        ("54 fichas M / Historical M register", BASE_URL + "landscape/legacy.csv"),
        ("10 comparaciones N / ES", BASE_URL + "PAPER_ES.md"),
        ("10 technical comparisons / EN", BASE_URL + "PAPER_EN.md"),
        (f"DOI {DOI}", "https://doi.org/" + DOI),
    ]:
        y -= 16
        link(c, label, url, MARGIN, y, 8.5)
    y -= 22
    rights_es = "Texto editorial propio © Rubén Abella, CC BY 4.0. Marcas y material de terceros conservan sus derechos."
    rights_en = "Original editorial text © Rubén Abella, CC BY 4.0. Trademarks and third-party works retain their own rights."
    end = min(put(c, rights_es, MARGIN, y, COL, BODY), put(c, rights_en, MARGIN + COL + 22, y, COL, BODY))
    if end < 55:
        raise ValueError("Overfull overview")


def build():
    global BODY, LEDE, TITLE
    fonts()
    BODY = style("SPEText", 8.75, 12.2, INK)
    LEDE = style("SPEText", 9.3, 13.4, INK)
    TITLE = style("SPEBold", 10.5, 14.1, INK)
    rows = read_rows(BIB)
    dated = {r["id"]: r for r in read_rows(LEDGER)}
    notes = {r["id"]: r["nota_es"] for r in read_rows(SPANISH)}
    ids = [r["id"] for r in rows]
    if ids != [f"B{i:03d}" for i in range(1, 117)] or set(ids) != set(notes):
        raise ValueError("Expected all 116 unique B identifiers and Spanish notes")
    if set(dated) != set(RECHECK_ES) or len(dated) != 58:
        raise ValueError("Recheck notes do not match the 58 dating records")
    kinds = [kind for _, _, group in GROUPS for kind in group]
    if len(set(kinds)) != len(kinds) or set(kinds) != {r["kind"] for r in rows}:
        raise ValueError("Section assignment must cover every source type once")
    dating = Counter(r["object_date_vs_2025_12_04"] for r in dated.values())
    if dating != {"before": 27, "after": 26, "unknown": 5}:
        raise ValueError("Unexpected dating-ledger distribution")
    groups = []
    for es, en, types in GROUPS:
        entries = [Entry(r, dated.get(r["id"], {}), RECHECK_ES.get(r["id"], notes[r["id"]]))
                   for kind in types for r in rows if r["kind"] == kind]
        groups.append((es, en, types, group_pages(entries)))
    path = HERE / "Prior_art_catalogue.pdf"
    c = Canvas(str(path), pagesize=A4, invariant=1, pageCompression=1)
    c.setTitle("Catálogo de antecedentes / Prior-art catalogue · SPE Audit 1.2")
    c.setAuthor("Rubén Abella · SPE Audit")
    c.setSubject("116 bibliographic records and the dating evidence of the 1.1 revision")
    overview(c, groups)
    c.showPage()
    for i, (es, en, kinds, pages) in enumerate(groups, 1):
        for j, entries in enumerate(pages):
            page_base(c, c.getPageNumber())
            if j == 0:
                c.bookmarkPage(f"group{i}")
                c.addOutlineEntry(es + " / " + en, f"group{i}", level=0)
            c.setFillColor(INK)
            c.setFont("Times-Roman", 22)
            c.drawString(MARGIN, HEIGHT - 81, es)
            c.setFillColor(MUTED)
            c.setFont("Times-Italic", 13)
            c.drawString(MARGIN, HEIGHT - 102, en)
            c.setFont("SPEText", 8)
            c.drawRightString(RIGHT, HEIGHT - 101, f"{j + 1} / {len(pages)}")
            y = HEIGHT - 126
            for entry in entries:
                y = entry.draw(c, y)
            if y < 52:
                raise ValueError("Overfull catalogue page")
            c.showPage()
    c.save()
    for es, en, types, pages in groups:
        print(f"{sum(map(len, pages)):2d} entries, {len(pages)} pages: {en}")
    print(path)


if __name__ == "__main__":
    build()
