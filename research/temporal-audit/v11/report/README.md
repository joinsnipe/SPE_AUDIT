# Tipografía y verificación de los PDF · PDF build and verification

Desde `research/temporal-audit/`, ejecute el comando siguiente. From `research/temporal-audit/`, run the following command.

```sh
python3 v11/report/render_supplements.py
```

**Español.** El script lee `v11/SUPPLEMENT_EN.md` y `v11/SUPPLEMENT_ES.md`. Genera los PDF con los mismos nombres en esa carpeta. Usa Pandoc, Python con ReportLab y PyMuPDF, las tipografías utilizadas por la edición 1.0 y los archivos publicados `render_paper.py` y `assets/logo.png`. La generación funciona sin conexión. En Debian, la primera edición utiliza los paquetes de fuentes `fonts-open-sans` y `fonts-dejavu-core`. Con los mismos archivos, dependencias y fuentes, el resultado se puede comparar por SHA-256.

Se comprueban el título, el logotipo, el número de edición, los marcadores de sección, la presencia de enlaces en el índice, los destinos externos citados, el contenido de párrafos y celdas, los márgenes horizontales y las páginas vacías. Las dos salidas pasan por la comprobación antes de sustituir sus versiones previas. Las tablas repiten sus encabezados. Las figuras pueden suministrarse como PNG o JPEG local en un párrafo propio, con su descripción en el texto alternativo.

**English.** The command reads `v11/SUPPLEMENT_EN.md` and `v11/SUPPLEMENT_ES.md` and writes their PDF counterparts alongside the manuscripts. It reuses the published `render_paper.py`, `assets/logo.png` and fonts from edition 1.0. It runs offline with Pandoc, Python, ReportLab and PyMuPDF. On Debian the original edition uses `fonts-open-sans` and `fonts-dejavu-core`. Matching inputs, fonts and dependencies permit byte-for-byte comparison using the SHA-256 values printed by the script.

The script checks the title, cover logo, edition number, section bookmarks, linked contents, cited external destinations, excerpts throughout paragraphs and table cells, horizontal text bounds and empty pages. Both outputs pass verification before they replace earlier files. Table headers repeat across pages. A standalone local PNG or JPEG with Markdown alternative text can serve as a figure with a printed caption.

Para elegir una sola edición o usar directorios alternativos, consulte la ayuda. To build one language or specify separate input and output directories, see the command help.

```sh
python3 v11/report/render_supplements.py --help
```

## Ediciones completas · Complete volumes

```sh
python3 -B v11/report/render_supplements.py
python3 -B v11/report/build_full.py
```

El segundo comando integra los suplementos con `PAPER_EN.pdf` y `PAPER_ES.pdf` de la edición 1.0 y produce `v11/FULL_EN.pdf` y `v11/FULL_ES.pdf`. Abre cada volumen con una portada en su idioma de edición, el DOI y enlaces directos a cada parte. Comprueba el texto de todas las páginas, las coordenadas y los destinos de los enlaces originales, la secuencia de marcadores y los metadatos de autor. Se pueden compilar ambas ediciones en otro directorio con `--output-dir`.

The second command combines the supplements with the published edition 1.0 PDFs. Each volume opens with a cover and contents in its own language, a DOI and direct links to both parts. The script verifies all source pages, the positions and destinations of their links, the order of bookmarks and the author metadata. Use `--output-dir` to build a second copy and compare the printed SHA-256 values.
