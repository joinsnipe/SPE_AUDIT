# Laboratorio abierto · Open research lab

**Rubén Abella · SPE Audit.** Material de exposición y experimentos posteriores al preprint 1.1 del 21 de noviembre de 2026. Cada experimento identifica los datos que se usaron, las decisiones individuales y las limitaciones de la prueba. [Estudio de referencia en Zenodo · Reference preprint](https://doi.org/10.5281/zenodo.24424024)

| | Español | English |
|---|---|---|
| Nota científica de seguimiento | [PDF bilingüe](brief/BRIEF_ES_EN.pdf) · [Texto en español](brief/BRIEF_ES.md) | [Bilingual PDF](brief/BRIEF_ES_EN.pdf) · [English text](brief/BRIEF_EN.md) |
| Lector con configuración fijada | [Protocolo e instrucciones exactas](reference_reader/reader_es.md) · [17 extractos institucionales](external/) | [Reference-reader protocol](reference_reader/reader_en.md) · [17 institutional passages](external/) |
| Demostración | [Reconstruir una petición](https://www.spetrace.com/es/research/temporal-audit) · [Abrir la mesa de revisión](https://www.spetrace.com/es/research/temporal-audit/review-desk) | [Reconstruct a request](https://www.spetrace.com/research/temporal-audit) · [Open the review desk](https://www.spetrace.com/research/temporal-audit/review-desk) |
| Piloto de 16 casos | [Guía de participación](open-pilot/) · [Descargar kit](open-pilot/pilot-16.zip) | [Organise a blind pilot](open-pilot/) · [Download the kit](open-pilot/pilot-16.zip) |
| Estudios | [Tres cohortes y seis sucesos nuevos](generalization/analysis_es.md) · [Cuatro políticas de revisión](escalation/) | [Three cohorts and six new events](generalization/analysis_en.md) · [Four review policies](escalation/) |
| Exposición pública | [Diapositivas](talk/slides_es.pdf) · [Guion](talk/talk_es.md) | [Slides](talk/slides_en.pdf) · [Speaker notes](talk/talk_en.md) |
| Traducción | [Protocolo de retrotraducción humana](generalization/backtranslation.md) | [Blind back-translation materials](generalization/forms/) |

El piloto se realiza localmente. Cada persona revisa las mismas 16 fichas sin ver la lectura del otro revisor ni las etiquetas del artículo. Cada grupo conserva sus archivos y elige si comparte algún resultado agregado. Quienes ya hayan visto los casos o la demo pueden declarar esa exposición.

The public demonstration and the separate blind packets serve different purposes. The downloadable pilot contains a local organiser, a reviewer interface and blank packets generated on demand. No registration is required. Participation and disclosure of aggregates are voluntary. The demonstration never sends the visitor’s decisions or notes to the research team.

## Reproducir · Reproduce

Desde esta carpeta, ejecuta `python3 verify.py` para verificar el inventario, repetir los comparadores, cotejar las decisiones con los recibos del modelo y ensayar la generación del piloto vacío. Con Node.js instalado también se prueba el visor interactivo. To start a fresh local model run, use the frozen instructions, exact model revision and CPU runtime described in the [reader protocol](reference_reader/README.md).
