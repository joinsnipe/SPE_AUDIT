# Auditoría temporal de las respuestas de IA · Temporal auditing of AI outputs

**Rubén Abella · SPE Audit · Edición integral 1.2.1 · 22 de noviembre de 2026**

[Descargar el volumen completo en español](FULL_ES.pdf) · [Download the complete English volume](FULL_EN.pdf) · [Zenodo · DOI 10.5281/zenodo.24448090](https://doi.org/10.5281/zenodo.24448090)

## Para el lector

La edición integral tiene 128 páginas en español y 121 en inglés. Cada PDF reúne la investigación en un volumen autónomo. El índice general y los marcadores permiten pasar del método al dato que lo respalda. El volumen precedente se conserva completo, incluidas sus ilustraciones y sus fichas históricas. Su foliación y su DOI permiten identificar qué se publicó entonces. Los enlaces a los archivos por caso llevan a los datos que se pueden inspeccionar o volver a puntuar.

| Dentro del volumen | Datos de apoyo |
|---|---|
| El experimento emparejado y las ocho decisiones ilustrativas | [112 respuestas, cuatro métodos](../v12/paired_decisions.csv) · [recuentos por suceso](../v12/metrics.csv) · [cambios entre brazos](../v12/transitions.csv) |
| El estudio original, su suplemento y los ensayos posteriores | [Datos de las cuatro misiones](../study/) · [seis sucesos nuevos de la edición 1.1](../v11/holdout/) · [17 pasajes NIST/USGS](../post11/external/) · [recibos del lector de seguimiento](../post11/reference_reader/) |
| Antecedentes, fichas y revisión de la datación | [116 referencias](../landscape/bibliography.csv) · [registro histórico de 54 fichas](../landscape/legacy.csv) · [58 referencias reexaminadas](../v11/sources/dating_ledger.csv) |
| Selección propuesta para un estudio externo | [34 acontecimientos candidatos y sus fuentes](../v12/candidate_events.csv) · [diseño de réplica](../v12/NEXT_STUDY.md) |

El estudio original usó cuatro sucesos en 96 filas de desarrollo y 16 frases de reto sobre esos mismos sucesos. El ensayo emparejado volvió a leer esas 112 respuestas con un solo modelo local: cada respuesta se evaluó con y sin un campo que identifica la fecha del desenlace. Se conservaron las 224 respuestas crudas del lector. En el reto de redacción, ambos brazos emitieron cuatro alertas correctas sobre ocho positivos, una falsa alerta entre ocho controles y once remisiones. La regla con fecha original remitió 14 de 16 y detectó 0 de 8. Los datos permiten ver qué recibió cada método y qué dejó a revisión.

La convocatoria de revisión humana sigue abierta. El [kit del piloto](../post11/open-pilot/) selecciona ocho casos en español y ocho en inglés del conjunto de 48 de la edición 1.1. Es un ejercicio distinto del reto original de 16 frases en inglés. Dos personas reciben los mismos casos en orden distinto y emiten sus decisiones por separado. Una tercera examina los desacuerdos. La [mesa pública](https://www.spetrace.com/es/research/temporal-audit/review-desk) permite explorar ejemplos resueltos; quienes participen en el piloto pueden registrar cualquier exposición previa.

## For readers and replicators

Each PDF brings the research, the original volume, follow-up results, updated catalogue and future event register together. The edition preserves the earlier volume in full. Its original folios and DOI identify the historical pages. The new front matter provides navigation across the integrated volume.

The original 96 development rows and 16 wording challenges share four space missions. A paired retrospective replay classified the same 112 answers twice, varying access to the recorded outcome date in a fixed local reader. All 224 raw completions are public. On the 16 wording challenges, both conditions alerted on four of eight positives and one of eight controls and referred eleven cases. The original dated matcher referred fourteen and alerted on none of the eight positives. The registered 34 candidate events await a new evaluation. External human agreement, active review time and error prevalence in deployed services remain unmeasured.

The author develops SPE Audit. Reference labels in the reported experiments were produced within the project with AI assistance. The [pilot kit](../post11/open-pilot/) supports a separately organised blind review. For the original four missions, the 48 bilingual cases and the paired local replay, see the case-level tables and their respective protocols. The [short edition 1.2](https://doi.org/10.5281/zenodo.24447732) provides a nine-page reading option. The [complete historical edition 1.1](https://doi.org/10.5281/zenodo.24424024) and the [all-versions DOI](https://doi.org/10.5281/zenodo.24424023) remain citable.

## Reproducir

La copia completa del repositorio adjunta en Zenodo contiene la edición y sus materiales de reproducción. Desde `research/temporal-audit/` se puede ejecutar con Python 3.12:

```sh
python -B verify.py
python -B v11/verify_v11.py
python -B post11/verify.py
python -B v12/score.py
```

Para volver a componer ambos volúmenes, ejecutar `python v121/build_volume.py` desde ese mismo directorio con Pandoc, ReportLab, PyMuPDF y las familias Open Sans y DejaVu.

The last command verifies the 224 responses against the frozen request plan before joining the predictions to the editorial labels. The [run instructions](../v12/README.md) also specify how to verify the externally timestamped plan and repeat local inference. The original text and figures are licensed under CC BY 4.0. Software is distributed under the [repository licence](../../../LICENSE). Trademarks and third-party material retain their respective rights.
