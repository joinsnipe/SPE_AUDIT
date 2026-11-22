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

## Qué cuenta cada cifra · What the numbers count

| Unidad / Unit | Español | English |
|---|---|---|
| 96 + 16 = 112 respuestas / answers | Cuatro misiones espaciales. Las 96 respuestas de desarrollo combinan plantillas y fechas de corte. Las 16 reformulaciones pertenecen a las mismas misiones. | Four space missions. The 96 development answers vary templates and cutoff dates. The 16 reworded answers concern the same missions. |
| 48 respuestas / answers | Seis sucesos adicionales, con 18 positivos, 24 controles y 6 referencias indeterminadas en español e inglés. | Six additional events, with 18 positives, 24 controls and 6 indeterminate references across English and Spanish. |
| 160 fichas / cases | El explorador reúne las 112 respuestas originales y las 48 posteriores. Cada conjunto tiene su propio denominador. | The explorer contains the original 112 answers plus the later 48. Each cohort has its own denominator. |
| 224 lecturas / readouts | Un lector local evaluó dos veces las mismas 112 respuestas. Un pase recibió además la fecha del desenlace. | One local reader evaluated the same 112 answers twice. One pass also received the outcome date. |
| 17 pasajes / passages | Textos de terceros (NIST y USGS). El proyecto asignó las etiquetas de referencia. | Third-party texts from NIST and USGS. The project supplied the reference labels. |
| 34 sucesos / events | Sucesos propuestos para una réplica. La edición publicada contiene sus fuentes. Las preguntas, respuestas y etiquetas de esa evaluación siguen pendientes. | Events proposed for a replication. The published edition supplies their sources. Questions, answers and reference labels for that evaluation remain to be produced. |
| 16 casos del piloto / pilot cases | Selección de 8 casos en español y 8 en inglés, extraídos de los 48. En las observaciones publicadas constan cero decisiones humanas y cero minutos medidos. | A selection of 8 Spanish and 8 English cases drawn from the 48. The published observations contain zero human decisions and zero measured minutes. |

La regla de proposiciones detectó 30/32 positivos en desarrollo, 4/8 en las reformulaciones y 1/18 en los seis sucesos adicionales. En este último conjunto remitió 17 de los 18 positivos a revisión. Con SmolLM2-135M, incluir la fecha del desenlace cambió seis decisiones de desarrollo y ninguna de las 16 reformulaciones. La lectura exploratoria de 18/18 positivos se hizo a posteriori, con referencias internas. La evaluación independiente propuesta permitiría medir el acuerdo entre personas y el tiempo que dedican a resolver los casos. [Resultados por conjunto](../post11/generalization/cohorts.csv) · [Cambios al añadir la fecha](../v12/transitions.csv) · [Convocatoria y método del piloto](../post11/open-pilot/)

The proposition rule detected 30/32 positives in development, 4/8 on reworded answers and 1/18 across the six additional events. In that last cohort it sent 17 of the 18 positives to review. With SmolLM2-135M, providing the outcome date changed six development decisions and none of the 16 reworded cases. The exploratory reading that flagged 18/18 positives took place after the fact and used internal reference labels. The proposed independent evaluation would measure human agreement and active review time. [Cohort counts](../post11/generalization/cohorts.csv) · [Date-access transitions](../v12/transitions.csv) · [Open pilot](../post11/open-pilot/)

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
