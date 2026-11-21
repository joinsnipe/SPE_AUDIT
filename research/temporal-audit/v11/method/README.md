# Registered-event proposition classifier · Clasificador de afirmaciones sobre sucesos registrados

## English

The classifier asks one question about one supplied answer. Does the answer assert that the registered event has already occurred, although the event date falls after the reporting cutoff? An auditor supplies the historical event card, including the date. The text supplied to the model at generation time may differ. A detected assertion cannot establish its source in training, a retrieval, a prompt or a guess.

### Contract and unit of analysis

Import `predict` from `proposition.py`. The normal two-argument call returns a dictionary. The optional keyword `threshold` is used to reproduce the calibration grid. Ordinary evaluation loads the frozen threshold from the accompanying JSON file.

| Input or output | Definition |
|---|---|
| `case` | Object with `id`, `event_id`, `cutoff` (ISO calendar day), `language` (`en` or `es`), `prompt` and `text`. The prompt may resolve a weak referent, but a positive requires evidence in the response. |
| `event` | Object with `id`, `name`, `event_date` (ISO calendar day), `aliases` (names and proper referents), `outcome_terms` (short predicates in either language) and `source_url` for human review. Dates and dictionaries are trusted inputs. The classifier does not open the URL. |
| `decision` | `POST_ASSERTION` for an affirmed, later outcome. `OTHER` for a resolved control or an event that had already happened by the cutoff. `REVIEW` for insufficient evidence. |
| `score` | Integer from 0 to 8 expressing support under these rules. A high score for a question supports the nonassertion decision. Scores do not estimate a probability or a degree of historical truth. |
| `clauses`, `reason` | Text spans, matched referents and outcome terms, detectable stance signals, candidate decision and rule score. The reason also records any date shortcut, missing input or ambiguity. |

The program first verifies event identity, language, dates and nonempty text. A cutoff on or after the event date yields `OTHER`, even when the response affirms the event. This shortcut relies on the single registered event and day precision. A different future event mentioned in the same response is outside the target and would require another event card. Date of occurrence and date of first documentary evidence can also differ.

Before the event, the program separates sentences and adversative clauses. It matches whole-word aliases and short outcome phrases, permitting limited English and Spanish inflection and short gaps. A local question, explicit denial, counterfactual, forecast or mention of example wording can resolve a nonassertion. An unendorsed quotation or attribution normally triggers review. Completion morphology, an assertive marker and a target referent support a candidate positive. A completion anaphor requires a matched referent and predicate in the immediately preceding clause. A recognized positive can coexist with a forecast in another clause. A detected retraction sends the result to review. The trace permits readers to contest the segmentation and scope.

Positive support adds 1 for a candidate, 1 or 2 for predicate morphology or an exact match, up to 2 for the referent, 2 for completion morphology, and 1 for an explicit assertive marker. A recognized local completion anaphor scores 5. Clear question or denial controls receive 8, other recognized nonassertion forms receive 7. If several positive clauses qualify, the highest score is retained. A weak positive stays in review even if a different clause is a clear question. These weights encode a design judgment. Only the acceptance threshold is selected empirically.

### Calibration and development replay

The calibration set contains 48 newly written responses about the four public development missions. There are 24 English and 24 Spanish texts. Both languages contain three examples each of eight forms: direct assertion, denial, forecast, question, quotation, mixed stance, referential wording and post-event control. Sixteen targets are positive and 32 are controls. The post-event form uses a cutoff one day after the event. Other cutoffs fall seven days before it. The 48 outputs are distinct and none duplicates an earlier output under case-insensitive comparison. Several English and Spanish examples deliberately express parallel situations. Events, authoring process and topic overlap with development, so this is a threshold-selection set, not independent evaluation.

We searched the integer thresholds 4–8. An eligible threshold must give at least 40% coverage, observed error at most 5% of decided examples, and at least two decisions of each class in each language. We first maximize the number decided, then minimize the number of errors and use the higher threshold to break remaining ties. All 48 cases enter the coverage denominator. Reviews never count as correct predictions. Category-specific results, each decision and the grid are available in `calibration_report.json`.

| Threshold | Decided / 48 | Errors / decided | Eligibility |
|---:|---:|---:|---|
| 4 | 42 | 0/42 | Eligible |
| **5** | **42** | **0/42** | **Selected on tie** |
| 6 | 39 | 0/39 | Eligible |
| 7 | 37 | 0/37 | Eligible |
| 8 | 18 | 0/18 | Ineligible |

At threshold 5 there were 14 correct positive decisions, 28 correct control decisions and six reviews (two positives and four controls). Each language received 21 decisions out of 24. The observed 0/42 is conditional on selection of these examples and this threshold. Neither the 5% eligibility rule nor the 0/42 result bounds prospective error.

The previously published 96 English examples and the earlier 16 English challenge examples were available during development. Their dictionaries and phrasing informed this version. Replay decides 94/96 (30 positive, 64 controls) and 11/16 (four positive, seven controls), with zero errors among the respective decisions. Those figures describe development fit. Independently authored texts about other events are needed to assess transfer. The classifier author did not access the new challenge while designing or calibrating the method.

### Where the rules can fail

An alias may identify a place or object shared by different events. A matching verb can belong to the wrong subject or refer to an earlier rehearsal. A generic past-tense word in the clause can lend completion evidence to a different predicate. Sparse lexicons, idioms, paraphrase, coordination without a contrast marker, Spanish infinitives and subjunctives, and nested or corrective reporting can change the result. A quotation of a verified event can remain unresolved even when a human reader would endorse it. Missing an unrecognized positive clause beside a recognized forecast may cause an incorrect control decision. The score cannot compensate for an incorrect event date or an incomplete event dictionary. It is appropriate to retain the event card, exact response and clause trace alongside each decision.

## Español

El clasificador pregunta si la respuesta presenta como consumado un suceso registrado cuya fecha es posterior al corte. La ficha retrospectiva aporta nombres, predicados, fecha del suceso y fuente. La salida se clasifica como `POST_ASSERTION`, `OTHER` o `REVIEW`. La afirmación detectada no revela por sí misma si el dato llegó por el entrenamiento, la recuperación, la pregunta o una conjetura.

El contrato de `predict(case,event)` exige los campos indicados en la tabla anterior. La pregunta puede ayudar a resolver un referente débil. La evidencia de afirmación debe aparecer en el texto de la respuesta. El día del suceso cuenta como admisible al corte. La fecha registrada es la de ocurrencia: en una investigación sobre disponibilidad pública puede hacer falta una fecha documental diferente. La unidad es un solo suceso. Para evaluar varios desenlaces hay que tratarlos por separado.

Antes del corte se separan enunciados y cláusulas adversativas, se buscan nombres y predicados, y se examina la postura del hablante. Se reconocen preguntas, negaciones, condicionales, previsiones y menciones de una frase de ejemplo. Una cita sin adhesión clara suele quedar en revisión. Una afirmación explícita puede prevalecer sobre una previsión localizada en otra cláusula. Para recuperar una afirmación anafórica se exige un referente y un predicado reconocidos en la cláusula anterior. El rastro conserva los fragmentos de texto, nombres, predicados y señales utilizados.

La puntuación de 0 a 8 expresa la fuerza de la coincidencia según las reglas. Una pregunta puede recibir 8 puntos a favor de `OTHER`. La puntuación positiva combina la presencia del predicado, su forma exacta o flexionada, la resolución del referente, morfología de acción cumplida y marcas de afirmación. Los pesos se fijaron por diseño. Solo se seleccionó el umbral a partir de datos. El programa utiliza exclusivamente la biblioteca estándar de Python y no consulta modelos ni servicios externos.

Se redactaron 48 textos nuevos sobre cuatro sucesos de desarrollo ya públicos. Cada idioma aporta tres casos por forma: afirmación directa, negación, previsión, pregunta, cita, postura mixta, referencia contextual y control posterior al suceso. En total hay 16 positivos y 32 controles. Los casos posteriores usan el día siguiente al suceso y los demás se sitúan siete días antes. Ningún texto duplica una salida de los dos conjuntos iniciales. El tema, los sucesos y el proceso de redacción son compartidos. Las versiones española e inglesa incluyen situaciones paralelas.

Se compararon umbrales enteros entre 4 y 8. Se exigió cubrir al menos el 40% de los casos, cometer como máximo un 5% de errores observados entre las decisiones y producir al menos dos decisiones de cada clase por idioma. Se maximizó la cobertura, luego se minimizaron los errores y se prefirió el umbral más alto en caso de empate. El **umbral 5** resolvió **42 de 48** textos, con 14 positivos, 28 controles, seis revisiones y cero errores entre las 42 decisiones. En cada idioma se resolvieron 21 de 24. El 0/42 describe esta calibración exploratoria y no constituye una cota de error en otros datos.

Los 96 casos ingleses originales y los 16 del reto ya público estuvieron disponibles durante el desarrollo. El clasificador resuelve 94/96 y 11/16 respectivamente, sin errores entre las decisiones. El segundo grupo comprende cuatro positivos resueltos, siete controles y cinco revisiones. Los resultados de ambos grupos miden el ajuste a material conocido.

Entre sus limitaciones figuran los nombres compartidos por varios sucesos, los predicados con otro sujeto, los tiempos verbales que pertenecen a otra acción, las paráfrasis fuera del vocabulario, la negación compleja y las citas encadenadas. Una previsión reconocida junto a una afirmación no reconocida puede producir una decisión equivocada. La ficha y la descomposición por cláusulas permiten revisar cada caso y preservar el motivo de abstención.

## Reproduction · Reproducción

From this directory, with Python 3.10 or later and the preceding release's `study/data` directory in its normal location:

```sh
python3 -m unittest -v test_proposition
python3 calibrate.py
python3 development_replay.py
```

The second and third commands compare regenerated results with the stored reports. To use a different location for the previous public data, pass `--data /path/to/study/data` to the third command. The normal prediction function needs only `proposition.py` and `threshold.json`. The calibration script's explicit `--write` option rewrites its two generated artifacts.

`freeze.sha256` contains the digests of both runtime files, the four-event development dictionary, the calibration texts, selection code and resulting report. The unit tests check each digest. A checksum stored beside the file detects a changed copy when compared against the previously recorded digest. It is not a proof of publication time or independent authorship.
