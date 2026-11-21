# Bilingual holdout | Reto bilingüe

## English

This collection asks whether the writer of an answer presents one specified milestone as already accomplished at a cutoff that precedes its actual occurrence. Read the prompt to resolve ellipsis and pronouns, then judge what the answer commits its writer to. All prompts, answers, fictional documents and quoted examples were written for this exercise. They are neither institutional quotations nor answers collected from a deployed model. The cited institutions document the dates.

Six events across transport infrastructure, performing arts and experimental physics each have four English and four Spanish cases. The combination deliberately includes ordinary wording, indirect references, date-free answers, predictions, denial, disputed claims, readings of quotations and ambiguous questions. Each language was written separately. The rows do not form translation pairs. A file- or row-level split of this corpus would allow almost identical event facts to appear on both sides of an evaluation. Keep entire event groups together in subsequent training and evaluation.

The author selected the events, wrote the texts and supplied the reference labels without consulting the new classifier, its outputs, its development data or another annotator's labels. Selection followed the availability of short, dated institutional accounts and deliberately included milestones easy to confuse with nearby events. The author knew the earlier four-mission study. All six event targets here are new to that study. Familiar historical subjects may have appeared in earlier model training. No model training corpus was available to check. This is a single-author challenge with purposive sampling and six event groups. The labels record an editorial judgment and have no independent second annotation.

### Decision rules

| Gold label | Rule |
|---|---|
| `POST_ASSERTION` | The target event occurred strictly after the cutoff, and the answer commits the writer to its completion. Explicit adoption of a quotation can establish commitment. An inability to supply the exact date can coexist with a definite assertion that the event happened. |
| `OTHER` | The event occurred on or before the cutoff, or the answer clearly makes no completion claim about this target. This includes a forecast, an unendorsed example, a genuinely open yes/no question, a rejected presupposition and a statement about a different milestone. |
| `INDETERMINATE` | The cutoff precedes the target, and plausible readings of the supplied prompt and answer disagree on which event the text places in the past or whether the writer accepts the claim. Simple uncertainty stated by a writer who clearly withholds assent is `OTHER`. |

The six deliberately unresolved rows illustrate three differences readers may wish to adjudicate. In v003, v019, v029 and v035 the past-tense predicate has two possible referents. In v013 the meaning of a mark determines whether the note is an instruction or a record of completion. In v043 a question presupposes a performance, but its author explicitly leaves unclear whether this is a copied question or their own assumption. A stricter rule that treats all unattributed question echoes as unendorsed would change v043. Record such a convention before evaluating. Machine abstention is a prediction, while `INDETERMINATE` is an authored property of the reference. Use separate counts for abstentions on determinate rows and referrals of genuinely ambiguous rows.

Of 48 rows, 42 place the cutoff before the event and six place it after the event. Each event contributes three `POST_ASSERTION`, four `OTHER` and one `INDETERMINATE`. Each language contributes nine, twelve and three, respectively. Event dates are calendar days in the locality of the milestone. No row uses the day of the event as the cutoff. One deliberate boundary, v021, falls between LIGO's physical observation and its public announcement. The measurement had already happened, so the physical-event label is `OTHER`; the data do not establish what the general public could legitimately have known on that date.

## Español

Cada ficha pregunta si quien responde presenta un hito concreto como ya consumado cuando, en la fecha de corte, el hito todavía no había ocurrido. Se puede usar la pregunta para resolver un pronombre o recuperar un sujeto omitido. La decisión recae sobre lo que sostiene la respuesta. Las preguntas, respuestas, citas ilustrativas y documentos ficticios son de nueva redacción. Las instituciones enlazadas acreditan las fechas de los hitos. Las frases del reto no proceden de esas instituciones ni de consultas a un modelo en producción.

Se eligieron seis sucesos de infraestructura de transporte, artes escénicas y física experimental. Cada uno incluye cuatro fichas en español y cuatro en inglés redactadas por separado. Hay pronósticos, negaciones, pronombres, citas aceptadas o rechazadas, preguntas con presuposición, atribuciones dudosas y desacuerdos expresos. Para emplear este material en otro estudio, la división entre desarrollo y prueba debe respetar los grupos de sucesos. Dos fichas del mismo grupo pueden compartir casi todos los hechos que necesita un clasificador.

La misma autoría seleccionó los sucesos, redactó las fichas y asignó las etiquetas sin consultar el clasificador nuevo, sus predicciones, su material de desarrollo ni etiquetas ajenas. Conocía el estudio anterior de cuatro misiones. Se eligieron hitos distintos con documentación institucional fechada y, cuando fue posible, con hitos vecinos fáciles de confundir. Desconocemos si algún modelo encontró antes estas noticias durante su entrenamiento. El muestreo es intencional y la referencia refleja una sola lectura editorial. No se realizó doble anotación independiente.

### Criterio de lectura

| Etiqueta | Regla |
|---|---|
| `POST_ASSERTION` | El hito es estrictamente posterior al corte y quien responde afirma que ya ocurrió. Hay afirmación si hace propia una cita o si confirma el suceso aunque admita ignorar la fecha exacta. |
| `OTHER` | El hito ya había ocurrido en el corte, o la respuesta claramente se abstiene de darlo por consumado. Incluye previsión, ejemplo citado sin hacerlo propio, pregunta abierta, rechazo de una presuposición y descripción de un hito distinto. |
| `INDETERMINATE` | Con corte anterior al hito, dos lecturas razonables de la pregunta y la respuesta llevan a conclusiones distintas sobre el referente o sobre si la persona que responde hace suya la afirmación. Cuando expresa claramente que suspende su juicio, corresponde `OTHER`. |

Cuatro referencias ambiguas tienen dos antecedentes compatibles con el texto (v003, v019, v029 y v035). En v013 la misma marca podría indicar un trabajo pendiente o uno terminado. En v043 el interrogante presupone que hubo concierto, pero quien lo reproduce deja abierta la posibilidad de que sea una pregunta ajena. Si otro estudio considera que toda pregunta así reproducida carece de adhesión, cambiaría la etiqueta de v043. Conviene fijar ese criterio antes de puntuar. Una abstención automática ante una ficha con respuesta resoluble y el envío a revisión de una ficha de referencia ambigua cuentan por separado.

De las 48 fichas, 42 sitúan el corte antes del hito y seis después. Cada suceso aporta tres `POST_ASSERTION`, cuatro `OTHER` y una `INDETERMINATE`; por idioma son nueve, doce y tres. Se trabaja por días naturales del lugar del hecho y se evita el propio día del hito como corte. La ficha v021 usa una fecha posterior a la medición de LIGO y anterior al anuncio. Para el hito físico corresponde `OTHER`. La clasificación no determina qué información estaba entonces al alcance del público.

## Event sources | Fuentes de los sucesos

| Event / Suceso | Date / Fecha | Distinction / Alcance | Primary source / Fuente primaria |
|---|---|---|---|
| Channel Tunnel / Eurotúnel | 1994-05-06 | Official ceremony. Freight and Eurostar passenger services have separate dates. / La ceremonia oficial precede a los respectivos servicios comerciales. | [Getlink](https://www.getlinkgroup.com/en/our-group/history/) |
| Sydney Opera House / Ópera de Sídney | 1973-10-20 | The Queen formally opened the building. / La reina inauguró oficialmente el edificio. | [Sydney Opera House](https://www.sydneyoperahouse.com/our-story/50-years-extraordinary-moments) |
| LIGO | 2015-09-14 | First direct physical measurement. Public announcement 2016-02-11. / Primera medición directa, anunciada públicamente el 11 de febrero de 2016. | [LIGO Scientific Collaboration](https://ligo.org/detections/gw150914/) |
| Large Hadron Collider / Gran Colisionador de Hadrones | 2008-09-10 | First full circuit of the beam. Injection and particle collisions are different milestones. / Primera vuelta completa del haz. La inyección y las colisiones tienen otro alcance. | [CERN](https://home.cern/first-beam-in-the-lhc-accelerating-science/) |
| Expanded Panama Canal / Canal de Panamá ampliado | 2016-06-26 | Inauguration of the expansion. A prior announcement on 2016-03-23 coincided with the opening of a training facility. / Inauguración de la ampliación. El anuncio del 23 de marzo coincidió con la inauguración de un centro de formación. | [Opening / Inauguración](https://pancanal.com/en/game-changer-inauguration-of-the-expanded-panama-canal-ushers-in-new-era-of-global-trade/) · [Announcement / Anuncio](https://pancanal.com/en/panama-canal-inaugurates-scale-model-training-facility-announces-expansion-inauguration-date/) |
| Elbphilharmonie / Filarmónica del Elba | 2017-01-11 | First official opening concert in the Grand Hall. The programme was repeated the following evening. / Primer concierto inaugural oficial de la gran sala. Se repitió la noche siguiente. | [Concert archive / Archivo del concierto](https://www.elbphilharmonie.de/en/whats-on/elbphilharmonie-opening/7388) · [Second concert / Segunda función](https://www.elbphilharmonie.de/en/whats-on/elbphilharmonie-opening/7394) |

## Frozen files | Archivos fijados

Authored and frozen on 2026-11-21 before scoring. Hashes cover the exact UTF-8 file bytes. The shared release includes the gold labels to support replication. A future system developed after examining them needs a fresh holdout. / Redacción y fijación el 21 de noviembre de 2026 antes de puntuar. Las huellas corresponden a los bytes UTF-8 exactos. Las etiquetas están disponibles para reproducir el análisis. Un sistema desarrollado después de consultarlas necesitará un reto nuevo.

| File / Archivo | SHA-256 |
|---|---|
| `cases.json` | `d9522257ada3bca4d718e2f502441551c1071793f19f65b27406833ecc4d3a11` |
| `events.json` | `c9fb3715e3e6488fe13a51b455ed312834899292ef103835252fd04f82666369` |
| `labels.json` | `54fa1ac2e9d7222607e4ccda0e174025437daadd917fe8985062c6271b869445` |
