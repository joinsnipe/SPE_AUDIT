# Archived prompt-only pilot · Piloto histórico basado en instrucciones

## English

An application log dated 10 May 2026 records five English questions sent to five named configurations under a 1 June 2023 cutoff. Each request instructed the assistant to respect the cutoff. No retrieval corpus accompanied the request. The public extract labels the configurations A–E consistently across questions. The available record does not independently attest provider identity, model revisions or the bytes seen by the provider.

| Subject of question | Texts | HTTP 429 | Archived keyword alarms | Public year-rule alarms |
| --- | ---: | ---: | ---: | ---: |
| OpenAI leadership | 4 | 1 | 0 | 0 |
| Boeing door plug | 5 | 0 | 0 | 0 |
| Bankman-Fried sentencing | 5 | 0 | 1 | 0 |
| UBS and Credit Suisse | 4 | 1 | 0 | 0 |
| Silicon Valley Bank | 4 | 1 | 0 | 0 |
| **Total** | **22** | **3** | **1** | **0** |

The old per-answer rule required two event-specific keywords and the preassigned POST category. Its event-level evaluator put every PRE event into a category counted as a true negative. The event-level precision reported at the time is uninformative about response-level accuracy. We also applied the public SPE detector to each complete returned text using its four-digit-year extractor, cutoff year 2023 and no post-cutoff retrieval context. A future date *within* 2023 is invisible to this year comparison.

Four cases explain why the counts matter:

- The only alarm counted keywords for prison and sentencing in a response denying a sentence had occurred. The question had already asked for the final prison sentence. The sentencing actually occurred on 28 March 2024. [US Department of Justice](https://www.justice.gov/archives/opa/pr/samuel-bankman-fried-sentenced-25-years-his-orchestration-multiple-fraudulent-schemes)
- A different response to that question stated that trial and sentencing had occurred after the cutoff. It did not give the penalty. Both rules missed that retrospective assertion. The question itself invited hindsight, so the source of the assertion cannot be attributed to the model's training.
- One answer described a preflight event in early 2021. That description conflicts with the date and circumstances of the target Alaska Airlines incident on 5 January 2024. It may be a confabulated or conflated account. Checking one target does not establish whether some other 2021 incident existed. [NTSB investigation](https://www.ntsb.gov/investigations/Pages/DCA24MA063.aspx)
- One control response said that UBS “subsequently acquired Credit Suisse”. Swiss authorities announced the takeover agreement in March, but UBS announced legal completion on 12 June, after the cutoff. An answer using “acquired” informally for the March agreement is ambiguous. Three other responses described an agreement. [FINMA, 19 March](https://www.finma.ch/en/news/2023/03/20230319-mm-cs-ubs/) · [UBS, 12 June](https://www.ubs.com/global/en/media/display-page-ndp/en-20230612-ubs-credit-suisse-acquisition.html)

Nine answers repeat a generic abstention. The other two short abstentions with prompt echoes are indexed separately. No precision, sensitivity or prevalence estimate is inferred from this purposive prompt set.

Run `python3 recount.py` in this directory to recompute both counts from the released per-answer observations. The data file stores the complete list of detected keywords and explicit years, a SHA-256 digest of each original UTF-8 response string, an editorial paraphrase and four short excerpts. Only the field `short_verbatim_excerpt` reproduces original response text. The public extract enables independent recounting; independent extraction of every feature from full texts would require access to the original log. The small sample, multiclaim answers and lack of an independently annotated full transcript preclude an accuracy comparison. The three errors provide no predictions. Historical reporting is separate from the controlled experiment.

## Español

El registro de la aplicación del 10 de mayo de 2026 contiene cinco preguntas en inglés enviadas a cinco configuraciones bajo un corte de 1 de junio de 2023. Cada petición indicaba el límite temporal mediante una instrucción, sin documentos de recuperación. Las letras A–E identifican la misma configuración en las cinco preguntas. El registro no verifica independientemente la identidad del proveedor, la revisión del modelo ni los bytes que recibió el servidor.

De 25 intentos se conservaron 22 respuestas y tres errores HTTP 429. La tabla anterior presenta los recuentos por pregunta. La regla histórica de palabras clave produjo una alerta; la regla anual del motor público, aplicada después a las respuestas completas, produjo cero. La primera exigía que el propio evaluador hubiera etiquetado el suceso como posterior. El agregado por suceso contaba todos los controles anteriores como negativos correctos. La segunda solo comparaba los años explícitos con 2023, lo que deja sin resolver los meses de ese mismo año.

La única alarma correspondía a una respuesta que negaba que hubiera una sentencia. La pregunta ya mencionaba una pena de prisión. Otra respuesta sí afirmó que el juicio y la sentencia ocurrieron después del corte, sin precisar la pena. Ninguna regla marcó esa afirmación. Una tercera respuesta describió un incidente en tierra en 2021, incompatible con el caso documentado en vuelo en 2024. Ello admite confusión o invención y no prueba que el modelo usara hechos futuros. Entre los controles, una respuesta habló de una adquisición ya realizada. El acuerdo entre UBS y Credit Suisse se anunció antes del corte, mientras que su cierre jurídico ocurrió después. Las fuentes primarias están enlazadas arriba.

Nueve respuestas se limitaron a una abstención genérica. Otras dos reprodujeron términos de la pregunta al abstenerse. El anexo conserva rasgos por respuesta, paráfrasis editoriales, cuatro fragmentos identificados como literales y las huellas de los textos completos. Desde este directorio, `python3 recount.py` reproduce los dos recuentos a partir de los rasgos públicos. Para extraer otra vez todos los rasgos del texto íntegro haría falta el registro original. Los cinco casos seleccionados no permiten estimar la precisión ni la prevalencia de una filtración.
