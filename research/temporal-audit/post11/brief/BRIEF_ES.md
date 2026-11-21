# Una inferencia reproducible puede repetir un error

**Rubén Abella · SPE Audit · 21 de noviembre de 2026**

Nota de investigación posterior al depósito. El DOI enlaza el artículo de referencia. [Artículo depositado en Zenodo](https://doi.org/10.5281/zenodo.24424024) · [Sección pública](https://www.spetrace.com/es/research/temporal-audit)

## Dos lecturas de las mismas 48 respuestas

La lectura exploratoria archivada en el artículo coincidió con la referencia editorial en los 18 positivos, los 24 controles y las seis ambigüedades. Se encargó **después** de examinar los resultados agregados de la regla. La nueva ejecución usa un modelo local identificable para preguntar qué ocurre cuando también se fijan y registran los detalles de inferencia. Se reutilizan 48 respuestas de prueba ya públicas, redactadas para el estudio en español e inglés. Son inferencias efectivamente ejecutadas sobre ejemplos construidos.

| Método en los mismos 48 casos | Alerta | Otro | Revisión | Positivos detectados / 18 |
|---|---:|---:|---:|---:|
| Regla de proposiciones 1.1 | 2 | 22 | 24 | 1/18 |
| Lectura exploratoria archivada | 18 | 24 | 6 | 18/18 |
| Nueva inferencia local con plan fijado | 29 | 2 | 17 | 11/18 |

Se fijaron los pesos cuantizados Q4_K_M de SmolLM2-135M-Instruct, el motor llama.cpp b8058, el texto del prompt, la temperatura 0 y la semilla 20261121. El lector recibió el hecho y las fechas de referencia, la pregunta y la respuesta, con identificadores enmascarados y sin etiquetas de evaluación. En dos pasadas, las 48 decisiones, citas seleccionadas e identificadores de evidencia coincidieron. Los cuerpos completos de respuesta diferían por datos de temporización. [Plan, capturas y puntuaciones](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/reference_reader/replay48.zip) · [Lectura archivada](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/v11/results/reader_metrics.json)

El lector local alertó en 13 de los 24 controles y remitió los otros 11 a revisión. No clasificó correctamente como «otro» ninguno de los controles. Sobre las 42 referencias determinadas decidió 26 y acertó 11 de esas 26. En las seis ambiguas emitió cinco alertas y una revisión. Si se compara la etiqueta en los 48 casos, considerando la revisión como coincidencia para una referencia ambigua, el resultado es **12/48**. La repetibilidad de la salida y la concordancia con la referencia miden propiedades distintas. Los porcentajes se limitan a este modelo, este prompt y este conjunto.

## Qué cambia con extractos de terceros

El segundo conjunto consta de 17 extractos breves en inglés, 167 palabras de 17 páginas, sobre seis acontecimientos públicos. Once páginas proceden del NIST y seis del Servicio Geológico de Estados Unidos. Las agencias escribieron las frases; el estudio eligió las fuentes, fijó fechas de corte contrafactuales y redactó las preguntas y las referencias. Hay cinco positivos, once controles y una referencia ambigua. El ejercicio examina nuevas formulaciones documentadas. La muestra dirigida no estima la frecuencia de errores en usuarios reales ni el acceso de un modelo a fuentes anteriores. [Fuentes y enlaces a los pasajes](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/external/source_index.json) · [Referencias por extracto](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/external/labels.json)

| Mismos 17 extractos | Positivos detectados / 5 | Decisiones sobre 16 determinados | Errores en esas decisiones | Salida ante el ambiguo |
|---|---:|---:|---:|---|
| Regla anual | 0/5 | 16 | 5 | Otro |
| Proposiciones 1.1 | 2/5 | 7 | 0 | Otro |
| N-gramas | 3/5 | 16 | 7 | Otro |
| Red de caracteres 1.1 | 0/5 | 7 | 1 | Revisión |
| Lector local fijado | 0/5 | 1 | 1 | Revisión |

La regla de proposiciones acertó en las siete referencias determinadas sobre las que decidió. Dejó nueve determinadas pendientes y cerró la ambigua como «otro». Un recuento limitado a las siete decisiones correctas contaría como resuelta una fracción demasiado amplia del conjunto. El lector local remitió 16 de los 17 extractos y cerró como «otro» un positivo. Solo coincidió con la referencia en el ambiguo: 1/17. Las 17 salidas estructuradas se repitieron en la segunda pasada. [Decisiones de las cuatro líneas de base](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/external/results.json) · [Capturas de la inferencia local](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/reference_reader/external17.zip)

La etiqueta positiva describe una afirmación de un desenlace posterior al corte. Una página que se publicó después puede contener una previsión o negar ese desenlace. Disponer de un texto redactado por terceros mejora la diversidad de origen. La independencia de la etiqueta y la representatividad del muestreo siguen siendo preguntas abiertas.

## Qué queda pendiente al decidir

Se reprodujeron cuatro políticas sobre las 48 respuestas construidas. Las señales de entrada son **la regla 1.1 y la lectura exploratoria archivada**. El lector local nuevo se evalúa aparte. La cascada conserva las decisiones de la regla y consulta la lectura archivada cuando aquella se abstiene. La política de acuerdo comprueba ambas señales en todos los casos y solo cierra ante dos etiquetas determinadas coincidentes. [Rutas de cada expediente](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/escalation/routes.csv) · [Resumen de políticas](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/post11/escalation/summary.json)

| Política | Pendientes / 48 | Alertas correctas / 18 | Alertas falsas en controles | Ambiguos autocerrados / 6 |
|---|---:|---:|---:|---:|
| Regla congelada | 24 | 1 | 1 | 3 |
| Cascada | 3 | 18 | 1 | 3 |
| Acuerdo de ambas señales | 28 | 1 | 0 | 0 |
| Revisión de todos los casos | 48 | 0 | 0 | 0 |

En **v038**, la persona que habla repite la premisa de que se inauguró el canal ampliado de Panamá y después dice «No acepto esa premisa». La regla alerta en la primera frase. La cascada conserva esa falsa alerta. Al exigir acuerdo, la discrepancia mantiene pendiente el expediente. Las seis referencias ambiguas siguen abiertas bajo la política de acuerdo. También quedan pendientes 17 positivos, cuatro controles y el propio control v038. En este ejemplo, una cola más corta admite cierres cuya corrección sigue en disputa. [Abrir el visor público de casos](https://www.spetrace.com/es/research/temporal-audit/review-desk)

**Piloto humano abierto.** El kit contiene 16 casos para dos revisores bilingües, con paquetes separados y una tercera persona para adjudicar desacuerdos tras el sellado. Al abrir la convocatoria se habían observado **cero decisiones y cero minutos humanos**. El visor permite ensayar con soluciones visibles. Quien haya visto un caso debe registrar esa exposición antes de participar en una lectura ciega. Todavía no hay una estimación de acuerdo o tiempo entre personas. [Kit y protocolo del piloto](https://github.com/joinsnipe/SPE_AUDIT/tree/main/research/temporal-audit/post11/open-pilot)
