# Qué cambió entre los 96, 16 y 48 casos

**Rubén Abella · SPE Audit. Análisis retrospectivo posterior a la edición 1.1.**

En las 96 respuestas construidas que se conocían durante el desarrollo, la regla de proposiciones 1.1 detectó 30 de 32 afirmaciones positivas. En un reto de 16 respuestas sobre los mismos cuatro sucesos detectó 4 de 8. En las 48 respuestas nuevas, sobre seis sucesos distintos, detectó 1 de 18. Las cifras describen tres diseños. Cambian los sucesos, la redacción, el reparto de idiomas, el inventario de predicados y la presencia de referencias indeterminadas. No permiten identificar cuál de esos cambios explica la diferencia, ni diagnosticar por sí solos sobreajuste o un efecto del dominio.

## Comparar reglas exige comprobar qué información recibieron

Se reprodujeron las 160 decisiones archivadas, incluidos sus motivos y las trazas por cláusula, a partir de los programas y entradas cuyas huellas figuran en el inventario. Un positivo de referencia afirma como consumado un desenlace posterior al corte. Las remisiones a revisión cuentan en el denominador de sensibilidad. Las falsas alertas se calculan sobre controles determinados. Las decisiones automáticas sobre referencias indeterminadas se conservan por separado.

| Cohorte | Método | Positivos detectados | Falsas alertas en controles | Remitidos a revisión |
|---|---|---:|---:|---:|
| 96 construidas | Año 1.0 | 4/32 | 12/64 | 0/96 |
| 96 construidas | Fechado 1.0 con sus fichas originales | 24/32 | 0/64 | 12/96 |
| 96 construidas | Proposiciones 1.1 | 30/32 | 0/64 | 2/96 |
| 16 de redacción nueva, sucesos conocidos | Año 1.0 | 1/8 | 2/8 | 0/16 |
| 16 de redacción nueva, sucesos conocidos | Fechado 1.0 con sus fichas originales | 0/8 | 0/8 | 14/16 |
| 16 de redacción nueva, sucesos conocidos | Proposiciones 1.1 | 4/8 | 0/8 | 5/16 |
| 48 de sucesos nuevos | Año 1.0 | 0/18 | 2/24 | 0/48 |
| 48 de sucesos nuevos | Fechado 1.0 con sus fichas originales | Sin entrada válida | Sin entrada válida | 0 ejecuciones históricas |
| 48 de sucesos nuevos | Proposiciones 1.1 | 1/18 | 1/24 | 24/48 |
| 48 de sucesos nuevos | Código fechado 1.0 con vocabulario 1.1, transferencia posterior | 2/18 | 1/24 | 41/48 |

### El hueco en la comparación original y el ensayo posterior

El contrato de la regla fechada exige una fecha de suceso y una lista de expresiones literales en el campo `affirmed_phrases`. Sus cuatro fichas son Perseverance, DART, OSIRIS-REx y Rosetta. Ninguna de las seis fichas nuevas pertenece a ese inventario. El protocolo de la edición 1.1 limitó esta comparación a los sucesos originales y cada una de las 48 filas archivadas carece de la decisión nativa correspondiente. Una celda vacía significa «no ejecutado con el inventario original». Asignarle cero aciertos sobre 18 convertiría falta de soporte en una predicción ficticia.

Para obtener una comparación exploratoria se conservó sin cambios el código 1.0. Se entregó como `affirmed_phrases` la lista **completa y literal** de `outcome_terms` que ya figuraba en la ficha 1.1 correspondiente. No se introdujeron sinónimos, conjugaciones nuevas, traducciones o excepciones. Se conservó la fecha original y se pasaron los textos y cortes publicados. El programa produce las decisiones antes de unirlas con las referencias, pero esta decisión analítica se tomó después de que los resultados 1.1 fueran públicos. Además, el campo nuevo describe vocabulario de resultados y no necesariamente una afirmación consumada. Estos resultados deben citarse como transferencia posterior de diccionario.

Los dos aciertos de esa transferencia fueron en inglés. En v033 coincidió la subcadena «inaugurate» y en v044 «perform». La única falsa alarma, v011, contiene «inaugurar» en una pregunta seguida de una frase declarativa que explica que la pregunta queda abierta. El texto completo no acaba con signo de interrogación y supera esa comprobación inicial del programa. El ensayo remitió 16/18 positivos, 19/24 controles y las seis referencias indeterminadas a revisión. El único acierto de 1.1 ocurrió en otra fila, v009. En este conjunto, que un método logre dos aciertos y el otro uno no establece una superioridad general.

## Qué dicen las trazas de 1.1 sobre las 48 filas

| Suceso o idioma | Aciertos / positivos | Falsas alertas / controles | Remitidos / casos | Indeterminados que recibieron «otro» |
|---|---:|---:|---:|---:|
| Apertura ceremonial del túnel del Canal | 0/3 | 0/4 | 6/8 | 0/1 |
| Apertura de la Ópera de Sídney | 1/3 | 0/4 | 2/8 | 1/1 |
| Detección de LIGO | 0/3 | 0/4 | 3/8 | 1/1 |
| Primera vuelta del LHC | 0/3 | 0/4 | 4/8 | 0/1 |
| Ampliación del canal de Panamá | 0/3 | 1/4 | 5/8 | 0/1 |
| Concierto de apertura de Hamburgo | 0/3 | 0/4 | 4/8 | 1/1 |
| Inglés | 0/9 | 0/12 | 12/24 | 1/3 |
| Español | 1/9 | 1/12 | 12/24 | 2/3 |

Todos los 17 positivos que 1.1 dejó de detectar fueron remitidos. En 16, la regla devolvió `insufficient_proposition_evidence`. De esos 16, doce carecen de señal de predicado exacto o flexionado en las cláusulas y cuatro sí contienen una señal que no llegó a producir una afirmación resuelta. El reparto de esos doce y cuatro casos fue de ocho y uno en inglés y de cuatro y tres en español. El decimoséptimo positivo remitido fue v027, en español sobre el LHC. La segunda cláusula señalaba un predicado flexionado y morfología de finalización, pero puntuó 4 con umbral 5. La detección de v009, en español sobre Sídney, puntuó 7 al asociar predicado, forma de finalización, marcador asertivo y referencia explícita a Bennelong Point.

De los tres positivos de referencia por suceso, ninguno de los tres ejemplos de LIGO registró una señal de predicado. Dos positivos del túnel del Canal, dos de Panamá y dos de Hamburgo tampoco la registraron; el positivo restante de cada uno de esos sucesos sí tuvo una señal, pero la regla dejó la proposición sin resolver. Sídney tuvo un positivo detectado, otro sin resolver con señal y otro sin señal. El LHC tuvo dos positivos sin señal y el candidato que quedó por debajo del umbral.

La falsa alarma v038, en español sobre Panamá, puntuó 6 por la cláusula que repetía la premisa de una pregunta. El clasificador dejó sin resolver «No acepto esa premisa». El error se puede localizar y discutir frase por frase. No hace falta atribuir a la regla una intención o a los textos una dificultad general superior. Ninguna de las seis referencias indeterminadas recibió una alerta 1.1; tres recibieron «otro» y tres pasaron a revisión. Los subconjuntos inglés y español de esta cohorte son textos distintos, no traducciones emparejadas. La tabla por suceso e idioma incluye grupos de solo cuatro filas.

**Para una presentación.** «Las trazas nos permiten explicar por qué el programa remitió una frase o activó una alerta en estos ejemplos. Para separar el efecto del idioma, del cambio de sucesos o de la selección de vocabulario necesitaríamos un diseño que varíe cada factor con los demás controlados.»

Desde esta carpeta puede ejecutarse `python3 -B analyze.py` para cotejar las diez salidas distribuidas. Con `--out DIRECTORIO` se obtiene otra copia. [Cohortes y denominadores](cohorts.csv) · [Suceso e idioma](strata.csv) · [Motivos por estrato](reasons.csv) · [Trazas de las 160 respuestas](row_traces.csv) · [Inventario de entradas](inputs.json) · [Protocolo de retrotraducción](backtranslation.md)
