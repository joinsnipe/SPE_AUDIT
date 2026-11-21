# De la señal a la decisión · From signal to disposition

**Rubén Abella · SPE Audit.** Este análisis posterior reproduce decisiones sobre las mismas 48 respuestas publicadas. Separa la sugerencia automática, la derivación y el cierre. La referencia del estudio puede ser `INDETERMINATE`. La cola operativa usa `PENDING_REVIEW` mientras falta una decisión. Tras revisar, una persona puede conservar `indeterminate` como resolución fundamentada. Aquí no se ha observado ninguna respuesta humana.

| Política | Pendientes / 48 | Alertas acertadas / 18 | Falsas alertas / 24 controles | Indeterminados cerrados automáticamente / 6 | Pérdida ilustrativa |
|---|---:|---:|---:|---:|---:|
| Regla congelada | 24 | 1 | 1 | 3 | 78 |
| Consultar la lectura archivada solo al abstenerse la regla | 3 | 18 | 1 | 3 | 57 |
| Exigir dos señales determinadas coincidentes para cerrar | 28 | 1 | 0 | 0 | 28 |
| Disputa individual, todas las disposiciones pendientes | 48 | 0 | 0 | 0 | 48 |

La tercera política consulta ambos registros en **todos** los casos. Una abstención o discrepancia deja la ficha pendiente. Captura la autocorrección de `v038` por discrepancia y mantiene pendientes los seis casos indeterminados. También remite 17 positivos y cuatro controles que la lectura archivada por sí sola clasificó correctamente. La etiqueta de referencia solo se abre después de escribir las decisiones de enrutamiento en memoria. En la cuarta política elegimos exigir revisión humana para todos los cierres cuando hay una disputa individual, con independencia de la sugerencia del sistema. La decisión corresponde a la organización en su contexto.

La pérdida reproduce el perfil administrativo ilustrativo del estudio: 12 unidades por falsa alerta, 25 por positivo cerrado como otro, 14 por indeterminado cerrado y 1 por derivación. Ese modelo de costes asigna el mismo coste a todas las derivaciones y cero al cómputo de leer un caso. Las 48 lecturas aquí reutilizadas consumieron recursos. Para estimar un presupuesto faltan el coste marginal del lector y tiempos humanos observados. El resultado de la regla de acuerdo se conoce después de ver estas 48 filas y depende de una lectura exploratoria ya archivada. Compartir errores entre los métodos permitiría dos señales iguales y equivocadas.

## English

A signal proposes a reading. A disposition determines whether a case remains pending. The agreement policy closes only if both signals give the same determinate answer. On these 48 already public cases it deferred 28, detected one positive automatically and closed zero reference-indeterminate cases. The earlier cascade deferred three, passed through the false alert on v038 and automatically closed three indeterminate cases. The individual-dispute illustration keeps all 48 decisions pending for human review. Its cost of 48 is measured in hypothetical loss units. Neither human accuracy nor person-minutes was observed. The agreement policy was designed after inspection of this data; correlated errors affect its usefulness on future cases.

Run `python3 replay.py --out /path/to/empty-directory` and compare with [case-level routes](routes.csv) and [summary](summary.json). Inputs are the frozen rule signals and recorded reader answers from the [reference publication](https://doi.org/10.5281/zenodo.24424024).
