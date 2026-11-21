# Auditoría temporal de las respuestas de IA · Temporal auditing of AI outputs

**Rubén Abella · SPE Audit**  
Edición de investigación 1.1 · Research edition 1.1 · 21 noviembre / November 2026

| Leer y explorar | Español | English |
|---|---|---|
| Volumen integrado · Complete volume | [PDF completo en español](FULL_ES.pdf) | [Full English PDF](FULL_EN.pdf) |
| Suplemento 1.1 · Supplement 1.1 | [PDF](SUPPLEMENT_ES.pdf) · [Markdown](SUPPLEMENT_ES.md) | [PDF](SUPPLEMENT_EN.pdf) · [Markdown](SUPPLEMENT_EN.md) |
| Casos y predicciones · Cases and predictions | [Demo en español](https://www.spetrace.com/es/research/temporal-audit) · [Explorador sin conexión](explore/README.md) | [English demo](https://www.spetrace.com/research/temporal-audit) · [Offline explorer](explore/README.md) |
| Resultados por caso · Case-level results | [Decisiones](results/decisions.csv) · [Comparación de modelos](results/learned_metrics.json) | [Decisions](results/decisions.csv) · [Model comparison](results/learned_metrics.json) |
| Fuentes y comunicación · Sources and communication | [Método de búsqueda](sources/fuentes_es.md) · [Diapositivas](outreach/slides_es.pdf) | [Search method](sources/fuentes_en.md) · [Slides](outreach/slides_en.pdf) |

## Español

**¿Qué podía afirmarse en una fecha y qué conserva la aplicación para que alguien lo compruebe?** En 48 respuestas nuevas sobre seis sucesos, 18 afirmaron un desenlace posterior, 24 sirvieron de controles y seis quedaron indeterminadas según la referencia. El detector anual detectó 0 de los 18 positivos. La regla de proposiciones detectó uno, emitió una falsa alarma y remitió 24 de 48 a revisión. El clasificador de n-gramas detectó 11 positivos con seis falsas alarmas entre los controles, además de tres alertas en casos indeterminados. El pequeño modelo neuronal decidió nueve casos y detectó cero positivos. Los resultados sobre 112 ejemplos traducidos se presentan por separado. Los corpus son construidos y los ensayos no estiman una tasa de error para servicios desplegados.

### Reproducir sin conexión

Extrae el paquete completo o clona el repositorio. Conserva juntos los directorios hermanos `v11/`, `study/`, `field/`, `assets/` y el verificador 1.0 `verify.py`. Desde `research/temporal-audit/`, usa Python 3.10 o posterior:

```sh
python3 v11/verify_v11.py
```

En Windows con el lanzador Python, ejecuta `py -3 v11/verify_v11.py`. El programa verifica las huellas de los ficheros distribuidos, las pruebas y capturas 1.0, los clasificadores congelados, las decisiones por idioma, la robustez, los costes, el expediente intradía y las pruebas de revisión. Vuelve a ejecutar las 360 llamadas locales del ensayo con códigos ficticios y compara sus salidas byte por byte. Reconstruye también el explorador y comprueba el contenido de su ZIP. No necesita cuentas, una API o acceso a internet. Los tests de la mesa de revisión abren un puerto efímero de loopback en el propio equipo.

OpenSSL 3 permite verificar la prueba RFC 3161 con certificados locales temporales. Node.js permite comprobar las interacciones de las interfaces. Los tests informan si se omite alguna de esas comprobaciones. Para repetir además el entrenamiento neuronal añade `--retrain`; el entorno de referencia empleó Python 3.12 y NumPy 2.3.5. Otros entornos numéricos pueden producir diferencias de bytes. La generación editorial de los PDF usa herramientas adicionales. [Instrucciones de maquetación](report/README.md)

Para verificar una copia de confianza del índice, añade `--manifest-sha256 HUELLA` con la huella de `SHA256.json` guardada por otra vía. El índice incluido permite detectar diferencias frente a la edición que enumera. Un índice guardado solo con los datos carece de testigo independiente de fecha u origen. Los PDF y las presentaciones se comprueban por su huella de distribución. El verificador reconstruye el paquete de depósito y comprueba que contiene los dos volúmenes integrados, la autoría personal, el DOI y el alcance de las licencias aprobadas.

### Alcance

La mesa de revisión y el protocolo permiten recoger decisiones humanas futuras. El análisis publicado puntúa una lectura asistida por IA previamente archivada; los tiempos y revisores de las pruebas son simulados. El expediente demuestra qué bytes recibió un emisor local. Cuando una vía alternativa proporciona el código, este aparece aun cuando el documento está ausente. La observación no establece causalidad dentro de un proveedor remoto. El verificador de sellos se probó con una autoridad local; la prueba de pertenencia de Merkle sí se ejecuta. Los diseños de conocimiento cero y atestación de hardware se describen como propuestas. [Protocolo del lector](reader/protocol.md) · [Evidencia](evidence/evidence_es.md) · [Intervenciones](interventions/interventions_es.md)

## English

**What could be asserted on a given date, and what evidence survives for someone to check?** The 48 newly authored responses concern six events. The reference labels identify 18 assertions of a later outcome, 24 controls and six indeterminate cases. The year rule detected none of the 18 positives. The proposition rule detected one, raised one false alarm and referred 24 of 48 cases. The n-gram classifier detected 11 positives, with six false alerts on controls and three alerts on indeterminate cases. The small neural model made nine decisions and detected no positives. The separate translation replay uses 112 previously public examples. These constructed corpora do not estimate error rates for deployed services.

### Reproduce offline

From `research/temporal-audit/`, run `python3 v11/verify_v11.py`, or `py -3 v11/verify_v11.py` with the Windows Python launcher. Use Python 3.10 or newer. Keep the entire research package together, including the 1.0 `verify.py` and sibling `v11/`, `study/`, `field/` and `assets/` directories. The verifier checks the files against their distribution digests, runs the test suites, executes the 1.0 captures and recount, and regenerates the main results, learned-model decisions, language and robustness analyses, costs and intraday evidence. It performs 360 fresh local subprocess calls and compares the generated result files byte for byte. It rebuilds the explorer's data and checks the contents of its offline ZIP. These steps use no account, paid API or external network connection. The desk tests open an ephemeral loopback server on the local machine.

OpenSSL 3 enables the local RFC 3161 fixture. Node.js enables the interface harnesses. The test output reports skips when those tools are unavailable. Add `--retrain` to refit neural weights on the reference NumPy stack; the original environment used Python 3.12 and NumPy 2.3.5. Other numerical environments can produce different bytes. Add `--manifest-sha256 DIGEST` to check the manifest against an independently retained copy of its digest. A manifest and data published together do not establish independent time or origin. The PDFs and slide decks are checked against their distribution digests. The deposit archive is rebuilt and its two complete volumes, personal authorship, DOI and licensing scope are checked. PDF typesetting has separate dependencies. [PDF build instructions](report/README.md)

The published reader score reuses one archived AI-assisted reading. Desk and review tests use simulated sessions, with no human times or human performance measurements. The source intervention measures a local sender. The alternative-input control reproduces its target even when the target document is absent. The Merkle inclusion proof and local timestamp-verification fixture run in this edition. Zero-knowledge and hardware-attestation designs are proposals. [Reader protocol](reader/protocol.md) · [Evidence](evidence/evidence_en.md) · [Interventions](interventions/interventions_en.md)

## Autoría, identificador y derechos · Authorship, identifier and rights

Rubén Abella es el autor. SPE Audit identifica el proyecto. El 21 de noviembre de 2026 se publicaron en Zenodo las ediciones integradas en español e inglés. Ambas se encuentran en el registro con DOI de versión **10.5281/zenodo.24424024**. El texto y las figuras originales del artículo se ofrecen bajo CC BY 4.0. Las marcas y los materiales de terceros conservan su régimen propio. El software está sujeto a las condiciones de Business Source License 1.1 del repositorio. [Registro público de Zenodo](https://zenodo.org/records/24424024) · [DOI de versión](https://doi.org/10.5281/zenodo.24424024) · [Ficha del depósito](deposit/metadata-paper.json) · [Licencia del artículo](https://creativecommons.org/licenses/by/4.0/) · [Licencia del software](../LICENSE)

Rubén Abella is the author. SPE Audit identifies the project. Zenodo published the integrated Spanish and English editions on 21 November 2026. Both volumes are available under version DOI **10.5281/zenodo.24424024**. The original article text and figures are released under CC BY 4.0. Trademarks and third-party material retain their respective terms. Software is subject to the repository's Business Source License 1.1 and its terms. [Public Zenodo record](https://zenodo.org/records/24424024) · [Version DOI](https://doi.org/10.5281/zenodo.24424024) · [Deposit guide](deposit/README_ES.md) · [Article licence](https://creativecommons.org/licenses/by/4.0/) · [Software licence](../LICENSE)
