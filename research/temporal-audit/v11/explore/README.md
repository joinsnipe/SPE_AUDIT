# The cutoff date · La fecha de corte

**Rubén Abella · SPE Audit**

Open `site/index.html` in a current browser, or extract `offline.zip` and open `spe-audit-explore/index.html`. Use `?lang=en` or the language control for English. Every interactive function, the original SPE Audit logo, the case table and the CSV are local. The optional document, DOI and institutional-source links open external resources. No API key, model, analytics, third-party scripts, fonts, backend or network connection is needed to run the experiment. Serve the contents of `site/` from any static host to deploy the same edition.

Abre `site/index.html` en un navegador actual o descomprime `offline.zip` y abre `spe-audit-explore/index.html`. La edición arranca en español y permite cambiar de idioma. Los datos, el logotipo, el cálculo de las huellas y las interacciones se incluyen en la descarga. Los enlaces documentales y de fuentes son opcionales y externos. Para desplegar la edición, sirve los archivos de `site/` como un sitio estático.

## What is being compared / Qué se compara

The four missions use the original publication-date cards from `study/data/events.json`. The cutoff includes the selected day. A local sender takes the actual canonical UTF-8 request bytes, parses them and returns the latest supplied card by `(date, id)`, or the original English fallback if there is no eligible card. The study deliberately uses a DART report published the day after impact. The day of the event and the day a particular source reported it can be inspected separately.

Cada misión tiene como referencia la captura publicada de la condición `after` en `study/results/capsules.jsonl`, cuya línea se indica en pantalla. Cambiar el corte vuelve a ejecutar el emisor y reemplaza cualquier edición manual por su salida. El registro de la prueba de integridad incluye las huellas SHA-256 de los bytes UTF-8 de la petición y de la respuesta; el sello se calcula sobre el registro canónico sin su propio campo `record_sha256`. «Añadir un byte» agrega un solo espacio ASCII al final de la respuesta. Se comparan los bytes y las huellas con la referencia publicada. Si se sospecha una sustitución de toda la publicación, hace falta una referencia conservada por separado.

The synthetic canary compares two calls with the same prompt and cutoff. One has no card, and the other has one fictional card with a harmless marker. The evidence is about this particular local sender. It provides no provider-side receipt and makes no causal claim about a live model.

Las 160 filas corresponden a 96 ejemplos construidos, 16 del desafío anterior y 48 del nuevo reto bilingüe. La tabla conserva las decisiones de `v11/results/decisions.csv`, añade la pregunta, la respuesta y el corte originales, y une las 48 decisiones de la lectura semántica mediante los identificadores enmascarados del experimento. Las filas son textos redactados para evaluar métodos. El CSV de la web contiene las 160 fichas con las columnas expuestas; se abre sin conexión. Los paquetes públicos ya vistos no sirven como casos inéditos para la revisión humana.

## Build and verify / Reproducir y verificar

From the root of the temporal-audit research package / Desde la raíz del paquete de auditoría temporal:

```sh
python3 v11/explore/build.py
node v11/explore/verify.js
```

The build uses Python 3.10+ and the standard library. It verifies all original seals and reconstructs the original twelve interventions before writing the browser dataset and CSV, copying the logo and generating the offline ZIP with fixed entry metadata. Static HTML, CSS and first-party JavaScript are maintained directly under `site/`. Node 18+ is used only for the checks. Opening the site requires neither Python nor Node. The checks compare all 124 canonical requests and complete records with the original Python archive, replay all twelve interventions, test both hash implementations, exercise cutoff and editing controls through a DOM harness, and verify both languages, result navigation and local asset references.
