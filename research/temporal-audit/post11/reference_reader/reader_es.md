# Un lector semántico local reproducible

Este protocolo conserva los bytes enviados a un modelo local de instrucciones, la respuesta que devolvió y la comparación con una referencia custodiada aparte. El lector recibe una pregunta, una respuesta y la ficha de un suceso. La prueba estudia si el texto da por ocurrido un desenlace. La procedencia del conocimiento de quien escribió la respuesta queda fuera de lo que puede establecer esta lectura.

La lectura exploratoria anterior sigue siendo una observación histórica independiente. Sus instrucciones documentadas y sus respuestas permiten recalcular puntuaciones. No se pudo recuperar la versión desplegada del modelo, la serialización completa, los parámetros de generación ni el procesamiento del proveedor. La instrucción científica de este directorio se redactó expresamente para el nuevo experimento. Se publican sus bytes exactos, incluido el salto de línea final. Cada solicitud conserva cómo se incorporó la instrucción en la plantilla. [Instrucción exacta](prompt_v1.txt)

## Configuración congelada

| Componente | Condiciones de estas ejecuciones |
|---|---|
| Modelo | SmolLM2-135M-Instruct. Conversión de QuantFactory en la revisión `476854d00ede130660aba430d15f9347ad2e7d0e`, archivo `SmolLM2-135M-Instruct.Q4_K_M.gguf`. El archivo de 105.454.144 bytes tenía SHA-256 `8030f04528538d47bda434f6f0bdf3952c40a58123e4d5e755332f23731a8684`. |
| Motor | Binario oficial de llama.cpp b8058 para Linux x86-64. Declaró commit `184c694f4`, GNU 11.4.0 y backend de CPU Zen 4. SHA-256 del ejecutable `36a0e300a5f827798fc4ad253ab35e6ceea2b82e4e060ef9fd73397fcf083b50`. Cada plan conserva además las huellas de las bibliotecas contiguas. |
| Inferencia | Un hilo de CPU para inferencia, un hilo de procesamiento por lotes, una ranura, cero capas en GPU y contexto de 4.096 tokens. El ejecutor arranca su propio servidor en un puerto local efímero. No admite un servidor de inferencia remoto. Cada pase arranca un proceso independiente. |
| Muestreo | Temperatura 0, semilla 20261121, máximo 384 tokens de salida. Se desactivaron la transmisión incremental y la caché de instrucciones por solicitud. La respuesta HTTP conserva también los parámetros que declara el motor. |
| Instrucción | `semantic-stance-chatml-v1`. SHA-256 `5378009285a27aee5fd9a6566dd6671d6ab236a036845dda657195c3d7fb9a9d`. Todos los idiomas usaron la misma instrucción en inglés. La ficha del modelo señala el inglés como su idioma principal. |
| Entradas y salida | E1 contiene el suceso, su fecha, el corte inclusivo y el localizador de la fuente. E2 es la pregunta y E3 la respuesta. El modelo elige `POST_ASSERTION`, `OTHER` o `REVIEW`, una cita literal de E3 y los identificadores permitidos de evidencia. No recibe la etiqueta de referencia, ID original, estrato, predicciones previas ni métricas. |

Las fuentes públicas identifican la procedencia del modelo y del motor. La cuantización corresponde a un tercero. El descargador opcional comprueba las huellas de ambos archivos antes de extraerlos o usarlos. La inferencia y la puntuación funcionan localmente. [Modelo original](https://huggingface.co/HuggingFaceTB/SmolLM2-135M-Instruct) · [Cuantización fijada](https://huggingface.co/QuantFactory/SmolLM2-135M-Instruct-GGUF/blob/476854d00ede130660aba430d15f9347ad2e7d0e/SmolLM2-135M-Instruct.Q4_K_M.gguf) · [Distribución del motor](https://github.com/ggml-org/llama.cpp/releases/tag/b8058) · [Protocolo de generación](https://github.com/ggml-org/llama.cpp/blob/b8058/tools/server/README.md)

## Ejecución prospectiva

1. La persona responsable de la referencia debe fijar el criterio de interpretación y las etiquetas por separado. Se puede depositar la huella del archivo ante un tercero o en un repositorio público antes de la inferencia. Las etiquetas quedan en poder de quien puntúa. Documente el origen de los casos, los criterios de inclusión y cualquier solapamiento con datos de desarrollo.
2. Entregue al ejecutor solo los casos y las fichas de los sucesos. El programa copia una lista cerrada de campos, reemplaza los ID con claves opacas generadas con una sal aleatoria y ordena por esas claves. Conserve la tabla de correspondencias aparte. Las fechas de los sucesos se facilitan al lector retrospectivo; no establecen qué sabía quien produjo la respuesta original.
3. Selle la identidad del modelo, los parámetros, la implementación exacta, las entradas enmascaradas y la instrucción en un directorio de plan nuevo. Si se necesita acreditar el momento de la operación ante terceros, registre externamente la huella antes de comenzar. Una huella calculada en local por sí sola carece de fecha pública probada.
4. Ejecute el plan dos veces en directorios nuevos. Se conserva para cada caso el cuerpo enviado y el cuerpo exacto recibido. El modelo solo puede escoger citas entre la respuesta completa y las frases candidatas proporcionadas. Una cita válida acredita extracción limitada a E3. La interpretación semántica se evalúa por separado con la decisión. Las posiciones comienzan en cero, excluyen el final e identifican la primera aparición del fragmento.
5. Compruebe ambos manifiestos y compare los dos pases antes de abrir la referencia. Conserve todos los fallos. Una salida mal formada, cita inválida, error de transporte o motor no disponible queda registrado como error y requiere revisión manual sin sumar acierto. Se distingue del `REVIEW` elegido por el modelo. Los reintentos usan directorios nuevos y preservan el intento anterior.
6. Abra la referencia y las correspondencias después de fijar los registros. El puntuador vuelve a verificarlos, incluye todos los casos en el denominador, distingue `REVIEW` de `ERROR` e informa de cobertura y exactitud sobre referencias determinadas. Una etiqueta de referencia `INDETERMINATE` se corresponde aquí con la acción de solicitar revisión. Se publican también las tres decisiones posibles y su matriz de confusión.

Estas órdenes parten de este directorio bajo Python 3.12 y usan rutas de salida nuevas. La descarga opcional recupera una sola vez unos 125 MiB de archivos públicos. Si ya se dispone de ellos, `ENGINE` y `GGUF` deben apuntar al ejecutable y archivo local comprobados.

```sh
python download_reference.py /tmp/spe-reader-runtime
ENGINE=/tmp/spe-reader-runtime/engine/llama-b8058/llama-server
GGUF=/tmp/spe-reader-runtime/model.gguf
MODEL_ID=QuantFactory/SmolLM2-135M-Instruct-GGUF@476854d00ede130660aba430d15f9347ad2e7d0e/SmolLM2-135M-Instruct.Q4_K_M.gguf
python mask.py --cases cases.json --events events.json --out masked.json --mapping private-map.json
python protocol.py freeze --masked masked.json --backend llama.cpp --purpose prospective --engine "$ENGINE" --model "$GGUF" --model-id "$MODEL_ID" --output plan
cat plan/plan.sha256
python protocol.py run --plan plan --engine "$ENGINE" --model "$GGUF" --output run1
python protocol.py run --plan plan --engine "$ENGINE" --model "$GGUF" --output run2
python score.py compare --plan plan --run run1 --second run2 --out agreement.json
python score.py score --plan plan --run run1 --gold reference.json --mapping private-map.json --out score.json
```

`cases.json` es una lista de entradas con `id`, `event_id`, `cutoff`, `language`, `prompt` y `text`. `events.json` contiene `id`, `name`, `event_date` y, opcionalmente, `source_url`. Las fechas siguen el formato AAAA-MM-DD. La referencia es un objeto JSON que asocia el ID original de cada caso con su etiqueta. Una vez abiertas las respuestas, las personas autorizadas para puntuar pueden vincular ambos archivos. Para expedientes sensibles, la publicación de la tabla y de los textos literales exige una base apropiada de divulgación.

## Resultados y pruebas de ingeniería

En el desafío EN/ES de 48 casos que ya tenía referencia pública, el modelo consiguió **12/48 coincidencias (25 %)**. Los 48 casos de cada pase produjeron JSON y cita válidos. Entre 42 referencias determinadas emitió una decisión distinta de revisión en 26 y acertó 11 de esas 26. Ninguno de los 24 controles `OTHER` recibió la decisión correcta. Se reprodujeron exactamente las 48 decisiones, citas e identificadores de evidencia. Los cuerpos HTTP completos fueron diferentes en todos los pares debido exclusivamente al campo `timings` del motor. Este resultado compara el nuevo lector cuantizado con una prueba ya publicada. No mide generalización prospectiva. [Archivo completo de los 48 casos](replay48.zip)

En el conjunto separado de 17 fragmentos ingleses de terceros, las 17 salidas de cada pase tuvieron JSON y cita válidos. El lector remitió 16 casos a revisión. Su única decisión distinta de revisión fue errónea. Su única coincidencia global, 1/17, correspondió al caso indeterminado correctamente remitido a revisión. Sobre las 16 referencias determinadas cubrió una y acertó cero de una. En ambos pases, para las cinco referencias positivas predijo cero positivas, una OTHER y cuatro REVIEW. Los 11 controles OTHER y el caso indeterminado recibieron REVIEW. Los 17 resultados estructurados coincidieron entre pases. En cada par de cuerpos HTTP únicamente difería el campo de tiempos. Ambos conjuntos utilizaron la misma instrucción científica congelada, pesos, ejecutable y parámetros de muestreo. Quien puntuó recibió las etiquetas del conjunto de terceros después de sellar los dos manifiestos de inferencia. Los fragmentos habían sido publicados y seleccionados editorialmente. Queda pendiente la validación con una muestra genuinamente prospectiva. [Registros de los 17 fragmentos](external17.zip) · [Denominadores, cobertura y huellas](summary.csv) · [Matrices de confusión](confusion.csv)

La gramática puede obligar a producir una cita textual correcta incluso cuando la etiqueta interpreta mal el fragmento. Para el uso operativo, un ERROR se remite a revisión manual y se conserva en la columna de errores en la auditoría estadística. La repetición y el JSON válido no justifican resolver automáticamente estas lecturas.

Las pruebas de ingeniería utilizan un transporte explícitamente identificado que siempre devuelve `OTHER`, u otro que falla de forma deliberada. Comprueban el enmascaramiento, la validación de citas, la conservación de fallos, la detección de cambios en los manifiestos, la puntuación separada y la repetición. Funcionan sin pesos y no aportan predicciones al estudio. Las órdenes siguientes verifican también las solicitudes, respuestas, manifiestos, resultados y huellas de entrada archivados del modelo real. El inventario ZIP cubre cada archivo. El empaquetado de los mismos bytes utiliza un orden y fechas ZIP fijos. [Protocolo](protocol.py) · [Puntuador](score.py) · [Pruebas de ingeniería](test_protocol.py)

```sh
python test_protocol.py
python evidence.py verify replay48.zip
python evidence.py verify external17.zip
```
