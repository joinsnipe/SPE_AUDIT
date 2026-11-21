# Un modelo neuronal local de 3.638 parámetros

El prototipo aprende a predecir el siguiente carácter de textos de desarrollo en español, inglés, francés y alemán. Una segunda fase ajusta sus representaciones para clasificar la postura de una respuesta sobre un suceso registrado. Los pesos se inicializaron al azar y se entrenaron desde cero en CPU. El archivo de pesos ocupa 45.903 bytes. La inferencia utiliza Python estándar, sin servicios externos ni acceso a Internet. Su alcance empírico es el de un experimento sobre ejemplos breves redactados para este proyecto. [Código](local_model.py) · [Pesos](weights.json) · [Informe de entrenamiento](training_report.json)

## Datos y límite de la evaluación

| Entrada de desarrollo | Filas | Uso |
|---|---:|---|
| 96 respuestas públicas originales, en inglés | 96 | Texto para aprendizaje de caracteres. Las filas con corte anterior al suceso también aportan supervisión de postura. |
| Calibración editorial previa en inglés y español | 48 | 24 casos por idioma con cuatro sucesos de desarrollo. Para este modelo constituyen datos de entrenamiento. |
| Traducción francesa y alemana de los 96 originales | 192 | 96 por idioma. Se cotejaron el identificador, el suceso, la fecha de corte y la etiqueta con la fila original. |
| **Total** | **336** | 120 en inglés, 24 en español, 96 en francés y 96 en alemán. Las traducciones comparten sucesos y contenidos con los originales. |

Se separaron la pregunta y la respuesta de cada fila, se normalizó el texto y se eliminaron cadenas duplicadas. Quedaron 179 documentos y 13.099 predicciones objetivo para aprender el siguiente carácter. En la fase de postura entraron las filas para las que el suceso era posterior al corte. A partir del día del suceso, una afirmación verdadera en pasado puede recibir la etiqueta temporal `OTHER`, aunque sí afirme que el suceso ocurrió. Excluir esas filas de la supervisión evita convertir esa etiqueta en una indicación errónea de postura. Después de deduplicar por idioma y respuesta quedaron 129 textos supervisados: 64 afirmaciones y 65 de la otra clase. Fueron 50 textos ingleses, 21 españoles, 29 franceses y 29 alemanes. [Datos FR/DE](eu-development.json) · [Huellas de los cinco archivos de entrada](training_report.json)

Las cifras sobre los 96 casos originales o sus traducciones francesas y alemanas son resultados sobre datos vistos. Las 16 reformulaciones, incluidas sus traducciones, retoman ideas que ya eran públicas. El desafío nuevo de 48 casos existe solo en inglés y español y quedó fuera de todo entrenamiento. La persona que implementó el prototipo ya había visto descripciones generales del desafío durante otra parte del trabajo. Los pesos, el código y el umbral se congelaron antes de la evaluación de este modelo con esas respuestas. Esto describe una comparación retrospectiva con separación de archivos, sin presuponer que todo el equipo trabajó a ciegas. [Manifiesto congelado](freeze.sha256)

## Aprendizaje de lenguaje y ajuste de postura

El vocabulario tiene 60 símbolos, incluidos relleno izquierdo, carácter desconocido y final de documento. Tras normalización Unicode NFC, conversión a minúsculas con `casefold` y normalización de espacios, el modelo usa los ocho caracteres anteriores. Cada uno aporta ocho coordenadas aprendidas. Las 64 coordenadas concatenadas alimentan una capa de 24 unidades con activación tanh. Una capa lineal y softmax predice el siguiente carácter o el final del documento. La predicción de cada posición solo recibe caracteres anteriores de ese documento. Se usaron 18 épocas, lotes de 128, Adam con tasa 0,003 y semilla 20261121. El valor inicial de la pérdida media en este corpus fue 4,100415 nats por objetivo. Tras el aprendizaje de caracteres descendió a 1,319675.

Para clasificar una respuesta se calculan la media y el máximo de cada una de las 24 activaciones a lo largo de sus ventanas. Una capa lineal de 48 entradas produce dos puntuaciones. Se ajustaron esa capa, las representaciones de caracteres y la capa de contexto con entropía cruzada ponderada por clase, 110 épocas, lotes de 16 y Adam con tasa 0,001. Los pesos de la capa de predicción de caracteres quedaron fijos en esta fase. Como las representaciones compartidas cambiaron, la pérdida de caracteres del modelo final subió a 2,193646 en los mismos datos. Estas cifras describen el ajuste en desarrollo; no hay una estimación independiente de competencia lingüística general. [Entrenamiento](train.py) · [Pérdidas y parámetros por capa](training_report.json)

## Qué observa una persona auditora

La interfaz es `predict(case, event)`. El caso suministra el identificador del suceso, el idioma, el corte, la pregunta y el texto de respuesta. La ficha aporta el identificador, el sujeto nominal, la fecha del suceso, posibles alias, expresiones del desenlace y una referencia de origen. La función lee estas entradas y los pesos locales. No consulta esa referencia.

| Salida | Interpretación |
|---|---|
| `decision` | `POST_ASSERTION` indica que la regla clasifica el texto como afirmación posterior al corte; `OTHER` recoge la otra clase; `REVIEW` solicita revisión. Cada decisión lleva un código `reason`. |
| `p_assertion` y `score` | Mismo valor softmax de la cabeza sobre la respuesta. Es nulo cuando una comprobación de entrada o fecha determina el resultado. No se calibró como probabilidad de acierto. |
| `trace` | Incluye sujeto suministrado, referencia de origen, ambas fechas, estado, cita literal de la respuesta, posiciones de caracteres para nombres y predicados reconocidos y huella del archivo de pesos. Los intervalos de Python comienzan en cero y excluyen el extremo final. |

Los umbrales se fijaron por diseño. Antes del suceso, con sujeto o alias literal en la pregunta o respuesta, una puntuación ≥0,70 produce `POST_ASSERTION`, una ≤0,30 produce `OTHER` y el intervalo intermedio conduce a `REVIEW`. Un corte igual o posterior al día del suceso produce `OTHER` bajo la premisa de un único suceso registrado. Se devuelve `REVIEW` si faltan una identidad o una fecha válida, el idioma queda fuera de los cuatro previstos, o la respuesta está vacía o supera 512 caracteres normalizados. La cabeza lee solo la respuesta. La pregunta puede aportar el anclaje nominal. Los fragmentos con predicados se muestran para inspección y no se usan como puntuación neuronal.

El ejemplo construido conserva exactamente «North Museum opened.», el sujeto «North Museum», un corte del 31-12-2000 y una fecha registrada del 02-01-2001. La salida fue `POST_ASSERTION` con puntuación 0,896369 para una ficha ficticia. La cita, los intervalos y la decisión pueden recomputarse desde el propio registro. Un nombre en la pregunta puede señalar un referente equivocado, y la red puede malinterpretar una cita, una negación, un tiempo verbal o un giro idiomático. El sistema no estima S(t), A(t), Δ(t) ni la causa de una respuesta. [Ejemplo de entrada y traza](example_trace.json)

## Reproducción

Desde este directorio, las siguientes órdenes comprueban el manifiesto y ejecutan cuatro pruebas de contrato sin red. Ejecute el entrenamiento de referencia en Python 3.12 con NumPy 2.3.5 y CPU. El directorio de salida de ejemplo se mantiene separado de los pesos publicados. Si los archivos del estudio están en otro árbol se puede pasar `--study-data` o `--method-dir`.

```sh
sha256sum -c freeze.sha256
python test_local_model.py
python train.py --output /tmp/spe-local-rebuild
cmp weights.json /tmp/spe-local-rebuild/weights.json
```

Dos ejecuciones en el entorno de referencia produjeron pesos e informe idénticos byte a byte. La huella SHA-256 de los pesos es `8f444d23138b39c16a2bce1ada44f17cc971c296ed6bb7fa04c4be7f8f6897e2`. La inferencia con los pesos distribuidos requiere Python 3.10 o posterior. Puede producir una distribución del próximo carácter mediante `next_characters(prefix, count=5)`. [Pruebas sin datos del ensayo](test_local_model.py) · [Manifiesto](freeze.sha256)
