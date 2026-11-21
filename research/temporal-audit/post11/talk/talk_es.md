# ¿Podía una IA dar por ocurrido el impacto de DART el 1 de enero de 2022?

**Rubén Abella · SPE Audit**

Guion de cinco minutos. Siete diapositivas para la exposición y una de reserva para preguntas. Material de comunicación posterior al depósito. El DOI identifica el artículo. [Artículo depositado](https://doi.org/10.5281/zenodo.24424024)

### 0:00–0:37 · 1. Un verbo y una fecha

Es el 1 de enero de 2022. Alguien pregunta qué podía decirse entonces de la misión DART y recibe esta frase: «DART impactó contra Dimorphos en 2022». Es la traducción de un caso que construí para el estudio. NASA ya había anunciado el lanzamiento y el choque previsto. El impacto ocurrió el 26 de septiembre. La frase da por consumado en enero algo que entonces era un plan. Una regla que solo compara años pasa por alto el problema: tanto el corte como el impacto pertenecen a 2022.

### 0:37–1:15 · 2. Hasta dónde llega el registro

Si mañana se impugnara la frase, querría recuperar la petición exacta. El adaptador selecciona las fichas por su fecha declarada, serializa la pregunta, el corte, la política y las fichas admitidas, y pasa esos bytes a una función emisora local. Conserva también el texto devuelto. Con una huella de referencia retenida por separado, otra persona puede comprobar si coincide el registro. Si ese emisor transforma la petición antes de enviarla, el registro sigue describiendo su entrada local. Afirmar qué procesó un proveedor remoto requeriría evidencia de ese otro punto.

### 1:15–1:55 · 3. Dos poblaciones

La regla de proposiciones 1.1 detectó 30 de 32 positivos en los 96 casos ya conocidos, sobre cuatro misiones utilizadas en el desarrollo. Resolvió 94 casos automáticamente. Después se aplicó la misma regla a 48 frases en español e inglés sobre seis acontecimientos nuevos. De los 18 positivos, detectó uno y remitió los otros 17 a revisión. La cobertura fue 24 de 48. Cambiaron los acontecimientos, las formulaciones y la composición de la muestra. Esta diferencia demuestra que el resultado depende de la colección. El diseño no permite atribuir cuánto cambió por cada factor.

### 1:55–2:42 · 4. Qué decidió cada método sobre los mismos 48

Hay tres salidas posibles: alerta, otro o revisión. En esos mismos 48 casos, la regla anual emitió dos alertas, clasificó 46 como «otro» y nunca se abstuvo. Ninguna de sus alertas correspondía a un positivo. La regla de proposiciones emitió dos alertas, cerró 22 como «otro» y dejó 24 para revisión. Una alerta acertó y otra fue falsa. La lectura semántica con IA, encargada después de examinar el resultado agregado, identificó los 18 positivos, clasificó los 24 controles como «otro» y remitió las seis referencias ambiguas. Recibió la pregunta, el texto, el acontecimiento y las fechas, con identificadores enmascarados y sin etiquetas de referencia. La coincidencia con las etiquetas editoriales es exploratoria. Falta una adjudicación humana independiente para contrastarla.

### 2:42–3:32 · 5. Una impugnación en la mesa de revisión

Abramos el caso v038. El corte es el 21 de junio de 2016 y el canal ampliado de Panamá se inauguró el 26. La frase dice: «La pregunta da por hecho que se inauguró el canal ampliado. No acepto esa premisa». La regla alertó. La referencia editorial dice «otro». Para explicar la discrepancia subrayaría la segunda frase: quien responde rechaza la premisa que acaba de citar. La mesa deja leer la pregunta y la respuesta, señalar las palabras decisivas, elegir una etiqueta y justificarla. En un ejercicio ciego, cada revisor recibiría su paquete sin esta solución ni las predicciones. Esta demostración está resuelta de antemano. No se ha medido cuántos revisores coincidirían ni cuánto tardarían.

### 3:32–4:16 · 6. Cuánto pesa un error

En el escenario administrativo ilustrativo, revisar un caso cuesta una unidad convencional, una falsa alerta cuesta doce y cerrar automáticamente una ambigüedad cuesta catorce. Cerrar un positivo como «otro» cuesta veinticinco. Con la regla hubo una falsa alerta, ningún positivo cerrado como «otro», 24 revisiones y tres ambigüedades cerradas. Suman 78 unidades. Revisar los 48 casos cuesta 48 con esos mismos pesos. Son valores asignados para explorar una decisión. No son euros, tiempos de trabajo ni resultados observados de personas. Un servicio tendría que medir sus propias consecuencias y capacidad.

### 4:16–5:00 · 7. Una discrepancia reproducible

Para reproducir este análisis elegiría una respuesta, declararía el corte y pediría a dos lectores que conservaran por separado las frases que justifican su decisión. Después compararía esas razones con la predicción automática. Ahí aparece la diferencia entre una máquina que reconoce un verbo y una persona que debe interpretar quién está afirmando qué. En el repositorio están los textos, los registros de decisión y la mesa de revisión. El artículo ofrece una base común para discutir la evidencia. Una pregunta para abrir el debate: ¿qué tendría que guardar hoy su servicio para que otra persona pudiera impugnar una respuesta dentro de un año?

### Reserva · 8. Qué significan 3.638 parámetros

El anexo muestra un prototipo neuronal entrenado desde cero en CPU con caracteres y una segunda fase que aprende la postura lingüística. La cifra cuenta sus parámetros, incluidas las capas de predicción de caracteres y de clasificación. Con los pesos congelados, en los mismos 48 casos devolvió cero alertas, nueve «otro» y 39 revisiones. Entre los 18 positivos hubo 17 revisiones y un cierre erróneo como «otro». El comparador estadístico de n-gramas sobre esos mismos casos emitió 20 alertas: once positivos, seis controles y tres casos indeterminados. El tamaño del prototipo describe su implementación. Un diagnóstico de sobreajuste requeriría variar de forma controlada tamaño, datos y condiciones de evaluación.

### Un párrafo científico para discusión

Dentro del mismo reto, v009 identificaba el desenlace de la Ópera de Sídney por el lugar y el predicado. Fue el único positivo que la regla de proposiciones detectó. En v038 la primera frase activó la alerta aunque la segunda rechazaba la premisa. En v019 el texto dejó sin identificar cuál de dos señales se había detectado y la regla cerró el caso como «otro» frente a una referencia indeterminada. De los 17 positivos remitidos a revisión, el registro codificó 16 con evidencia de proposición insuficiente y uno con puntuación 4, por debajo del umbral 5. El recuento distingue decisiones sobre expresiones y decisiones ante ambigüedad. No identifica por sí solo una causa de la diferencia entre cohortes. [Casos](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/v11/holdout/cases.json) · [Referencias editoriales](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/v11/holdout/labels.json) · [Decisiones y trazas](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/v11/results/predictions.jsonl)
