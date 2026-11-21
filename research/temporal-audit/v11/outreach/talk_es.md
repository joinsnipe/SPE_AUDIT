# ¿Qué podía afirmar una IA el 1 de enero de 2022?

**Rubén Abella · SPE Audit**

Guion de 4 min 45 s. Siete diapositivas. Las pausas y los cambios de pantalla están incluidos. Las frases de ejemplo pertenecen a un estudio construido.

### 0:00–0:32 · 1. La pregunta

Les voy a pedir que vuelvan al uno de enero de 2022. Una persona pregunta por la misión espacial DART y recibe esta respuesta: «DART impactó contra Dimorphos en 2022». Hoy sabemos que eso ocurrió. Pero imaginen que esa frase se usa para justificar qué se sabía en enero. ¿La aceptarían? Publiqué el caso, los documentos y el código en SPE Audit para que cualquiera pueda discutir mi lectura.

### 0:32–1:08 · 2. La cronología

NASA ya había anunciado el lanzamiento a finales de 2021 y el objetivo de la misión. El impacto llegó el 26 de septiembre de 2022. En enero se podía explicar el plan. Dar el choque por consumado añade algo que todavía faltaba por ocurrir. El ejemplo inglés es el caso `dart-09`, que escribí para el estudio. Y encierra un detalle fácil de pasar por alto: el año de la frase es el mismo que el del corte. Un programa que solo compara años deja pasar esta afirmación.

### 1:08–1:46 · 3. La evidencia

¿Qué conservaría yo si alguien impugnara esa respuesta? La petición exacta que recibió el emisor local, la fecha de corte, la regla que eligió las fuentes y la salida que devolvió. Con una huella guardada por separado, un tercero puede comparar los bytes y ver si el registro cambió. Para decidir qué afirma la frase hace falta leerla junto a la evidencia fechada. Para atribuirla al entrenamiento o a un documento concreto harían falta observaciones adicionales. Son tres preguntas que un auditor debe poder contestar por separado.

### 1:46–2:27 · 4. Las primeras 96 respuestas

Trabajé con 96 casos construidos. En 32, la frase daba por consumado un hecho posterior al corte. El primer comparador del estudio con fechas detectó 24 de esos 32, un 75 %. Emitió una decisión automática en 84 de 96, una cobertura del 87,5 %. Las otras doce respuestas quedaron para revisión. Fíjense en los denominadores: uno pregunta cuántos positivos detectó el método y el otro cuántos casos resolvió. Confundirlos ofrecería al comprador una promesa que el experimento jamás midió.

### 2:27–3:01 · 5. Cuando cambia la redacción

Después utilicé 16 frases preparadas en otra fase sobre las mismas misiones. Ocho seguían presentando como consumado un hecho posterior. El mismo comparador detectó cero de ocho y mandó catorce de las dieciséis a revisión. Las únicas dos decisiones automáticas fueron controles. El estudio no midió lo que habría resuelto un equipo humano en esos catorce expedientes. Esta es la cifra que me gustaría ver junto a cualquier oferta de automatización: ¿qué trabajo vuelve a las personas cuando cambia el lenguaje?

### 3:01–4:02 · 6. Un código y dos vías

Para el suplemento construí cuarenta tríadas con un identificador ficticio por caso. Presenté a tres programas locales la misma pregunta con el documento presente, ausente o sustituido. El primero copió el identificador correcto cuarenta veces con el documento presente y ninguna sin él. Cuando sustituí la ficha, devolvió el identificador alternativo las cuarenta veces. El segundo programa siempre respondió con un texto genérico. El tercero recibió el identificador por otra entrada. Acertó cuarenta de cuarenta, incluso cuando el documento faltaba y cuando lo sustituí.

Son 360 llamadas locales y cuarenta unidades emparejadas por contraste. En estos sistemas conozco los dos mecanismos porque los construí. Ante una respuesta histórica aislada, ver el mismo código permite varias explicaciones. Ninguno de estos cuarenta casos observó el entrenamiento o la ejecución de un proveedor remoto.

### 4:02–4:45 · 7. Un piloto que se puede discutir

Si una organización quiere probar esto con su propio servicio, propongo empezar por una sola pregunta con fecha y unos documentos que pueda compartir. Podemos delimitar el punto de captura, integrar el adaptador bajo las condiciones de licencia y entregar un informe con ejemplos, cobertura, discrepancias y carga de revisión. El estudio y el verificador están disponibles antes de contratar nada. Me interesa que la primera conversación sea sobre un caso concreto. Traigan una respuesta que hoy consideren discutible. Acordemos qué evidencia permitiría resolverla y qué quedaría pendiente después de la auditoría.

### Tres aperturas alternativas

- **Para responsables de producto.** «Si un cliente recurriera hoy una respuesta de enero, ¿podrían recuperar los documentos concretos que vio su aplicación?»
- **Para auditores.** «Una frase puede ser históricamente correcta y, aun así, quedar fuera de la fecha que había que respetar. Les propongo reconstruir una.»
- **Para una audiencia general.** «Viajen conmigo al día de Año Nuevo de 2022. Una nave va camino de un asteroide. ¿Ya podemos escribir que ha chocado?»

### Tres cierres alternativos

- **Para una demostración.** «Elijan la fecha, lean las dos fuentes y ejecuten el verificador. Después discutimos la frase con el mismo material delante.»
- **Para investigación.** «Me interesan las reproducciones que cambien la redacción o incorporen otros sucesos. Publiquen también qué casos acabaron en revisión.»
- **Para un piloto técnico.** «Traigan un caso y un responsable de revisión. Definiremos qué registrar, qué decisión evaluar y qué observación exigiría una afirmación más fuerte.»

[Diapositivas en PDF](slides_es.pdf) · [Artículo científico](https://github.com/joinsnipe/SPE_AUDIT/blob/main/research/temporal-audit/PAPER_ES.pdf) · [Intervención con identificadores](https://github.com/joinsnipe/SPE_AUDIT/tree/main/research/temporal-audit/v11/interventions) · [Licencia del proyecto](https://github.com/joinsnipe/SPE_AUDIT/blob/main/LICENSE)
