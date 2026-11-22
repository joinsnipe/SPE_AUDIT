# Diseño para una réplica externa · Design for independent replication

## Español

El [registro de candidatos](candidate_events.csv) propone 34 acontecimientos de política monetaria, transacciones, justicia, regulación, elecciones, cultura, deporte e infraestructura. Cada fila especifica la proposición fechada en español e inglés, el tipo de fecha, el idioma de la página oficial y el enlace. Los nombres de las columnas y los códigos se documentan abajo. Las descripciones bilingües son editoriales. Una fecha comprobada sirve para preparar un caso futuro. La etiqueta de una frase concreta requiere leer lo que afirma esa frase.

1. **Definir la selección antes de redactar.** Identificar la población sobre la que se quiere aprender, el intervalo temporal y los criterios de inclusión y exclusión. Congelar el listado elegido y registrar su procedencia. Reservar eventos enteros, familias de sucesos relacionados y un dominio para evaluación externa. Dos cancelaciones o aplazamientos motivados por la misma crisis pueden estar relacionados. Un grupo puede aportar acontecimientos nuevos, incluso fuera de este listado.
2. **Distinguir las fechas que cambian el veredicto.** Preparar por separado fichas del plan, anuncio, suceso, publicación, vigencia y captura cuando existan. Congelar versiones de fuentes, idioma y zona horaria. En las cancelaciones deben distinguirse dos proposiciones: «se celebró según el plan» y «se anunció la cancelación». Verificar cada una contra la fecha y el expediente pertinentes. Una búsqueda infructuosa deja la cuestión abierta.
3. **Redacción y referencia independientes.** Un equipo ajeno al desarrollo redacta preguntas y respuestas sin ver las reglas ni los ejemplos resueltos. Dos revisores con competencia en la lengua reciben en orden aleatorio las mismas fichas sin las salidas de los métodos, ni el trabajo del otro. Mantienen separados positivo, otro e indeterminado. Se congelan sus decisiones por separado. Una tercera persona adjudica los desacuerdos. Se documentan exposición previa, relación con el proyecto y alcance de la asistencia informática.
4. **Comparación sin información privilegiada.** Ejecutar la regla anual, una regla con abstención y uno o varios lectores con las mismas filas y un contrato de entrada declarado. En el brazo primario solo entran corte, pregunta, respuesta y fichas admisibles. Una variante retrospectiva que añade la fecha del desenlace se analiza aparte. Fijar prompt, modelo, parámetros, diccionario, plan de puntuación y huellas antes de inferir. Publicar un sello externo previo y conservar los errores de transporte.
5. **Si se estudian proveedores remotos.** Distinguir el modelo que genera una respuesta del lector que la clasifica. Para comparar emisores, fijar alias y revisión disponible de cada servicio, política de herramientas, corte solicitado, documentos, orden aleatorio, número de réplicas y reglas de parada. En intervenciones con y sin ficha de desenlace, mantener constante el resto de la petición. Contar errores y respuestas vacías. Documentar procedencia y autorización de publicación. El cliente conserva lo que envió y recibió. La inferencia sobre la causa interna depende de la visibilidad del proveedor.
6. **Resultados y costes.** Publicar la matriz de confusión, positivos detectados, falsas alarmas, precisión en alertas, cobertura, revisiones y fallos con denominadores. Distinguir concordancia entre analistas, concordancia con la adjudicación y tiempo activo. Mostrar acuerdos brutos y por clase, κ o α con sus supuestos, y los indeterminados. Para muestras suficientemente diversas, remuestrear acontecimientos o grupos de acontecimientos relacionados y comunicar la sensibilidad al agrupamiento. Un intervalo condicionado a una lista dirigida conserva el sesgo de selección.

El [piloto descentralizado de 16 casos](../post11/open-pilot/) permite ensayar el procedimiento con datos públicos. Para una evaluación externa nueva, sustituir los casos de práctica por material sin exposición previa y conservar los expedientes individuales de forma privada. Cada organización decide qué agregados comparte.

## English

The [34-event candidate register](candidate_events.csv) records a dated milestone and its official source for possible future writing. No sentence in this register has been scored as an audit case. The bilingual descriptions were prepared for the research project. The source-language column refers to the linked page.

An external team should declare its target population, selection rules and publication cutoff before authoring cases, reserve whole events and related families, and document shared causes. Distinguish the planned event, a cancellation announcement, entry into force and public availability. Freeze historical source versions. Independent writers should work without seeing development examples. Two reviewers label randomized packets separately, with blinded methods and a third adjudicator. Preserve ambiguity, disagreement and prior exposure.

Compare all methods on the same rows and declare their input contracts. Withhold the registered outcome date in the primary condition. Precommit the prompts, weights, rules, reference protocol, number of repetitions and stopping criteria. For hosted emitters, identify model revision and enabled tools, distinguish generation from judging, randomize inclusion of source cards and retain failed calls. Report exact class denominators, review workload, failures and human time. Estimate sampling variability at event or related-family level only under defensible sampling assumptions. The [16-case voluntary pilot](../post11/open-pilot/) is available for practicing these procedures.

## CSV fields

| Field | Meaning |
|---|---|
| id, domain, jurisdiction | Registry key, subject and jurisdiction or venue. |
| language | Language of the linked official page. |
| status | Documented outcome category for the proposed event: occurred, cancelled or postponed. |
| event_es, event_en | The specific milestone in Spanish and English. |
| target_date, date_kind | Calendar date in ISO format and the operation it dates. |
| official_url | Source from the institution responsible for the record. |
| secondary_date_note | Distinctions such as announcement versus effective date, including relevant limits. |
