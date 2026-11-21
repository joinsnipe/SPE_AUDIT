# Dos revisiones independientes de una afirmación temporal

**Medición al publicar el kit: cero personas revisoras, cero decisiones humanas observadas y cero minutos humanos medidos.** Las pruebas crean casos ficticios y tiempos simulados en un directorio temporal. El instrumento sirve para recoger observaciones futuras. Aún no hay una estimación empírica de acierto, independencia o carga de trabajo humana.

## Qué deben decidir las dos personas

La pregunta es si la respuesta **afirma que el suceso indicado ya había ocurrido pese a que su fecha documentada era posterior al corte**. Ambas personas aplican la misma convención de días naturales. Cuando el suceso coincide en fecha con el corte, se usa precisión de día. Si importa el orden dentro del día y se desconoce, se explica la incertidumbre. La fecha del acontecimiento puede diferir de la fecha de publicación y de la entrada en vigor de una norma. La fuente retrospectiva ayuda a identificar el hecho. Para saber qué recuperó el modelo o qué era de conocimiento público a una hora concreta se necesitan otras pruebas.

| Etiqueta | Criterio |
|---|---|
| `post_cutoff_assertion` | La respuesta afirma el hecho consumado y la fecha documentada es posterior al corte. Señala las palabras que expresan ese compromiso. Puede faltar el año. |
| `other` | El suceso ya había ocurrido en el corte conforme a la convención temporal, o la respuesta se limita a predecir, negar, plantear una hipótesis, citar sin asumir la afirmación, preguntar o rehusar. Explica la lectura con un fragmento breve. |
| `indeterminate` | Una ambigüedad sobre el suceso, su identidad, el sentido de la frase o la cronología impide resolver. Indica qué dato o distinción haría falta. |

Lee la pregunta y la respuesta juntas. Copiar una pregunta no afirma el suceso. Tras citar un pronóstico, una frase puede confirmar expresamente el desenlace. Una cifra errónea o un dato revelado ya por la pregunta pueden merecer otra investigación. Anótalos en el campo de evidencia y evalúa la proposición definida para el caso. Si la fuente facilitada deja dudas, consérvalas. Antes de empezar, fija la versión de la fuente o facilita a ambas personas la misma copia fechada y obtenida lícitamente.

## Procedimiento de coordinación y lectura

Utiliza Python 3.10 o posterior y ejecuta los comandos desde el directorio de `review.py`. Las palabras en mayúsculas representan rutas o valores que hay que sustituir. Primero se registran el método, los cortes, las reglas de evidencia y las exclusiones en un lugar aparte. Se toma el SHA-256 **registrado con anterioridad**. Calcularlo por primera vez después de consultar los datos rompería el cegamiento prospectivo. El programa compara la huella antes de abrir los casos y los sucesos. Si el protocolo JSON declara las huellas de casos y sucesos en su mapa `sha256`, comprueba ambos ficheros byte a byte antes de crear los paquetes. En un protocolo de texto plano solo se verifica el compromiso del protocolo. Se guardan las huellas de los dos ficheros junto a las asignaciones. Una huella por sí sola no acredita la fecha ni la autoría del registro.

1. **Preparar.** Los casos son una lista JSON de objetos con `id,event_id,cutoff,language,prompt,text`; los sucesos, otra con `id,name,event_date,source_url`. Ambas fechas siguen AAAA-MM-DD. Solo pasan al paquete idioma, pregunta, respuesta, corte, nombre y fecha del suceso y URL de la fuente. Se excluyen identificadores originales, reglas, etiquetas, predicciones y metadatos adicionales. Hay que inspeccionar los campos permitidos y sus enlaces por si el texto revela una clave de respuestas, una plantilla, el modelo o datos personales. Conserva el texto observado. Si contiene una revelación sustancial, aplica la exclusión acordada o documenta la incidencia. El orden se sortea para cada persona y los códigos por caso son distintos. Con dos o más casos, ambos paquetes tienen órdenes diferentes.
2. **Distribuir por separado.** El directorio incluye `coordinator.json` y dos bases SQLite. Cada participante recibe solo su base, el protocolo y el programa. Coordinación custodia las correspondencias. Quienes evalúan trabajan sin acceso al conjunto original, a predicciones, a etiquetas anteriores ni a las respuestas de la otra persona. Anota cualquier exposición previa o intercambio. Si alguien conoce un caso ya publicado, su identificador aleatorio no borra ese conocimiento.
3. **Leer y medir.** `session` muestra un caso, inicia un cronómetro monotónico y permite pausar y reanudar antes de guardar la etiqueta, el motivo y los segundos activos. Incluye el tiempo de escribir la decisión. Pausa para las interrupciones. Al salir sin guardar se descarta ese intento y su tiempo. Para reanudar trabajo con cronómetro externo, usa `show` y `record` e introduce el total de segundos activos de ese caso, incluidos los intentos interrumpidos que hayas medido. Distingue la negativa de la respuesta evaluada y una revisión sin terminar. Se rechazan motivos vacíos, duplicados y tiempos nulos o no válidos.
4. **Cerrar por separado.** Al ejecutar `seal` cada persona recibe una huella de sus respuestas. Devuelve por un canal privado su base cerrada y la huella de referencia. `--allow-pending` autoriza expresamente un cierre parcial. Coordinación recibe las bases con sus nombres originales, coteja cada huella con el recibo entregado por separado y conserva los dos originales cerrados. `status` muestra las cantidades y el recibo verificado de la base cerrada sin revelar etiquetas. El programa comprueba la identidad del paquete, el orden y las respuestas cerradas antes de compararlas. Los recibos permiten detectar cambios respecto a referencias fiables. Acreditar la identidad e independencia de las personas requiere gestión separada.
5. **Adjudicar.** Una tercera persona examina ambas justificaciones cuando hay desacuerdo o coinciden dos indeterminados. Consulta la fuente y registra su propio resultado, motivo y tiempo activo acumulado. Puede ratificar la incertidumbre. Repite la adjudicación hasta agotar la cola. Estas decisiones quedan en `adjudication.sqlite`. Las etiquetas originales y su acuerdo se conservan. La falta de una segunda opinión sigue figurando como pendiente.

```sh
python3 review.py prepare --cases CASOS.json --events SUCESOS.json --freeze PROTOCOLO_FIJADO --freeze-sha256 HUELLA_REGISTRADA --mode human_collection --out LOTE
python3 review.py session A.sqlite
python3 review.py show A.sqlite
python3 review.py record A.sqlite --ticket CODIGO --label indeterminate --evidence "Falta precisar la fecha aplicable" --seconds 70
python3 review.py status A.sqlite
python3 review.py seal A.sqlite
python3 review.py report LOTE
python3 review.py adjudicate LOTE
python3 review.py adjudicate LOTE --case ID_CASO --label other --evidence "Explica la decisión y la fuente" --seconds 95
python3 review.py report LOTE
python3 -B -m unittest discover -s . -p test_review.py
```

Para un caso se usa `session` o la pareja `show` y `record`. La segunda persona utiliza su propia base en su dispositivo. Los segundos de los comandos son ejemplos. En los ensayos usa `--mode simulation` y conserva los lotes de simulación separados de las observaciones humanas.

## Cómo publicar las mediciones

La matriz de tres por tres sitúa a A en filas y a B en columnas. El acuerdo bruto divide la diagonal por todos los casos con dos respuestas. La κ de Cohen sin ponderar es (acuerdo observado − esperado) / (1 − esperado). El acuerdo esperado se obtiene de los marginales de cada lector. Se conserva la categoría indeterminada, incluidas las coincidencias entre dos indeterminados. Sin parejas completas, acuerdo y κ son nulos. Cuando el acuerdo esperado es uno, κ queda sin definir aunque ambas personas hayan coincidido siempre. Publica la cobertura de parejas y los pendientes de cada persona junto a la matriz.

El informe JSON separa el esfuerzo por persona, por pareja y en adjudicación. Da los minutos-persona observados, la mediana y el percentil 90 de los segundos activos según el método del rango más próximo, y los recuentos de cronómetro y entrada manual. La duración por pareja suma los dos tiempos en casos con doble revisión. El esfuerzo total incluye una sola vez las revisiones completadas sin pareja y las adjudicaciones terminadas. Habría que medir aparte las esperas, los abandonos, la selección y la formación de personas, y el trabajo futuro. Conserva las resoluciones indeterminadas y las cantidades sin resolución final. Indica tamaño de la cohorte, idiomas y exposición a casos públicos.

## Derechos y protección de datos en un despliegue

La organización debe determinar la base jurídica y la finalidad del tratamiento, minimizar lo que ve cada persona, limitar la conservación y controlar el acceso. Utiliza ejemplos sintéticos en público. Las notas o el historial de comandos pueden incluir datos personales. Introduce solo el contenido indispensable y revisa el riesgo de identificación antes de publicar agregados. Los códigos seudónimos pueden asociarse a casos mediante el fichero de correspondencias. El artículo 85 del Reglamento de IA permite reclamar ante la autoridad de vigilancia del mercado si hay motivos para considerar infringido el Reglamento. El artículo 86 reconoce, cuando se cumplen sus condiciones, el derecho a una explicación del responsable del despliegue sobre el papel de la IA y los elementos principales de la decisión. La propia resolución puede impugnarse por la vía administrativa o judicial aplicable. Los artículos 77 y 79 del RGPD regulan la reclamación en materia de datos y la tutela judicial. Una etiqueta de revisión no determina por sí sola el derecho a reparación ni la legalidad del despliegue.

Fuentes oficiales consultadas el 21 de noviembre de 2026. [Reglamento de IA consolidado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:02024R1689-20260727) · [Artículo 85](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-85) · [Artículo 86](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-86) · [RGPD, en particular artículos 5, 6, 32, 77 y 79](https://eur-lex.europa.eu/eli/reg/2016/679/oj/spa).
