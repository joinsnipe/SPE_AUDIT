# Abrir la mesa de revisión

Necesitas tu propio paquete **A.sqlite o B.sqlite**, Python 3.10 o posterior y un navegador moderno. Cada persona trabaja en su ordenador. Desde el directorio que contiene la carpeta `v11`, abre una terminal. En el ejemplo, sustituye `A.sqlite` por la ruta al paquete recibido:

```sh
python3 v11/desk/desk.py A.sqlite --authored-holdout
```

En Windows se puede usar `py -3` en lugar de `python3`. Se abrirá el navegador. Si no aparece, copia en él el enlace privado que muestra la terminal. Deja la terminal abierta. La página lleva el código y los estilos incrustados. Se sirve en `127.0.0.1` con un puerto temporal, funciona sin Internet y no consulta las direcciones de las fuentes. El valor al final del enlace permite acceder al paquete en esa sesión. Guárdalo en privado. Utiliza una sola pestaña y evita abrir el mismo paquete a la vez con la herramienta de línea de comandos.

## Una revisión de principio a fin

1. Elige **ES** o **EN** y pulsa **Empezar o reanudar**. El cronómetro se pone en marcha. Los tres paneles muestran la pregunta y la respuesta originales, las fichas de la petición si existe una captura, y el suceso con su fecha y la fuente retrospectiva. El idioma de la interfaz se puede cambiar sin modificar el texto evaluado.
2. Lee sin pistas. Puedes seleccionar un fragmento y pulsar **Subrayar selección**. Con teclado, abre **Seleccionar mediante teclado**, escribe un fragmento exacto y pulsa **Subrayar fragmento**. Si se repite, añade contexto para identificarlo. La marca continua corresponde a tus propias selecciones. Puedes quitar cada una. La pestaña no tiene acceso a etiquetas de referencia ni a predicciones del detector.
3. Elige la etiqueta y escribe por qué. El borrador se guarda al escribir. **Pausar** guarda el texto y detiene el cronómetro. Cambiar de pestaña solicita una pausa. El servidor recibe una señal cada cuatro segundos. Si desaparece sin pausarse, contabiliza como máximo quince segundos desde la última señal y exige reanudación. Al cerrar de forma abrupta se puede perder la última fracción de tiempo o texto aún pendiente de guardar. Pausa antes de salir. Abre el mismo paquete y pulsa **Empezar o reanudar** para continuar.
4. Pulsa **Guardar y continuar** cuando la decisión esté lista. La etiqueta, la justificación, las selecciones exactas y los segundos activos quedan en las mismas tablas que utiliza el kit de revisión. Las decisiones terminadas se conservan. La persona que adjudica sigue el [protocolo de revisión](../review/review_es.md).
5. Al completar todos los casos, pulsa **Cerrar paquete y obtener recibo**. Conserva el archivo SQLite y la huella indicada. Devuelve el paquete por el canal privado acordado y la huella por separado. Cierra la terminal con Ctrl+C. Para cerrar expresamente un paquete parcial, utiliza `review.py seal A.sqlite --allow-pending` según el protocolo.

**Modo asistido.** Solo se activa al pedirlo expresamente dentro de un caso. Subraya con una línea discontinua los años de cuatro cifras entre 1500 y 2199. Una coincidencia no establece que haya una afirmación ni que se incumpliera el corte. La activación se conserva aunque se pause o se cierre la página. Cada nueva respuesta empieza sin pistas. Si el protocolo exige doble ciego, conserva ese modo en todos los casos y declara cualquier exposición anterior. Para contar las dos condiciones por separado usa:

```sh
python3 v11/desk/desk.py A.sqlite --summary
```

El resumen distingue las decisiones ciegas, las expuestas a ayuda y las procedentes de otras interfaces. Los segundos asistidos incluyen solo los intervalos activos posteriores a la petición de ayuda. La nota sellada conserva el modo y los fragmentos de evidencia con sus posiciones en puntos de código Unicode. El informe general de acuerdo del kit combina las decisiones según el protocolo. Para interpretar un resultado ciego hay que apartar de ese análisis los casos asistidos y registrar la exposición previa. La pausa, las huellas y el cronómetro de la aplicación no prueban que dos personas trabajaran de manera independiente.

## Qué recibió realmente el sistema

El indicador `--authored-holdout` corresponde al conjunto de evaluación redactado para la versión 1.1. No hubo una generación por un modelo ni envío de fichas durante aquella generación. Las referencias del tercer panel sirven para comprobar posteriormente el suceso. Para un paquete de origen desconocido, omite ese indicador y la interfaz dirá que falta una captura.

En un estudio con solicitudes registradas, coordinación puede adjuntar únicamente las capturas asociadas **a los códigos ciegos de ese lector**. Sustituye la opción anterior por `--contexts contextos_A.json`. Este JSON es un objeto cuyas claves son los códigos del paquete. Cada valor contiene `request_utf8`, `request_sha256` y `output_sha256` de la captura. La petición codificada conserva `prompt`, `cutoff` y `sources`, con los campos de fuente `text`, `date` y `url`. La mesa comprueba ambas huellas y la correspondencia de la pregunta y el corte, y solo presenta las fichas contenidas en esa petición. Una lista vacía comprobada se muestra como «cero fichas». Si falta el código, figura «se desconoce». La correspondencia con el registro local no demuestra uso por un proveedor ni una relación causal. Revisa los textos y enlaces permitidos para evitar una revelación accidental. Usa únicamente las fuentes autorizadas y mínimas para esta decisión.

## Qué exige la UE sobre los idiomas

El Reglamento de IA no establece una obligación universal de que todo sistema de IA responda en todas las lenguas oficiales de la UE. El artículo 13.2 exige instrucciones comprensibles, accesibles y claras para responsables del despliegue de sistemas de alto riesgo. El artículo 47.2 exige traducir la declaración UE de conformidad a una lengua que entiendan fácilmente las autoridades nacionales pertinentes. El artículo 50.5 exige que las comunicaciones de transparencia comprendidas en ese artículo sean claras, distinguibles y accesibles. Son obligaciones con destinatarios y objetos concretos. La lengua de un trámite público, los derechos lingüísticos nacionales y las necesidades de las personas usuarias deben examinarse para el servicio concreto. Esta herramienta permite revisar en español e inglés y conserva el idioma original de la evidencia.

Fuentes oficiales consultadas el 21 de noviembre de 2026. [Reglamento de IA, texto consolidado](https://eur-lex.europa.eu/legal-content/ES/TXT/?uri=CELEX:02024R1689-20260727) · [Artículo 13](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-13) · [Artículo 47](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-47) · [Artículo 50](https://ai-act-service-desk.ec.europa.eu/en/ai-act/article-50).

## Verificación reproducible

```sh
python3 -B -m unittest discover -s v11/desk -p test_desk.py -v
```

Las pruebas usan casos simulados, tiempos de prueba y bases temporales. Comprueban pausa, persistencia, contextos, control de acceso local, modo asistido y el recibo de la base. Con Node 18 o posterior se ejecuta además el JavaScript entregado contra el servidor HTTP real con una representación del DOM de prueba. Ese recorrido incluye selección de evidencia, cambio de idioma, dos decisiones y cierre. La prueba no mide legibilidad visual ni valida el uso con lectores de pantalla. Cero participantes humanos.
