# Piloto abierto de revisión temporal · Open temporal review pilot

**Rubén Abella · SPE Audit.** Cualquier grupo puede organizar una lectura de 16 casos y conservar sus datos localmente. Participan dos personas con capacidad de leer español e inglés. Una tercera resuelve los desacuerdos una vez selladas ambas lecturas. No se requiere cuenta ni inscripción. Al abrir la convocatoria hay **0 decisiones y 0 minutos humanos observados**.

[Descargar el kit autónomo · Download the standalone kit](https://github.com/joinsnipe/SPE_AUDIT/raw/refs/heads/main/research/temporal-audit/post11/open-pilot/pilot-16.zip)

1. La persona coordinadora descarga y descomprime el ZIP. Con Python 3.10 o posterior, abre una terminal dentro de la carpeta extraída y ejecuta `python3 organize.py` (Windows: `py -3 organize.py`). En una copia del repositorio, ejecuta el mismo comando desde `post11/open-pilot/`.
2. Entrega `REVISOR_A.zip` y `REVISOR_B.zip` a **personas diferentes**. Cada archivo incluye su propio visor, fichas y cronómetro. Conserva la carpeta de coordinación en privado. Las personas revisoras solo necesitan su propio ZIP. Si han leído las respuestas, usado la demo o participado en el diseño, registra esa exposición al interpretar el resultado.
3. Antes de repartir, acordad cómo devolver las bases selladas, si se permiten pausas y si se usará el resaltado opcional. La primera lectura propuesta usa ayudas desactivadas en ambas personas para medir factibilidad sin mezclar condiciones. Cada una explica su decisión con un fragmento o describe la evidencia que falta. Se admiten indeterminados y retiradas. No incluyáis nombres ni datos personales en las notas.
4. Sigue la [guía de coordinación](COORDINATOR.md). Informa de los casos pareados, desacuerdos, mediana y percentil 90 de segundos activos, acuerdo simple, κ y su denominador. Deja visibles los casos incompletos y las incertidumbres pendientes. Los resultados y las notas permanecen con el grupo. Si decide compartir resultados, el grupo elige qué agregados publicar.

**Muestra y alcance.** Se eligen sin etiquetas 16 de los 48 casos ya públicos del artículo. El muestreo incluye un caso por combinación de suceso e idioma y dos casos adicionales por idioma mediante un orden SHA-256 fijado. Son ocho en inglés y ocho en español. El orden de presentación y los tickets se generan por separado para cada persona. La selección fija permite comparar sesiones; la exposición previa y el tamaño impiden extrapolar a otros servicios. Comparar con y sin asistencia requeriría asignación aleatoria y contrabalanceada sobre casos distintos por persona para evitar que recuerde una lectura anterior.

## English

Download and extract the kit, then run `python3 organize.py` (Windows: `py -3 organize.py`). Send each individual ZIP to a different bilingual reviewer. Keep the coordination folder private. A third reader adjudicates disagreements after both packets have been sealed and returned. Each reviewer receives the same 16 public authored examples in a different order with unrelated tickets. The selection is fixed before labels or predictions are read, with eight cases per language and all six events represented. Record prior exposure. This open exercise measures feasibility in the participating group. It has no central registration or automatic results collection. Use the [reviewer instructions](REVIEWER.md) and [coordination guide](COORDINATOR.md).

[Estudio de referencia · Reference paper](https://doi.org/10.5281/zenodo.24424024) · [Licencia de software · Software licence](../../LICENSE)
