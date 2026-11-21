# Un ensayo con textos publicados por terceros · A trial with third-party published text

Diecisiete fragmentos de noticias, avisos y declaraciones técnicas en inglés permiten probar una pregunta concreta. Si una respuesta contiene ese fragmento y se le asigna un corte histórico, ¿afirma que un hecho concreto posterior al corte ya ocurrió? Las frases se eligieron porque abordan un acontecimiento comprobable durante su preparación, en el anuncio o después. Las autoridades que las publicaron nunca recibieron las preguntas ni contestaron bajo esos cortes.

Seventeen English excerpts come from 17 dated public pages published by two US federal agencies. Each excerpt is replayed as a hypothetical answer paired with a new question and cutoff. The source has an identifiable publisher, date, direct URL, passage locator and text-fragment link. The questions, cutoffs, event dictionaries and reference decisions were created for this study. The agencies wrote or published the source language and did not supply the reference labels or validate this evaluation.

## Muestra y selección · Sampling

| Fuente · Publisher | Acontecimientos registrados · Targeted events | Pasajes · Passages |
|---|---|---:|
| U.S. Geological Survey (USGS) | Inicio de la erupción de Mauna Loa de noviembre de 2022 e inicio de la erupción de Kīlauea de junio de 2024 | 6 |
| National Institute of Standards and Technology (NIST) | Publicación de los tres primeros estándares poscuánticos finales, del CSF 2.0 y del AI RMF 1.0, y anuncio público de la puesta en servicio del reloj NIST-F2 | 11 |
| **Total** | **6 eventos · 6 events** | **17** |

The purposive retrospective search paired official before/after narratives, draft/final notices and reference material for the six selected events. Eligible material had an identifiable agency author or publisher, a visible date, a focal fact with a separate dated public record, and short English agency wording that could be redistributed. No pages or excerpts were chosen based on measured reader outputs. Seven excerpts are complete headlines, nine are complete sentences and one is a contiguous main clause from a newsletter. They contain 4–17 whitespace-delimited words each, 167 in total. No translations, third-party attributed quotations, images or full primary-source pages are distributed. The signed clock statement is an extract of the NIST scientist's own remarks.

La selección se hizo a posteriori. Se buscaron voces y fases reconocibles en dos instituciones, con documentos localizables y fechas verificables. Los titulares y las frases institucionales breves pueden resultar más fáciles o más difíciles que una conversación, una respuesta extensa o una fuente en otro idioma. Se admitió una sola muestra por página, aunque las páginas de un mismo suceso suelen compartir autores institucionales e información. El procedimiento no permite inferir la frecuencia de afirmaciones temporales en producción ni en la prensa.

## Fechas, alcance y referencia · Dates, scope and reference

The structured event record includes a subject, a registered outcome date, a compact bilingual-schema-compatible list of English subject aliases and outcome terms, and a second official page establishing the date. The six comparison URLs differ from every sampled page. They are separate documentary records from the responsible institution. They can establish an outcome date without using the reference label. They do not constitute independent witnesses or fresh corroboration by another newsroom. Where local and UTC days differ for Hawaiian eruptions, the record uses the local event day. The Mauna Loa comparison page carries a November 28 byline and explicitly reproduces a notice issued on November 27, 2022, local time. Full date provenance is in [event_sources.json](event_sources.json).

Se asignó el día anterior al hecho como corte en catorce casos. Tres controles usaron el día siguiente al hecho, lo que permite observar una respuesta afirmativa sobre un acontecimiento ya admisible y dos descripciones posteriores de actividad volcánica. La fecha de la página original fue anterior al corte artificial en seis muestras, coincidió en dos y lo siguió en nueve. El corte determina la admisibilidad del acontecimiento, no la disponibilidad histórica de la página de donde se extrajo la frase. La simulación no mide el acceso de ningún modelo a esa página.

The text and prompt supply the wording and the nominated referent. A positive reference requires a factual assertion about that registered outcome, with its day strictly after the cutoff. A different milestone, a plan, an explicit denial or an event already within the cutoff receives OTHER. INDETERMINATE preserves unresolved release status in one headline. The linked source body permits verification of the quote and date; it must not be used to upgrade the answer with facts omitted from the excerpt. For the short Kīlauea observation, the reference accepts an ongoing eruption of the named volcano as implying onset of the episode identified in the question. The sentence alone supplies no location for the vent. Removing this scope-sensitive case leaves four reference positives: the year rule alerts on 0/4, proposition rule 2/4, naïve Bayes 3/4 and the character neural reader 0/4. These figures are a sensitivity description only.

Las etiquetas de referencia son decisiones editoriales del estudio, redactadas por un solo proceso de curación asistido por IA; no se atribuyen a un revisor humano independiente ni a las agencias. Los textos y las fichas se sellaron antes de inferencia y sin modificar los cuatro lectores de la versión publicada. Se evaluaron cinco afirmaciones posteriores, once ejemplos OTHER y un caso indeterminado. El juicio binario se limita a dieciséis. La fecha pública, el corte asignado, los anuncios previos y las formulaciones negativas son rasgos observables, no pruebas de filtración de entrenamiento. No se estiman intervalos poblacionales con esta muestra dirigida.

## Resultados de los lectores congelados · Frozen-reader results

| Lector · Reader | Decisiones sobre los 16 determinados · Determinate decisions | Errores entre esas decisiones · Errors among those decisions | Alertas sobre los 5 positivos · Positives alerted | Resultado del único indeterminado · Sole ambiguous case |
|---|---:|---:|---:|---|
| Año explícito · Explicit year | 16/16 | 5/16 | 0/5 | OTHER |
| Regla proposicional v1.1 · Proposition rule | 7/16 | 0/7 | 2/5 | OTHER |
| Naïve Bayes de caracteres · Character n-grams | 16/16 | 7/16 | 3/5 | OTHER |
| Modelo neuronal de caracteres v1.1 · Neural character model | 7/16 | 1/7 | 0/5 | REVIEW |

The year-only function received the same fixed no-later-context flag used in earlier synthetic replays. That flag defines this text-only comparison and is not a claim about original model context. The proposition reader used its published event-matching and threshold rules on the supplied new event dictionary. The character naïve Bayes parameters are reconstructed solely from the earlier pinned development files; the neural reader loads its earlier saved weights. No external excerpt, reference label or reader output enters training or calibration. Scores, when present, have a different meaning in each method. For the proposition rule, the nine reviews among determined cases consist of three positives and six negatives. Naïve Bayes generates eight alerts, of which five are incorrect under the declared reference. The neural character model returns no alert. Read all results alongside each method's review rate.

Otra lectura local en llama.cpp recibió los mismos textos, con IDs enmascarados y un protocolo propio de evidencia. Envió a revisión 15 de los 16 ejemplos determinados; clasificó el restante como OTHER y se equivocó. Envió también a revisión el único indeterminado. Las dos ejecuciones reprodujeron idénticas decisiones, citas e identificadores de evidencia en los 17 textos. Esa prueba documenta las salidas del sistema; no aporta una segunda anotación humana. The separate local llama.cpp protocol produced one determinate decision out of 16, and that decision was wrong. It referred the single ambiguous case to review. [Protocol and blind prediction archives · Protocolo y predicciones enmascaradas](../reference_reader/)

## Archivos y reproducción · Files and reproduction

- [cases.json](cases.json) contiene preguntas sintéticas, corte ISO, texto original y claves. [events.json](events.json) identifica exactamente qué suceso se pregunta.
- [source_index.json](source_index.json) records publisher, credited byline or speaker when available, date, locator, rights-policy key and link for each exact original passage. A missing personal byline preserves institutional attribution. For 11 NIST pages it includes a normalized HTML-block SHA-256. The remaining six passages were verified on the displayed official USGS notices/pages. [event_sources.json](event_sources.json) dates the distinct comparator for each event. These are records of pages as inspected on November 21, 2026. Site revisions and browser text-fragment support can change.
- [labels.json](labels.json) documenta separadamente cada decisión de referencia y su fundamento. [predictions.csv](predictions.csv) conserva las 68 salidas, incluidas abstenciones. [results.json](results.json) contains all four 3×3 matrices, explicit numerators/denominators and undefined values as null. The two denominators for coverage distinguish all cases from the sixteen determined cases.
- [inputs.sha256](inputs.sha256), [reference.sha256](reference.sha256) and [readers.sha256](readers.sha256) pin the input data, reference labels and previously published reader files. The full research checkout supplies the adjacent study and v1.1 directories. From this directory run:

```sh
python -B verify_sources.py
python -B replay.py --predictions-only --check
python -B replay.py --check
```

If you have independently downloaded source pages, name each file with its public case ID plus `.html` and run `python -B verify_sources.py --html DIRECTORY`. The verifier reports how many were supplied and checked. For NIST pages it matches the quote in the normalized HTML block and checks the block SHA-256; for USGS pages it checks normalized visible strings without a registered block digest. The text-fragment URL and locator also support manual checking. No remote request is required to replay the predictions.

## Créditos y reutilización · Attribution and reuse

USGS identifies its own writing and information as being in the US public domain. The six excerpts are official USGS or observatory text. Credits and institutional identity accompany the individual URLs. [USGS Copyrights and Credits](https://www.usgs.gov/information-policies-and-instructions/copyrights-and-credits)

NIST's published policy permits distribution and copying of unmarked public information on its sites and requests appropriate credit. Ten excerpts come from NIST-hosted pages and one from NIST's own, explicitly attributed Tech Beat bulletin distributed through its GovDelivery account. For the latter the excerpt comes from the agency's closing editorial item. No separately credited or marked copyrighted contributions were selected. Steve Jefferts is identified as the speaker in his NIST statement. Third-party excerpts retain their source status; the manuscript's CC BY notice does not purport to grant rights in them. Neither agency's seal or endorsement is used. [NIST Copyrights & Disclaimers](https://www.nist.gov/copyrights-disclaimers) · [NIST Tech Beat source bulletin](https://content.govdelivery.com/accounts/USNIST/bulletins/38d58b2)
