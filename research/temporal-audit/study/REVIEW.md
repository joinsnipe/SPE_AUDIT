# Reproduction check · Comprobación de reproducibilidad

**21 November 2026 · Internal AI-assisted technical review.** The checks below were performed within the SPE Audit project. They did not involve an external laboratory, independent human adjudication or peer review.

For a single offline check, open the extracted study package and run `python3 verify.py` on Linux or macOS, or `py -3 verify.py` on Windows with Python 3.10 or newer. La comprobación completa usa un directorio temporal y comunica los recuentos del estudio y del piloto.

## Procedure

A temporary ZIP was built from the supplied source, data, baseline files and expected results. It was unpacked into an empty directory. The following commands were run from its package root under CPython 3.12.14 on Linux using only the standard library. No keys, model APIs, network calls or paid services were used for the replay. From the root containing the `study` and `field` directories:

```sh
python3 study/reproduce.py --out reproduced
python3 -m unittest discover -s study -p test_capture.py
python3 study/capture.py reproduced/capsules.jsonl --expected-root 174ca466891bbd35e8c5b208b612d74dddf4984b9e7a31537bf7e02d41447e20
python3 field/recount.py
```

All four regenerated result files matched the supplied files byte for byte: the predictions CSV, capsule JSONL, intervention JSON and summary JSON. The seven capture tests passed. The capsule verifier accepted 124 records. The 112 classification rows reference the correct one-based line, seal, exact output, prompt and all eligible source cards. Eligibility was separately recomputed from ISO calendar dates in the supplied event table. The other 12 records belong to the four three-condition source interventions. Those records are excluded from classification denominators.

## Independent recount of recorded predictions

Counts below were computed directly by grouping CSV rows by split, reference label and prediction; the release's scoring function and stored summary were not used for this recount. Positive denotes an assertion of a completed outcome that occurred later than the cutoff. Each review is an abstention recorded against its actual reference class.

| Split and method | True positive | False positive | True negative | False negative | Review on positive | Review on negative | Decisions / total |
|---|---:|---:|---:|---:|---:|---:|---:|
| Constructed · year rule | 4 | 12 | 52 | 28 | 0 | 0 | 96/96 |
| Constructed · dated matcher | 24 | 0 | 60 | 0 | 8 | 4 | 84/96 |
| Challenge · year rule | 1 | 2 | 6 | 7 | 0 | 0 | 16/16 |
| Challenge · dated matcher | 0 | 0 | 2 | 0 | 8 | 6 | 2/16 |

There are 32 positive cases among 96 constructed rows and eight among 16 challenge rows. The matcher answers two challenge controls and refers every challenge positive for review; its positive predictive value on the challenge is undefined because it emits no positive alarms. The 96 constructed rows contain 29 distinct output texts, owing to deliberate reuse under different cutoffs and some shared control wording. The challenge contains 16 distinct outputs for the same four missions. These counts describe designed cases and do not estimate deployment prevalence or generalisation to an unseen domain.

The field dataset recount reproduced 25 attempts, 22 returned texts, three capacity errors, one historical keyword alarm and zero public year-rule alarms. Internally the 25 rows were paired with the archived records of those attempts. For returned texts we checked original UTF-8 hashes, explicit year features, recorded keyword hits and the historical alarm. The public extracts permit recounting from the released features; reconstructing every original response is outside the scope of the public archive.

The labels are joined after prediction, but the dated matcher is intentionally supplied a retrospective event dictionary with the actual event date and reviewed phrases. That dictionary is evidence available to the evaluator, distinct from the source texts supplied to the local response callback. The selected cases do not validate this dictionary on unseen subjects, prove the historical completeness of the source pool, establish provider-side execution or resolve the causal origin of any statement.

## Resumen en español

Se empaquetaron los componentes en un ZIP temporal, se extrajeron en una carpeta vacía y se repitió la ejecución con CPython 3.12.14 en Linux. Los cuatro archivos resultantes coincidieron byte por byte; pasaron las siete pruebas del adaptador y se verificaron 124 cápsulas. Se cotejaron de forma independiente los textos, las fichas admisibles por fecha y las referencias de las 112 filas de clasificación. Las otras 12 corresponden a intervenciones sobre la selección de fuentes.

La tabla reproduce los recuentos desde el CSV. La comparación principal comprende 96 casos construidos a partir de 29 textos distintos. El reto contiene 16 textos diferentes. En él, el comparador con fechas solo resolvió dos controles y remitió a revisión los ocho positivos y seis controles adicionales. Ningún positivo detectado implica que su precisión positiva carece de denominador en ese reto. En el piloto histórico hubo 22 respuestas entre 25 intentos. Se reprodujeron una alarma por palabras y cero alarmas por años. La revisión es interna y asistida por IA. El archivo de trabajo conserva el registro original del piloto; la publicación ofrece rasgos por respuesta que permiten repetir los recuentos.
