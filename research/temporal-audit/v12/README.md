# Auditoría temporal de las respuestas de IA · Temporal auditing of AI outputs

**Rubén Abella · SPE Audit · Edición 1.2 · 22 de noviembre de 2026**

[Artículo en español](PAPER_ES.pdf) · [English paper](PAPER_EN.pdf) · [Catálogo de antecedentes (116 fichas)](Prior_art_catalogue.pdf) · [DOI 1.2](https://doi.org/10.5281/zenodo.24447732) · [Volumen histórico 1.1](https://doi.org/10.5281/zenodo.24424024)

El estudio original partió de cuatro misiones espaciales. Sus 96 filas de desarrollo y 16 frases de redacción nueva comparten esos sucesos. El autor desarrolla SPE Audit; la construcción y lectura de materiales contó con asistencia de IA. Ambas cohortes tienen referencias editoriales. Al cambiar la redacción, la regla fechada original detectó 0/8 positivos y remitió 14/16 casos. Conservar los ocho positivos en el denominador permite ver qué queda pendiente de decisión.

En la actualización se volvieron a leer las mismas 112 respuestas en dos condiciones con SmolLM2-135M-Instruct. Un brazo recibió la pregunta, respuesta, corte y las fichas admitidas. El otro recibió además un campo con la fecha histórica del desenlace. En las 16 frases de reto, los dos brazos coincidieron caso por caso: 4/8 positivos detectados, 1/8 falsas alertas entre controles y 11/16 remisiones. En las 96 de desarrollo agregar el campo cambió seis decisiones, con 8/32 positivos detectados en ambos brazos. Los ocho positivos detectados en desarrollo pertenecían a Perseverance: el modelo alertó en las 24 filas de esa misión, incluidos los 16 controles, en los dos brazos. Hubo 224 respuestas de inferencia válidas. Son resultados de una configuración local; los minutos de revisión humana siguen sin medirse.

The original 96 development rows and 16 wording challenges concern the same four events. This follow-up ran the same small local model on the same 112 answers, with and without a separate recorded outcome date. On the 16 wording challenges, both arms alerted on four of eight editorial positives and one of eight controls and referred eleven of sixteen. Publishing the prompt, requests and responses makes these observations inspectable. Labels, dates in admissible cards, and possible knowledge in the model weights have separate evidentiary roles. The author develops the evaluated technology.

| Material | Alcance / scope |
|---|---|
| [Artículo ES](PAPER_ES.md) · [English text](PAPER_EN.md) | Texto accesible del artículo que acompaña a los PDF. |
| [112 comparaciones](paired_decisions.csv) · [Recuentos por cohorte, evento y método](metrics.csv) · [Transiciones entre brazos](transitions.csv) | Same-row review outcomes. Alert precision = true_alerts / alerts when alerts > 0; coverage = decided / rows; sensitivity = true_alerts / positives. |
| [Plan previo](PRIOR_PROTOCOL.md) · [224 huellas de peticiones](plan.json) · [Prompt exacto](prompt.txt) · [Respuestas crudas](receipts.zip) | Local loopback reader, quantized weights, forced choice including REVIEW. Each receipt retains a base64 copy of the complete HTTP response body. |
| [34 sucesos candidatos](candidate_events.csv) · [Diseño de réplica](NEXT_STUDY.md) · [Piloto humano de 16 casos](../post11/open-pilot/) | Proposed future collection, separate from the evaluated four events. The event register contains no new test answers, independent labels or classifier results. |
| [CSV original de 116 referencias](../landscape/bibliography.csv) · [Revisión histórica de 58 entradas](../v11/sources/dating_ledger.csv) | The catalogue distinguishes technical sources from market material, bibliographic leads and administrative context. |
| [Edición 1.1](../v11/) · [Laboratorio posterior](../post11/) | Includes the six-event bilingual cohort, the 17 third-party passages, earlier local model receipts and the public pilot kit. |

### Reproducir la puntuación / reproduce the scoring

Descargue el [ZIP de reproducción de la edición 1.2](Replication_1_2.zip) o clone este repositorio. Zenodo distribuye el mismo ZIP junto al artículo. Desde `research/temporal-audit/v12/`, use Python 3.12:

```sh
python -B score.py
openssl ts -verify -queryfile plan.tsq -in plan.tsr -CAfile /etc/ssl/certs/ca-certificates.crt
openssl ts -verify -data plan.json -in plan.tsr -CAfile /etc/ssl/certs/ca-certificates.crt
```

The two OpenSSL commands verify the signed timestamp against the original request (including its nonce) and the actual plan bytes. The path shown is typical on Linux. Supply your own trusted CA bundle on other platforms. DigiCert returned a timestamp of **2026-11-22 19:23:03 UTC** for the SHA-256 imprint `9402541a361800c9b2f7dddf1ccdb36c8cd6e383c7b46c6a5838f34c0252073e`. The [public pre-run Git commit](https://github.com/joinsnipe/SPE_AUDIT/tree/17c7461a3f1aa1ddf026d315befb54d1d3d68434/research/temporal-audit/v12) fixes the inputs and code. The given timestamp covers this new replay plan. The original examples and their labels were already public.

`score.py` first reconstructs the frozen prompt and checks it against the model's echo in every valid archived response, re-extracts each label, then joins to the earlier published predictions. The default mode checks all three tables byte for byte; `--out DIRECTORY` writes fresh copies. For each method, `human_queue` counts referrals plus technical failures. It does not measure human time. In this run there were no transport or validation errors. A missing alert can mean an automatic OTHER or REVIEW; both stay in the positive denominator.

### Repetir la inferencia / rerun the model

On Linux x86-64, fetch the pinned runtime and weights using the existing downloader; the initial download needs internet. From `v12/`:

```sh
python -B ../post11/reference_reader/download_reference.py /tmp/spe-model
python -B paired.py run /tmp/spe-model/engine/llama-b8058/llama-server /tmp/spe-model/model.gguf /tmp/spe-replay.zip
python -B score.py --archive /tmp/spe-replay.zip --out /tmp/spe-tables
```

Compare the resulting tables with those distributed here. Runtime timing fields can differ even if the labels agree. The original run used CPU, one model slot, greedy decoding and seed 20261122. Supplying model weights does not attest what a remote provider saw. The source of a claim, its date, and the integrity of a recorded packet are separate questions.

**Derechos / rights.** © 2026 Rubén Abella. Texto y figuras originales, CC BY 4.0. Las marcas y los materiales de terceros conservan sus derechos. El software mantiene la licencia BSL 1.1 del [repositorio](../../../LICENSE). The DOI identifies the document edition; linked software, model weights and third-party sources retain their respective terms.
