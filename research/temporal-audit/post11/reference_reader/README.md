# Local semantic reference reader · Lector semántico local

[Protocol and results in English](reader_en.md) · [Protocolo y resultados en español](reader_es.md)

| Public dataset | Agreed with reference | Valid JSON and bounded quote in each pass | Identical structured responses across passes |
|---|---:|---:|---:|
| Previously published EN/ES challenge | 12/48 | 48/48 | 48/48 |
| Third-party English passages | 1/17 | 17/17 | 17/17 |

El modelo se repitió en dos procesos por conjunto. El único acierto entre los textos ingleses de terceros fue el envío a revisión de un caso ambiguo. En ambos conjuntos, la validez del JSON y la coincidencia entre pases fueron muy superiores al acuerdo con la referencia. [Denominadores, cobertura y huellas](summary.csv) · [Matrices por pase](confusion.csv)

The two evidence packages contain the sealed input, original requests and response bodies, per-case hashes, both passes, the unblinded key, reference and scores. Each archive can be verified offline. The packages contain no weights or runtime binaries. [48-case receipts](replay48.zip) · [17-case receipts](external17.zip) · [Offline verifier](evidence.py) · [Exact scientific prompt](prompt_v1.txt)
