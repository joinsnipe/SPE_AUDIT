# Análisis de generalización y protocolo de traducción · Generalization analysis and translation protocol

**Rubén Abella · SPE Audit.** Análisis posterior de las 160 respuestas ya publicadas y un protocolo de validación humana pendiente. Post-release analysis of 160 published responses and a prospective human-validation protocol.

| Material | Español | English |
|---|---|---|
| Interpretación y cifras · Interpretation and results | [Análisis en español](analysis_es.md) | [English analysis](analysis_en.md) |
| Formularios humanos, aún sin respuestas · Blank prospective human worksheets | [Protocolo y formularios](backtranslation.md) | [Protocol and worksheets](backtranslation.md) |

`python3 -B analyze.py` coteja las decisiones y salidas. `python3 -B analyze.py --out DIR` genera una copia en otro directorio. Conservar esta carpeta como `research/temporal-audit/post11/generalization/` junto a `study/` y `v11/`.

Run `python3 -B analyze.py` to verify archived decisions and outputs, or add `--out DIR` to regenerate the CSVs elsewhere. Keep the original relative paths to the published `study/` and `v11/` directories. [Input inventory](inputs.json) · [Reanalysis program](analyze.py)
