# Temporal auditing of AI outputs · Zenodo

**Rubén Abella publicó la edición documental 1.1 el 21 de noviembre de 2026**. El registro de Zenodo contiene el artículo completo en inglés y español. Rubén Abella figura como autor único, sin afiliación ni ORCID consignados. Los archivos publicados se llaman `SPE_Audit_1_1_EN.pdf` y `SPE_Audit_1_1_ES.pdf`. Se comprobó el 21 de noviembre de 2026 que su contenido coincide byte a byte con las copias locales `FULL_EN.pdf` y `FULL_ES.pdf`, respectivamente. [Registro publicado](https://zenodo.org/records/24424024) · [DOI de la edición 1.1](https://doi.org/10.5281/zenodo.24424024).

**Cita de esta versión.** Abella, Rubén (2026). *Temporal auditing of AI outputs* (versión 1.1). Zenodo. https://doi.org/10.5281/zenodo.24424024

El DOI de concepto para el conjunto de versiones es [10.5281/zenodo.24424023](https://doi.org/10.5281/zenodo.24424023).

## Derechos y software relacionado

El texto y las figuras originales del artículo se distribuyen bajo **Creative Commons Attribution 4.0 International**. Las marcas quedan aparte y el material de terceros conserva sus condiciones. El código SPE se enlaza en GitHub y mantiene la **Business Source License 1.1** con las condiciones y avisos del repositorio. El registro del artículo contiene únicamente los dos PDF. [Licencia del artículo](https://creativecommons.org/licenses/by/4.0/) · [Código de reproducción](https://github.com/joinsnipe/SPE_AUDIT/tree/main/research/temporal-audit) · [Licencia del software](https://github.com/joinsnipe/SPE_AUDIT/blob/4f431863c63df6bba69ac85bdbf8defe36523d21/LICENSE).

El proyecto prevé una sección de investigación en SPE TRACE para presentar el estudio en ambos idiomas. Zenodo conserva la edición publicada y su DOI. [Sección prevista en inglés](https://www.spetrace.com/research/temporal-audit) · [Sección prevista en español](https://www.spetrace.com/es/research/temporal-audit).

## Verificar los archivos sin conexión

Desde la carpeta `v11`, ejecutar:

```sh
python -B deposit/prepare.py
python -B deposit/verify.py deposit/zenodo-deposit-1.1.zip --edition-dir .
```

El primer comando reconstruye el ZIP local con una copia de los dos PDF bajo `paper/files/`. El segundo coteja bytes, tamaños, SHA-256, autor, DOI y derechos. La ficha `paper/metadata.json`, la referencia `reference/software.json`, esta guía y el manifiesto son materiales auxiliares del ZIP local. El guion no modifica el registro de Zenodo ni los PDF. Las opciones `--paper-en` y `--paper-es` permiten indicar rutas alternativas; `--metadata-only` genera una copia local de las fichas sin los PDF.
