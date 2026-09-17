# 01 Overview Concept Diagram — Statistics

> Comparing two harness paradigms: Magma official (library-wide broad API driven, 1 harness covers multiple vulnerabilities)
> vs this project (vulnerability-level targeted driving, one harness per vulnerability/cluster).

## Overall Numbers

- Official harness source files: **7** (.c/.cc)
- Vulnerabilities covered officially: **80**
- Generated harness folders (vulnerability clusters): **31**
- Generated harness files (including timestamp duplicates): **54**
- Vulnerabilities covered by generated harness (deduplicated): **42**

- Average vulnerabilities covered per official harness: 11.4
- Average vulnerabilities covered per generated harness: 1.35

## Per-Library Comparison

| Library | Official harness count | Official vulnerability count | Generated folder count | Generated file count | Generated covered vulnerability count |
|---|---|---|---|---|---|
| lua | 1 | 4 | 4 | 5 | 4 |
| libpng | 1 | 7 | 3 | 7 | 5 |
| libsndfile | 1 | 18 | 5 | 6 | 5 |
| libtiff | 1 | 14 | 7 | 12 | 10 |
| libxml2 | 2 | 17 | 10 | 20 | 14 |
| sqlite3 | 1 | 20 | 2 | 4 | 4 |
| **Total** | **7** | **80** | **31** | **54** | **42** |

## Vulnerability Cluster (Many-to-One) Structure

In the generated harnesses, the same folder = multiple vulnerabilities sharing one harness:

- `PNG002_PNG003_PNG005` → shared harness `png_check_chunk_length.c`, covering 3 vulnerabilities: PNG002, PNG003, PNG005
- `SQL002_SQL003` → shared harness `flattenSubquery.c, selectExpander.c`, covering 2 vulnerabilities: SQL002, SQL003
- `SQL014_SQL018` → shared harness `multiSelect.c, sqlite3ExprAddCollateToken.c`, covering 2 vulnerabilities: SQL014, SQL018
- `TIF001_TIF007_TIF0012_TIF017` → shared harness `PredictorEncodeTile.c`, covering 4 vulnerabilities: TIF001, TIF007, TIF0012, TIF017
- `XML001_XML017` → shared harness `xmlSnprintfElementContent__internal_alias.c`, covering 2 vulnerabilities: XML001, XML017
- `XML002_xml009` → shared harness `xmlValidateOneNamespace__internal_alias.c`, covering 2 vulnerabilities: XML002, XML009
- `XML007_XML014_XML015` → shared harness `htmlParseChunk__internal_alias.c`, covering 3 vulnerabilities: XML007, XML014, XML015

## Data Quality Notes (To Be Addressed in the Paper)

- The `SND025/` folder is empty (no generated harness for this vulnerability yet).
- `TIF001_TIF007_TIF0012_TIF017`: `TIF0012` should be `TIF012`; `TIF017` does not exist in magma (TIF only has 001–014), the original numbering needs to be confirmed.
- In the official harnesses of libtiff / libxml2, `tiffcp` / `xmllint` are compilation tools rather than source harnesses, and are not included in this statistic.
