# 01 Overview 概念图 — 统计信息

> 对比两种 harness 范式：Magma 官方（全库级宽 API 驱动，1 harness 覆盖多个漏洞）
> vs 本项目（漏洞级定向驱动，每漏洞/每簇一个 harness）。

## 总体数字

- 官方 harness 源码文件：**7** 个（.c/.cc）
- 官方覆盖漏洞：**80** 个
- 生成 harness 文件夹（漏洞簇）：**31** 个
- 生成 harness 文件（含时间戳重复）：**54** 个
- 生成 harness 覆盖漏洞（去重）：**42** 个

- 平均每个官方 harness 覆盖漏洞：11.4 个
- 平均每个生成 harness 覆盖漏洞：1.35 个

## 分库对比

| 库 | 官方 harness 数 | 官方漏洞数 | 生成文件夹数 | 生成文件数 | 生成覆盖漏洞数 |
|---|---|---|---|---|---|
| lua | 1 | 4 | 4 | 5 | 4 |
| libpng | 1 | 7 | 3 | 7 | 5 |
| libsndfile | 1 | 18 | 5 | 6 | 5 |
| libtiff | 1 | 14 | 7 | 12 | 10 |
| libxml2 | 2 | 17 | 10 | 20 | 14 |
| sqlite3 | 1 | 20 | 2 | 4 | 4 |
| **合计** | **7** | **80** | **31** | **54** | **42** |

## 漏洞簇（多对一）结构

生成的 harness 中，同一文件夹 = 多个漏洞共用一个 harness：

- `PNG002_PNG003_PNG005` → 共用 harness `png_check_chunk_length.c`，覆盖 3 个漏洞：PNG002, PNG003, PNG005
- `SQL002_SQL003` → 共用 harness `flattenSubquery.c, selectExpander.c`，覆盖 2 个漏洞：SQL002, SQL003
- `SQL014_SQL018` → 共用 harness `multiSelect.c, sqlite3ExprAddCollateToken.c`，覆盖 2 个漏洞：SQL014, SQL018
- `TIF001_TIF007_TIF0012_TIF017` → 共用 harness `PredictorEncodeTile.c`，覆盖 4 个漏洞：TIF001, TIF007, TIF0012, TIF017
- `XML001_XML017` → 共用 harness `xmlSnprintfElementContent__internal_alias.c`，覆盖 2 个漏洞：XML001, XML017
- `XML002_xml009` → 共用 harness `xmlValidateOneNamespace__internal_alias.c`，覆盖 2 个漏洞：XML002, XML009
- `XML007_XML014_XML015` → 共用 harness `htmlParseChunk__internal_alias.c`，覆盖 3 个漏洞：XML007, XML014, XML015

## 数据质量说明（论文中需处理）

- `SND025/` 文件夹为空（该漏洞尚无生成 harness）。
- `TIF001_TIF007_TIF0012_TIF017`：`TIF0012` 应为 `TIF012`；`TIF017` 在 magma 中不存在（TIF 仅 001–014），需确认原始编号。
- libtiff / libxml2 的官方 harness 中 `tiffcp` / `xmllint` 是编译工具而非源码 harness，未纳入本统计。
