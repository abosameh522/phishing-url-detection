# Provenance — unified corpus

Built by `scripts/ingest_external.py` (2026-11-05) from the following local snapshots:

## Training pool (`train_pool`)

- **malicious_phish.csv** — local Kaggle-style snapshot (522,214 rows; `type` column). Licence not embedded in the file → treated as provenance-uncertain, used for development only.
- **PhreshPhish train** (56 shards) — Hugging Face `abosameh522/phishing-url-detection`, projected reads of `url,label,target,date,lang` only. CC BY 4.0; anti-phishing research only. 276,729 rows after canonical dedupe.
- **MURL** (Mendeley public data, 783,702 rows; `url`/`type` incl. phishing/malware/defacement) — 2020 dataset, Mendeley dataset `5fk24y4xmg`.
- **PhishBD_2026** (Mendeley public data, 131,167 rows; `url`/`label` 0=benign,1=phishing) — 2026 dataset, Mendeley `8d6zsfwc7z`.
- **PhreshPhish train** contributes 276,729 rows.

## Evaluation — sealed (`eval_sealed`)

- **PhreshPhish test** (21 shards; 91,260 rows; CC BY 4.0) — used as the benchmarked sealed set; benchmark hash-lists (975 files) matched against it (strings only).
- **LegitPhish** (Mendeley, 100,873 rows; `URL`/`ClassLabel` inverted 0=benign,1=phishing) — 2021 dataset, Mendeley `hx4m73v2sf`.

## Evaluation — fresh (`eval_fresh`)

- **Phishing.Database active** (789,054 URL strings) — repository feed, downloaded as strings only, never dereferenced.
- **OpenPhish** (2026-11-05 snapshot, 300 rows) — community feed terms.

## Evaluation — Tranco (`eval_tranco`)

- **Tranco JZPGY top-10k** (9,502 domains, Nov 4 2026 list) — served as homepages (`https://domain/`), never used as a feature and never as training negatives.

## Ingest hygiene

- Dedupe by canonical URL across all sources; conflicting labels removed (6,006 URLs dropped); duplicates kept 2,349,709.
- All evaluation domains removed from the training pool; zero train/eval overlap asserted.
- `sample_weight` computed from the surface-cue artifact audit (pooled grouped AUC 0.8673 before → 0.3328 after stratum reweighting, target ≤0.60).

## Not ingested

`ealvaradob/phishing-dataset`, `PhiUSIIL`, `URL-Phish` (repositories not found/404), `Common Crawl` (deferred). No data was fabricated.
