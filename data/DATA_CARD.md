# Data Card — `data/processed/urls_unified.parquet`

**Generated:** 2026-11-05 (branch `rebuild/v2`). Rebuilt from scratch by `scripts/ingest_external.py`; all numbers below are computed from the parquet on disk, never fabricated.

## Composition

| Source | family | rows kept | label schema | role |
|---|---|---|---|---|
| malicious_phish.csv | kaggle_like | 522,214 | `type` (benign/phishing) | train_pool |
| PhreshPhish train | phreshphish | 276,729 | `label` | train_pool |
| MURL (Mendeley) | mendeley_academic | 783,702 | `type` (phishing/malware/defacement→phishing; benign/legitimate→benign) | train_pool |
| PhishBD_2026 (Mendeley) | mendeley_academic | 131,167 | `label` 0=benign,1=phishing | train_pool |
| PhreshPhish test | phreshphish | 91,260 | `label` | eval_sealed |
| LegitPhish (Mendeley) | mendeley_academic | 100,873 | `ClassLabel` inverted (0=benign,1=phishing) | eval_sealed |
| Phishing.Database active | fresh_phishing | 766,057 | strings only, labeled phishing | eval_fresh |
| OpenPhish (2026-11-05 snapshot) | fresh_phishing | 300 | community feed terms | eval_fresh |
| Tranco JZPGY top-10k | tranco | 9,502 | benign homepages | eval_tranco |

**Total:** 1,828,468 unique canonical URLs, 594,413+ registrable domains, 655,159 benign / 1,173,309 phishing.

## Columns

`url_raw, url_canonical, label, source, family, split_role, date, brand_target, lang, registrable_domain, host, tld, has_scheme_raw, has_www_raw, has_trailing_slash_raw, hard_negative, hard_positive, collected_at, license, sample_weight`

Canonicalization: lowercase scheme+host, strip scheme, strip `www`/`www2.`, drop default port (80/443), drop fragment, drop lone trailing `/`, repair `hxxps`/`[.]` defangs.

## Splitting & leakage control

- Splits are assigned by **registrable domain** (`tldextract` with private suffixes). Each domain gets exactly one stable role.
- All evaluation domains (eval_sealed, eval_fresh, eval_tranco) are removed from the training pool; asserted zero overlap after dedupe.
- Conflicting labels on the same canonical URL → both copies dropped (6,006 conflicts).
- Cross-source dedupe is by canonical URL (2,349,709 duplicates removed; eval sources outrank training for consistent labels).
- `sample_weight` columns apply per-stratum rebalancing derived from the surface-cue artifact audit; eval rows keep weight 1.0.

## Sources NOT ingested (documented, not fabricated)

`ealvaradob/phishing-dataset` (repo/URLs resolve 404), `PhiUSIIL` (repo not found), `URL-Phish` (repo not found), `Common Crawl` (CDX query deferred). See `docs/DECISIONS.md` D0 and `DOWNLOAD_COMMANDS.md`.

## License & compliance

PhreshPhish (CC BY 4.0, anti-phishing research only), Mendeley datasets (public data, verify licence metadata on Mendeley pages), Tranco (terms; research snapshot), OpenPhish (community feed terms), Phishing.Database (repository licence/terms). **No URL was ever requested or opened; all data are strings only.**
