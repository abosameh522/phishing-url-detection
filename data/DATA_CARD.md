# Data Card — `data/processed/urls_unified.parquet`

**Generated:** from `data/processed/manifest.json` (created_at 2026-11-05T02:47:37.340964+00:00) by
`scripts/render_data_docs.py`. No count on this page is hand-typed.

- Total rows: **2,012,875** (654,874 benign / 1,358,001 phishing)
- Registrable domains: **917,633**
- Conflicting-label URLs removed: **6,080**
- Training rows removed to keep evaluation domains out of the train pool: **594,918**

## Per-source, per-class counts (rows kept)

```text
label              benign  phishing
family                             
fresh_phishing          0    766316
kaggle_like        254456     60695
mendeley_academic  200007    342873
phreshphish        190924    188117
tranco               9487         0
```

## Split roles (by registrable domain; zero train/eval overlap asserted)

```text
label        benign  phishing   total
split_role                           
calibration   55889     58636  114525
eval_fresh        0    766316  766316
eval_sealed  152573    110029  262602
eval_tranco    9487         0    9487
holdout       75925     71391  147316
train_dev    291642    289535  581177
validation    69358     62094  131452
```

## Label normalization

Source labels are normalized to `benign`/`phishing`:
- PhreshPhish: `benign`/`phish` → `benign`/`phishing` (mapped, see scripts/ingest_external.py)
- MURL `type`: `legitimate`/`benign` → benign; `phishing`/`malware`/`defacement` → phishing
- PhishBD_2026 `label`: 0/1 → benign/phishing
- LegitPhish `ClassLabel`: inverted (0=benign, 1=phishing); the inverted flag is verified upstream
- Kaggle `malicious_phish.csv type`: only `benign`/`phishing` kept (defacement/malware dropped)
- Feeds (OpenPhish, Phishing.Database): labeled phishing by construction; strings only

## Columns

url_raw, url_canonical, label, source, family, split_role, date, brand_target, lang,
registrable_domain, host, tld, has_scheme_raw, has_www_raw, has_trailing_slash_raw,
hard_negative, hard_positive, collected_at, license, sample_weight

Canonicalization: lowercase scheme+host, strip scheme, strip `www`/`www2.`, drop default port,
drop fragment, drop lone trailing `/`, repair `hxxps`/`[.]` defangs.

## Sources NOT ingested (documented, never fabricated)

{
  "ealvaradob/phishing-dataset": "repo/URLs resolve 404 (unavailable); see docs/DECISIONS.md D0",
  "MURL": "ingested",
  "PhishBD_2026": "ingested",
  "PhiUSIIL": "repo not found (404)",
  "URL-Phish": "repo not found (404)",
  "LegitPhish": "ingested",
  "Common Crawl": "CDX query deferred - not downloaded in this run"
}

## Licence and compliance

PhreshPhish CC BY 4.0 (anti-phishing research only); Mendeley public datasets (licence metadata
checked on their public pages); Tranco JZPGY snapshot (terms; research snapshot); OpenPhish
community feed terms; Phishing.Database repository licence. **No URL was ever requested,
resolved or opened; all data are strings.** PhreshPhish `html` column: never loaded
(`phresh_html_loaded` = False).

## PhreshPhish benchmark sets (sealed; evaluation only)

Hash lists are SHA-256 of the raw URL string; matched to local test rows (string-only; never queried online).

```text
{
  "benchmark-005": {
    "hashes": 26370,
    "matched_to_test_urls": 25919,
    "base_rate_label": "005"
  },
  "benchmark-010": {
    "hashes": 26640,
    "matched_to_test_urls": 26188,
    "base_rate_label": "010"
  },
  "benchmark-050": {
    "hashes": 26727,
    "matched_to_test_urls": 26275,
    "base_rate_label": "050"
  },
  "benchmark-100": {
    "hashes": 26419,
    "matched_to_test_urls": 25968,
    "base_rate_label": "100"
  },
  "benchmark-500": {
    "hashes": 23755,
    "matched_to_test_urls": 23359,
    "base_rate_label": "500"
  }
}
```

- Tranco list id: **JZPGY** (created 2026-11-04)
- `no_url_requests`: **True**
