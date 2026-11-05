# Data Card — `data/processed/urls_unified.parquet`

**Generated:** from `data/processed/manifest.json` (created_at 2026-11-05T03:13:07.271485+00:00) by
`scripts/render_data_docs.py`. No count on this page is hand-typed.

- Total rows: **2,013,066** (630,796 benign / 1,382,270 phishing)
- Registrable domains: **918,237**
- Conflicting-label URLs removed: **5,461**
- Training rows removed to keep evaluation domains out of the train pool: **595,346**

## Per-source, per-class counts (rows kept)

```text
label              benign  phishing
family                             
fresh_phishing          0    766316
kaggle_like        254169     60422
mendeley_academic  176529    367462
phreshphish        190611    188070
tranco               9487         0
```

## Split roles (by registrable domain; zero train/eval overlap asserted)

```text
label        benign  phishing   total
split_role                           
calibration   55960     58614  114574
eval_fresh        0    766316  766316
eval_sealed  128469    134752  263221
eval_tranco    9487         0    9487
holdout       76144     71417  147561
train_dev    291572    289200  580772
validation    69164     61971  131135
```

## Label normalization

Source labels are normalized to `benign`/`phishing`:
- PhreshPhish: `benign`/`phish` → `benign`/`phishing` (mapped, see scripts/ingest_external.py)
- MURL `type`: `legitimate`/`benign` → benign; `phishing`/`malware`/`defacement` → phishing
- PhishBD_2026 `label`: 0/1 → benign/phishing
- LegitPhish `ClassLabel`: **0=phishing, 1=benign** (0-label rows are IP-hosted droppers and
  malware URLs; 1-label rows are normal small-business sites — verified by content inspection
  after the model flagged a sealed-slice AUC of 0.016 under the previous mapping)
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
    "matched_to_test_urls": 25918,
    "base_rate_label": "005"
  },
  "benchmark-010": {
    "hashes": 26640,
    "matched_to_test_urls": 26187,
    "base_rate_label": "010"
  },
  "benchmark-050": {
    "hashes": 26727,
    "matched_to_test_urls": 26274,
    "base_rate_label": "050"
  },
  "benchmark-100": {
    "hashes": 26419,
    "matched_to_test_urls": 25967,
    "base_rate_label": "100"
  },
  "benchmark-500": {
    "hashes": 23755,
    "matched_to_test_urls": 23358,
    "base_rate_label": "500"
  }
}
```

- Tranco list id: **JZPGY** (created 2026-11-04)
- `no_url_requests`: **True**
