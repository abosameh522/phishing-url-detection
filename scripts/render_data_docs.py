"""Render DATA_CARD.md / PROVENANCE.md strictly from data/processed/manifest.json
and data/processed/urls_unified.parquet so every count is generated, never hand-typed."""
from pathlib import Path
import json
import pandas as pd
import numpy as np

m = json.loads(Path("data/processed/manifest.json").read_text())
df = pd.read_parquet("data/processed/urls_unified.parquet")

src = m["sources_kept"]
n_rows = m["rows_kept"]
by_class = m["class_balance"]
splits = m["split_counts"]
bench = m.get("phresh_benchmark_file_summary", {})
rows = len(df)


def fam_counts():
    return df.groupby(["family", "label"]).size().unstack(fill_value=0)


def split_table():
    t = df.groupby(["split_role", "label"]).size().unstack(fill_value=0)
    t["total"] = t.sum(axis=1)
    return t


ft = fam_counts().to_string()
st = split_table().to_string()

data_card = f"""# Data Card — `data/processed/urls_unified.parquet`

**Generated:** from `data/processed/manifest.json` (created_at {m['created_at']}) by
`scripts/render_data_docs.py`. No count on this page is hand-typed.

- Total rows: **{n_rows:,}** ({by_class.get('benign', 0):,} benign / {by_class.get('phishing', 0):,} phishing)
- Registrable domains: **{m['registrable_domains']:,}**
- Conflicting-label URLs removed: **{m['conflicting_urls_removed']:,}**
- Training rows removed to keep evaluation domains out of the train pool: **{m['rows_dropped'].get('training_rows_removed_for_eval_domain_overlap', 0):,}**

## Per-source, per-class counts (rows kept)

```text
{ft}
```

## Split roles (by registrable domain; zero train/eval overlap asserted)

```text
{st}
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

{json.dumps(m['sources_skipped'], indent=2)}

## Licence and compliance

PhreshPhish CC BY 4.0 (anti-phishing research only); Mendeley public datasets (licence metadata
checked on their public pages); Tranco JZPGY snapshot (terms; research snapshot); OpenPhish
community feed terms; Phishing.Database repository licence. **No URL was ever requested,
resolved or opened; all data are strings.** PhreshPhish `html` column: never loaded
(`phresh_html_loaded` = {m['phresh_html_loaded']}).

## PhreshPhish benchmark sets (sealed; evaluation only)

Hash lists are SHA-256 of the raw URL string; matched to local test rows (string-only; never queried online).

```text
{json.dumps(bench, indent=2)}
```

- Tranco list id: **{m['tranco_list_id']}** (created {m['tranco_created_on']})
- `no_url_requests`: **{m['no_url_requests']}**
"""

prov = f"""# Provenance — unified corpus

Rendered by `scripts/render_data_docs.py` from `data/processed/manifest.json`
(created {m['created_at']}). Everything below is reproducible from the two files.

- rows kept: {n_rows:,}
- benign / phishing: {by_class.get('benign', 0):,} / {by_class.get('phishing', 0):,}
- registrable domains: {m['registrable_domains']:,}
- kept per source: {json.dumps(src)}
- drops: {json.dumps(m['rows_dropped'])}
- conflicting_url removals: {m['conflicting_urls_removed']:,}
- eval_overlap removals from train: {m['rows_dropped'].get('training_rows_removed_for_eval_domain_overlap', 0):,}
- split counts: {json.dumps(splits)}
- PhreshPhish benchmark hash matching: {json.dumps(bench)}
- tranco: id={m['tranco_list_id']} created={m['tranco_created_on']}
- no_url_requests: {m['no_url_requests']}
- phresh_columns_read: {m['phresh_columns_read']}
- phresh_html_loaded: {m['phresh_html_loaded']}
"""

Path("data/DATA_CARD.md").write_text(data_card)
Path("data/PROVENANCE.md").write_text(prov)
print("wrote data/DATA_CARD.md and data/PROVENANCE.md from manifest")
