# Decisions Log — Phishing URL Detection Rebuild v2

## D0 — Skip unavailable external sources
- **Sources attempted but not obtainable**: `ealvaradob/phishing-dataset` (config `urls`), `PhiUSIIL`, `URL-Phish`. GitHub repo/file URLs resolve to 404 / are blocked by the network stack (HTTPError with no status). They are NOT fabricated into the corpus.
- **Decision**: Document as unavailable; proceed with sources actually present on disk. `DOWNLOAD_COMMANDS.md` lists the exact commands for later retry.
- No leakage: these datasets never enter the corpus.

## D1 — PhreshPhish column projection already satisfied
- All 56 train + 21 test shards + 975 benchmark hash-list files downloaded in the prior run with projected reads (`url,label,target,date,lang`). The `html` column was never requested and is absent. Verified: `df.columns == ['url','label','target','date','lang']` in the earlier log lines and no `html` in any shard.
- **Decision**: Treat PhreshPhish as complete; reuse shards verbatim (sha256 of parquet on next run for resumability).

## D2 — Rebuild unified parquet from scratch
- The existing `data/processed/urls_unified.parquet` (1,291,882 rows) was produced by a now-removed script (`prepare_data.py` in the prior agent's run). Manifests and `PROVENANCE.md`/`ARTIFACT_AUDIT.md` are stale/incomplete.
- **Decision**: Re-run the ingest (`scripts/ingest_external.py` updated) end-to-end so every number in `manifest.json`, `PROVENANCE.md`, `DATA_CARD.md`, and `ARTIFACT_AUDIT.md` is generated from the current parquet. Skip the rebuild only if a checksum-stable rebuild file exists.

## D3 — Train vs evaluation role assignment
- `train_pool`: `malicious_phish.csv`, `ealvaradob` (none), MURL-Phishing-family, PhishBD_2026, PhreshPhish train.
- `eval_fresh`: OpenPhish (community feed terms), Phishing.Database (repository licence).
- `eval_sealed`: PhreshPhish test (CC BY 4.0, benchmarked), benchmark hash-matches.
- `eval_tranco`: Tranco JZPGY top-10k homepages (never features, never training negatives).
- `train_dev`/`validation`/`calibration`/`holdout`: hashed subsets of `train_pool` only, by registrable domain.
- **Decision**: One registrable domain → one stable role, enforced by assert after dedupe (domains in eval roles are removed from train_pool).

## D4 — Canonicalization
- `scripts/ingest_external.py` already canonicalizes: lowercase scheme+host, strip `www`/`www2.` prefixes, drop default ports (80/443), drop fragment, drop lone trailing `/`, repair `hxxp[s]`/`[.]` defangs. `tests/test_pipeline.py` G2 asserts group-invariance (`https://www.google.com/` ≡ `google.com`).

## D5 — Label conflicts → drop both copies
- If the same canonical URL carries conflicting labels across sources, drop both copies (conservative, zero leakage). Eval sources outrank training for tie-breaking on consistent labels.

## D6 — Sample weights from surface-cue audit
- `scripts/artifact_audit.py` computes per-stratum weights so a surface-only classifier trained on train_dev/validation/calibration stays ≤0.60 grouped AUC. Weights go into `sample_weight` column; eval rows stay weight 1.

## D7 — Model protocol
- StratifiedGroupKFold (n_splits=5, seed=42) by registrable domain; lexical-only features (no Tranco rank, no reputation); final pick by cross-source recall@1% FPR; thresholds chosen on a third slice; calibration checked via histograms + reliability curve.

## D8 — Gates
- G3 (Tranco FPR ≤2% + cross-source recall > v1) must run against the live Tranco top-10k homepage file; v1 re-scored from notebook cells via nbformat.
