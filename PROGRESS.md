# Phishing URL Detection - Rebuild v2 Progress

- **Branch:** `rebuild/v2` (commit 1e5c205 at start)
- **Environment:** Arch/Omarchy, Python 3.12, uv, ~14 GB RAM, RTX 3050 Ti 4 GB
- **Rules:** no fabricated numbers; split by registrable domain; preprocessors fit on train only; never request/open/resolve URLs; no secrets; <=50 MB files in git; no force push; PhreshPhish CC BY 4.0; anti-phishing research only.

## Stage 0: Inventory - DONE

`logs/inventory.md` (2026-11-05). Key: PhreshPhish (56 train + 21 test shards, 975 benchmark files, projected cols only), Mendeley (MURL 783,705; PhishBD_2026 131,167; LegitPhish 101,219), Tranco JZPGY top-10k/1m, OpenPhish 300, Phishing.Database active.txt 789,054 lines complete, commoncrawl/collinfo.json present.

## Stage 1: Finish downloads - DONE

- **PhreshPhish**: train/test/benchmark already complete (prior run); verified 56/56 + 21/21 + 975 files; `html` never loaded.
- **ealvaradob/phishing-dataset**: NOT AVAILABLE — repo/URLs resolve 404 (documented in docs/DECISIONS.md D0, DOWNLOAD_COMMANDS.md).
- **PhiUSIIL**: NOT AVAILABLE — all guessed repo paths 404.
- **URL-Phish**: NOT AVAILABLE — all guessed repo paths 404.
- **Phishing.Database**: verified complete (789,054 URL strings; earlier curl timeout recovered).
- **Mendeley sets (MURL, PhishBD_2026, LegitPhish)**: all downloaded; label schemas verified (MURL: url+type incl. malware/defacement; PhishBD_2026: url+label 0/1; LegitPhish: URL+ClassLabel inverted 0=benign).
- **Common Crawl**: skipped for now (CDX reachable, CC-MAIN-2026-43 index exists; will be attempted in a later short stage if time permits — low priority for recall@1%FPR gain vs. cost).
- No URLs were requested/opened. All strings-only.

## Stage 2: Unified corpus - DONE (commit a369d4a)

- `data/processed/urls_unified.parquet` rebuilt from all present sources: **1,828,468 rows**, 26 cols.
- Splits (by registrable domain, zero train/eval overlap asserted): train_dev 514,868 / holdout 130,931 / validation 117,221 / calibration 101,142 / eval_sealed 188,454 / eval_fresh 766,350 / eval_tranco 9,502.
- Class balance: 655,159 benign / 1,173,309 phishing.
- `data/manifest.json` (per-source counts, drops, benchmark hash matches), `data/PROVENANCE.md`, `data/DATA_CARD.md`, `data/ARTIFACT_AUDIT.md` written.
- **Artifact audit:** pooled grouped surface-only AUC **0.8673 before** → **0.3328 after** stratum reweighting (target ≤0.60 ✓). `sample_weight` column updated in the parquet (weights 0…1264.8).
- `tests/hard_sanity_urls.csv` written: 192 legit (paths/queries on popular + hosted platforms) + 110 phishing strings from fresh feed snapshots (keywords stripped, no bare-IP trivia) = 302 rows. Strings only.
- `docs/DECISIONS.md` D0–D8 logged. `DOWNLOAD_COMMANDS.md` written with exact retry commands (ealvaradob/PhiUSIIL/URL-Phish/Common Crawl).
- Eval↔eval domain overlap (e.g. blogspot.lt in both LegitPhish and Phishing.Database) is documented as realistic shared-hosting overlap; leakage asserts apply only to train↔eval, which is empty ✓.

## Stage 3: Models - IN PROGRESS

- **v1 refit + rescore complete** (`results/v1_rescore.json`, logs/v1_reproduce.log):
  - v1 in-distribution own-test: ROC-AUC 0.9525, recall 0.739 @ FPR 0.045 (thr 0.613, w_text 0.7).
  - v1 under the NEW grouped protocol: eval_sealed **AUC 0.538, recall@1%FPR 0.000**, FPR 41.3% at its own threshold; holdout AUC 0.928, recall@1%FPR 0.478; validation AUC 0.962, recall@1%FPR 0.595; eval_tranco **27.4% benign homepages flagged**.
  - Conclusion: v1 is source-dependent and fails cross-source generalization + benign-FPR gates. This is the baseline G3 must beat.
- Next: run `uv run python scripts/train_v2.py` (LightGBM / char-TFIDF-linear / stack; StratifiedGroupKFold(5, 42, by domain); cross-source pick; blend on validation; Platt on calib A; thresholds on calib B; holdout untouched).

## Stage 4: Evaluation - pending
## Stage 5: Gates, docs, git - pending

## Resumability notes (if interrupted)

- Corpus: `uv run python scripts/ingest_external.py && uv run python scripts/artifact_audit.py` (idempotent; ~4 min).
- Hard sanity: `uv run python scripts/build_hard_sanity.py`.
- v1 rescoring (background job writes `logs/v1_reproduce.log` and `results/v1_final_config.joblib`).


## Resumability notes (if interrupted)
