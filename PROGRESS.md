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

## Stage 2: Unified corpus - DONE (final build ~2,012,875 rows + LegitPhish label fix D12)

- Two label bugs found and fixed during the rebuild (both content-verified, never guessed):
  - **PhreshPhish** labels are `benign`/`phish` — mapped via `LABEL_MAP` in ingest (was silently dropped before).
  - **LegitPhish** `ClassLabel`: **0=phishing, 1=benign** (previous mapping inverted the class; sealed AUC 0.016 was the tell). See docs/DECISIONS.md D12.
- Final counts on the corrected corpus — see `data/processed/manifest.json` (rendered docs: `data/DATA_CARD.md`, `data/PROVENANCE.md` from `scripts/render_data_docs.py`).
- **Artifact audit:** pooled grouped surface-only AUC **0.2930** after stratum reweighting (target ≤0.60 ✓).
- `tests/hard_sanity_urls.csv`: 192 legit + 110 non-trivial phishing = 302 rows (strings only).
- `docs/DECISIONS.md` D0–D12. `DOWNLOAD_COMMANDS.md` documents blocked sources (ealvaradob/PhiUSIIL/URL-Phish/Common Crawl CDX).
- Eval↔eval domain overlap (e.g. blogspot.lt) documented as realistic shared-hosting overlap; leakage asserts apply only to train↔eval.

## Stage 3: Models - v1 done; v2 done on D11/D12 corpus; re-running after D12 fix

- **v1 refit + rescore** (`results/v1_rescore.json`): in-distribution own-test ROC-AUC 0.9525; under the grouped protocol: eval_sealed recall@1%FPR 0.0019 / AUC 0.620 pre-D12; eval_tranco 27.4%→23.1% benign flagged at v1 threshold; holdout recall@1%FPR 0.5368. v1 is the G3 bar; its numbers re-generate on every corpus rebuild (script is resumable via `results/v1_checkpoint.joblib`).
- **v2 stack** (`results/model_bundle.joblib`, `results/model_metrics_v2.json`): LGBM-lexical + char-3-5 TF-IDF SGD linear; blended w_text=0.8 (chosen on validation: recall@1% 0.582, AUC 0.948); Platt on calibration half A (a=1.566, b=0.258); thresholds from half B: strict 0.9836 / balanced 0.9345 / sensitive 0.7712. CV on train_dev: char-linear AUC 0.940 / recall@1% 0.537 beats LGBM-lexical 0.834 / 0.305. Char-CNN skipped (torch absent, D9).
- After the D12 label fix everything re-runs from scratch in one chain (current background job): ingest → audit → docs → v1 → train_v2 → evaluate_v2.

## Stage 4: Evaluation - first pass done pre-D12; chain re-running

- Pre-D12 results (`results/v2_evaluation.json`): holdout recall@1%FPR 0.5855 (CI 0.564–0.612), AUC 0.9474; Tranco FPR 0.19% ✓; PhreshPhish test AUC 0.9425 / recall@1% 0.4843; sealed slice was polluted by the LegitPhish inversion; eval_fresh is phishing-only by construction (flag-share 23.6% at balanced).
- The re-run will regenerate `results/v2_evaluation.json`, `results/final_holdout.json` (touched once, from the fresh bundle+corpus pair), `results/hard_sanity_results.json`, `results/before_vs_after.md`.

## Stage 5: Gates, docs, git - pending

- `scripts/gates.py` (G1–G5) runs after the chain; then README render (`scripts/render_readme.py`), tests, commit, push `rebuild/v2`, then merge to main + tag only if all gates pass.

## Resumability notes (if interrupted)

- Full chain (idempotent, ~1 h): `uv run python scripts/ingest_external.py && uv run python scripts/artifact_audit.py && uv run python scripts/render_data_docs.py && uv run python scripts/v1_reproduce.py && uv run python scripts/train_v2.py && uv run python scripts/evaluate_v2.py`.
- `train_v2.py`, `evaluate_v2.py`, `v1_reproduce.py` are checkpoint/cache-resumable: CV probs in `results/cv_probs_*.npy`, features in `results/feat_cache_*.npz` (content-keyed), v1 in `results/v1_checkpoint.joblib`, eval slice scores in `results/slice_*_probs_*.npy` (bundle-keyed).
- If a corpus-level label definition changes again (ingest script), invalidate `results/cv_probs_*.npy results/feat_cache_*.npy results/v1_checkpoint.joblib results/final_holdout.json results/slice_*_probs_*.npy` first and re-run the chain; log the reason in docs/DECISIONS.md.
- Hard sanity: `uv run python scripts/build_hard_sanity.py`; docs: `scripts/render_data_docs.py`; README: `scripts/render_readme.py` (needs all results JSONs); gates: `uv run python scripts/gates.py`.
