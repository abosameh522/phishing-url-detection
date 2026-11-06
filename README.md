# Phishing URL Detection v2

**Ahmed Sameh**

A leakage-resistant URL-only phishing detector. It canonicalizes equivalent inputs, splits by
registrable domain, trains a lexical + character-n-gram stack, and exposes one predictor through
FastAPI and Streamlit. It never resolves, crawls, or downloads a submitted URL. Every number below
is generated from `results/*.json` by `scripts/render_readme.py`.

## Why v2 exists

The v1 notebook looked strong in-distribution (its own test ROC-AUC 0.951)
but collapses under a domain-grouped, cross-source protocol: on the sealed PhreshPhish-test slice its
recall@1%FPR is 0.683 and it flags
20.4% of benign
Tranco homepages. v2 was rebuilt to avoid those collection artifacts.

## Measured results

| slice | model | rows | recall@1%FPR | ROC-AUC | AP |
|---|---|---:|---:|---:|---:|
| eval_sealed | v1 (refit on same pool) | 263,221 | 0.683 | 0.960 | 0.966 |
| holdout | v1 (refit on same pool) | 154,963 | 0.544 | 0.940 | 0.938 |
| eval_tranco | v1 (refit on same pool) | 2,766 | n/a | n/a | 0.000 |
| validation | v1 (refit on same pool) | 135,148 | 0.637 | 0.967 | 0.964 |
| eval_sealed | **v2** | 263,221 | 0.706 | 0.961 | 0.968 |
| eval_fresh | **v2** | 766,316 | n/a | n/a | n/a |
| holdout (final) | **v2** | 154,963 | 0.569 | 0.945 | 0.944 |

| holdout (touched once) | 1% FPR | 0.569 | 0.010 | — | 0.945 |
| holdout (touched once) | 5% FPR | 0.749 | 0.050 | — | 0.945 |
| holdout (touched once) | AP | — | — | — | 0.944 |


## Held-out evaluation (final)

154963 holdout URLs grouped by registrable domain — touched exactly once.
Hard sanity fixtures: overall accuracy **0.825** (legitimate 0.958 / phishing 0.591 at the balanced threshold).

## CV model comparison (train_dev, StratifiedGroupKFold 5 seeds × domains, seed 42)

| model family | ROC-AUC | AP | recall@1%FPR | recall@5%FPR |
|---|---:|---:|---:|---:|
| lgbm | 0.832 | 0.840 | 0.306 | 0.452 |
| lgbm_light | 0.814 | 0.821 | 0.270 | 0.410 |
| tfidf_char_linear | 0.939 | 0.942 | 0.535 | 0.727 |
| stack(w_text=0.3) | 0.910 | 0.915 | 0.455 | 0.627 |
| stack(w_text=0.5) | 0.936 | 0.939 | 0.506 | 0.730 |
| stack(w_text=0.7) | 0.943 | 0.946 | 0.552 | 0.745 |


## Cross-source recall (threshold from other families' benign OOF scores)

| source family (in train_dev) | phishing rows | recall@1%FPR | recall@0.1%FPR |
|---|---:|---:|---:|
| commoncrawl | 0 | n/a | n/a |
| kaggle_like | 38,159 | 0.112 | 0.050 |
| mendeley_academic | 186,043 | 0.284 | 0.141 |
| phreshphish | 69,430 | 0.447 | 0.238 |
| tranco | 0 | n/a | n/a |


## Calibration and thresholds

Platt risk-score mapping fit on calibration half A; thresholds chosen on half B: `strict` = 0.9864, `balanced` = 0.9346, `sensitive` = 0.7599. Scores are calibrated to this corpus mix, not real-world prevalence, and are not deployment probabilities.

## Gates

**FAILED — see results/gates.json**
G3 (real-world) is measured with limited external data; any failure is documented in `results/gates.json` and `docs/LIMITS.md`.

## Run locally

```bash
uv sync
make gates
uv run uvicorn phishing_url_detection.api:app --reload --port 8000
uv run streamlit run app/streamlit_app.py
```

```bash
curl -X POST http://127.0.0.1:8000/predict -H 'content-type: application/json' -d '{"url":"https://www.google.com/","mode":"balanced"}'
```

The API returns a calibrated lexical risk score (not a real-world probability), class, threshold, canonical URL, reasons, and model version.
`strict` / `balanced` / `sensitive` select the stored thresholds.

## Data and protocol

Unified corpus: **2,044,164** URLs<a name=corpus> (656,858 benign /
1,387,306 phishing) across 918,238 registrable domains.
Split roles by domain hash: eval_fresh 766,316, train_dev 604,371, eval_sealed 263,221, holdout 154,963, validation 135,148, calibration 117,379, eval_tranco 2,766.
Preprocessors are fit on train roles only; zero train/eval domain overlap is asserted in G4.
See `data/DATA_CARD.md` and `data/PROVENANCE.md` (rendered from `data/processed/manifest.json`).

## Limitations and ethics

Lexical-only: no page content, DNS, WHOIS, reputation, or liveness. New-domain drift,
hosted-platform ambiguity, and adversarial obfuscation can reduce recall. No URL string is ever
requested or resolved. Use for anti-phishing research and defensive triage only.
