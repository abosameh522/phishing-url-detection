# Phishing URL Detection v2

**Ahmed Sameh**

A leakage-resistant URL-only phishing detector. It canonicalizes equivalent inputs, splits by
registrable domain, trains a lexical + character-n-gram stack, and exposes one predictor through
FastAPI and Streamlit. It never resolves, crawls, or downloads a submitted URL. Every number below
is generated from `results/*.json` by `scripts/render_readme.py`.

## Why v2 exists

The v1 notebook looked strong in-distribution (its own test ROC-AUC 0.953)
but collapses under a domain-grouped, cross-source protocol: on the sealed PhreshPhish-test slice its
recall@1%FPR is 0.677 and it flags
25.5% of benign
Tranco homepages. v2 was rebuilt to avoid those collection artifacts.

## Measured results

| slice | model | rows | recall@1%FPR | ROC-AUC | AP |
|---|---|---:|---:|---:|---:|
| eval_sealed | v1 (refit on same pool) | 263,221 | 0.677 | 0.959 | 0.966 |
| holdout | v1 (refit on same pool) | 147,561 | 0.536 | 0.936 | 0.939 |
| eval_tranco | v1 (refit on same pool) | 9,487 | n/a | n/a | 0.000 |
| validation | v1 (refit on same pool) | 131,135 | 0.641 | 0.967 | 0.965 |
| eval_sealed | **v2** | 263,221 | 0.707 | 0.963 | 0.969 |
| eval_fresh | **v2** | 766,316 | n/a | n/a | n/a |
| holdout (final) | **v2** | 147,561 | 0.562 | 0.946 | 0.947 |

| holdout (touched once) | 1% FPR | 0.562 | 0.010 | — | 0.946 |
| holdout (touched once) | 5% FPR | 0.747 | 0.050 | — | 0.946 |
| holdout (touched once) | AP | — | — | — | 0.947 |


## Held-out evaluation (final)

147561 holdout URLs grouped by registrable domain — touched exactly once.
Hard sanity fixtures: overall accuracy **0.785** (legitimate 0.995 / phishing 0.418 at the balanced threshold).

## CV model comparison (train_dev, StratifiedGroupKFold 5 seeds × domains, seed 42)

| model family | ROC-AUC | AP | recall@1%FPR | recall@5%FPR |
|---|---:|---:|---:|---:|
| lgbm | 0.833 | 0.848 | 0.301 | 0.458 |
| lgbm_light | 0.815 | 0.831 | 0.280 | 0.421 |
| tfidf_char_linear | 0.940 | 0.945 | 0.535 | 0.727 |
| stack(w_text=0.3) | 0.911 | 0.919 | 0.453 | 0.641 |
| stack(w_text=0.5) | 0.936 | 0.942 | 0.512 | 0.730 |
| stack(w_text=0.7) | 0.943 | 0.947 | 0.554 | 0.742 |


## Cross-source recall (threshold from other families' benign OOF scores)

| source family (in train_dev) | phishing rows | recall@1%FPR | recall@0.1%FPR |
|---|---:|---:|---:|
| kaggle_like | 36,488 | 0.108 | 0.053 |
| mendeley_academic | 184,220 | 0.282 | 0.139 |
| phreshphish | 68,492 | 0.438 | 0.235 |


## Calibration and thresholds

Platt calibration fit on calibration half A; thresholds chosen on half B: `strict` = 0.9864, `balanced` = 0.9366, `sensitive` = 0.7678.

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

The API returns the probability, class, threshold, canonical URL, top reasons, and model version.
`strict` / `balanced` / `sensitive` select the stored thresholds.

## Data and protocol

Unified corpus: **2,013,066** URLs<a name=corpus> (630,796 benign /
1,382,270 phishing) across 918,237 registrable domains.
Split roles by domain hash: eval_fresh 766,316, train_dev 580,772, eval_sealed 263,221, holdout 147,561, validation 131,135, calibration 114,574, eval_tranco 9,487.
Preprocessors are fit on train roles only; zero train/eval domain overlap is asserted in G4.
See `data/DATA_CARD.md` and `data/PROVENANCE.md` (rendered from `data/processed/manifest.json`).

## Limitations and ethics

Lexical-only: no page content, DNS, WHOIS, reputation, or liveness. New-domain drift,
hosted-platform ambiguity, and adversarial obfuscation can reduce recall. No URL string is ever
requested or resolved. Use for anti-phishing research and defensive triage only.
