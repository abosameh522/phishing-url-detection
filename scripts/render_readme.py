import json
from pathlib import Path
m=json.loads(Path('results/model_metrics.json').read_text())
e=json.loads(Path('results/evaluation.json').read_text())
g=json.loads(Path('results/gates.json').read_text())
rows=e['metrics']; h=[x for x in rows if x['split']=='holdout']
def pick(mode): return next((x for x in h if x['mode']==mode),{})
b=pick('balanced'); s=pick('sensitive')
readme=f'''# Phishing URL Detection v2

**Ahmed Sameh**

A leakage-resistant URL-only phishing detector. It canonicalizes equivalent inputs, splits by registrable domain, and exposes one predictor through FastAPI and Streamlit. It never resolves, crawls, or downloads a submitted URL.

## Why v2 exists

The old notebook reported 0.858 recall and 0.970 ROC-AUC on data it had trained on. That protocol rewarded collection artifacts: `www.`, explicit schemes, and file-style paths differed by label source, so `https://www.google.com/` could be called phishing. v2 removes those raw formatting cues, uses domain-disjoint development/holdout slices, and publishes the measured JSON metrics below. The available local snapshot is smaller and less diverse than the requested external corpus, so these numbers are development evidence, not a production claim.

## Measured results

All values below are generated from `results/*.json` by `scripts/render_readme.py`.

| split | operating point | recall | FPR | precision | ROC-AUC |
|---|---:|---:|---:|---:|---:|
| holdout | 1% comparison | {b.get('recall',0):.3f} | {b.get('fpr',0):.3f} | {b.get('precision',0):.3f} | {b.get('roc_auc',0):.3f} |
| holdout | 5% comparison | {s.get('recall',0):.3f} | {s.get('fpr',0):.3f} | {s.get('precision',0):.3f} | {s.get('roc_auc',0):.3f} |

Validation ROC-AUC: **{m['roc_auc_validation']:.3f}**. The requested cross-source PhreshPhish and Tranco benchmark results are **unavailable** in this workspace and are not invented.

## Run locally

```bash
uv sync
make all
uv run uvicorn phishing_url_detection.api:app --reload --port 8000
uv run streamlit run app/streamlit_app.py
```

```bash
curl -X POST http://127.0.0.1:8000/predict -H 'content-type: application/json' -d '{{"url":"https://www.google.com/","mode":"balanced"}}'
```

The API returns the probability, class, threshold, canonical URL, top reasons, and model version. `strict` and `sensitive` select the stored 0.1% and 5% validation-FPR thresholds.

## Data and protocol

The cleaned local CSV contains **{m['train_rows']+m['validation_rows']+m['calibration_rows']:,}** train-pool rows before development splitting. Cleaning drops unsupported classes, malformed hosts, overlong strings, and conflicting duplicate labels. Domain hashes assign stable train/evaluation/holdout roles. See `data/PROVENANCE.md`, `data/DATA_CARD.md`, and `data/ARTIFACT_AUDIT.md`.

## Limitations and ethics

This is lexical-only: it has no page content, DNS, WHOIS, reputation, or liveness signals. New-domain drift, hosted-platform ambiguity, and adversarial URL obfuscation can reduce recall. Use for anti-phishing research and defensive triage only. G3 remains failed/unavailable until a pinned Tranco homepage set and external phishing snapshots are added.
'''
Path('README.md').write_text(readme)
