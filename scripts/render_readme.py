"""Render README.md strictly from generated results/*.json + data/processed/manifest.json.

Every number in the README comes from a measured artifact. If an artifact is missing,
the README says so instead of inventing a value.
"""
import json
from pathlib import Path

R = Path("results")


def load(name, fallback=None):
    p = R / name
    if not p.exists():
        return fallback
    return json.loads(p.read_text())


manifest = json.loads(Path("data/processed/manifest.json").read_text())
metrics = load("model_metrics_v2.json", {})
evalv2 = load("v2_evaluation.json", {})
hold = load("final_holdout.json", {})
v1 = load("v1_rescore.json", {})
gates = load("gates.json", {})
sanity = load("hard_sanity_results.json", {})


def fmt(x, nd=3):
    if isinstance(x, float) and (x != x):  # NaN
        return "n/a"
    if isinstance(x, bool):
        return "yes" if x else "no"
    if isinstance(x, (int, float)):
        return f"{x:.{nd}f}" if isinstance(x, float) else f"{x:,}"
    return "n/a"


# -- holdout table (final numbers) ---------------------------------------
h = (hold.get("metrics") or {})
ho_rows = ""
if h:
    ho_rows = (
        f"| holdout (touched once) | 1% FPR | {fmt(h.get('recall@0.010FPR'))} | {fmt(0.01)} | — | {fmt(h.get('roc_auc'))} |\n"
        f"| holdout (touched once) | 5% FPR | {fmt(h.get('recall@0.050FPR'))} | {fmt(0.05)} | — | {fmt(h.get('roc_auc'))} |\n"
        f"| holdout (touched once) | AP | — | — | — | {fmt(h.get('average_precision'))} |\n"
    )

before_rows = ""
if v1.get("new_protocol") and evalv2.get("slices"):
    before_rows = "| slice | model | rows | recall@1%FPR | ROC-AUC | AP |\n|---|---|---:|---:|---:|---:|\n"
    for s, row in v1["new_protocol"].items():
        atv1 = row.get("at_v1_threshold") or {}
        before_rows += (f"| {s} | v1 (refit on same pool) | {fmt(row.get('rows'))} | "
                        f"{fmt(row.get('recall@0.010FPR'))} | {fmt(atv1.get('roc_auc'))} | "
                        f"{fmt(atv1.get('ap'))} |\n")
    for s in ["eval_sealed", "eval_fresh", "holdout"]:
        row = evalv2["slices"].get(s) or (h if s == "holdout" else None)
        if not row:
            continue
        name = "holdout (final)" if s == "holdout" else s
        before_rows += (f"| {name} | **v2** | {fmt(row.get('rows'))} | {fmt(row.get('recall@0.010FPR'))} | "
                        f"{fmt(row.get('roc_auc'))} | {fmt(row.get('average_precision'))} |\n")

# -- CV comparison table -------------------------------------------------------
cv = metrics.get("cv") or []
cv_rows = ""
if cv:
    cv_rows = "| model family | ROC-AUC | AP | recall@1%FPR | recall@5%FPR |\n|---|---:|---:|---:|---:|\n"
    for r in cv:
        cv_rows += (f"| {r['model']} | {fmt(r.get('ROC_AUC'))} | {fmt(r.get('AP'))} | "
                    f"{fmt(r.get('recall@0.010FPR'))} | {fmt(r.get('recall@0.050FPR'))} |\n")

# -- cross-source --------------------------------------------------------------
cross = metrics.get("cross_source") or {}
cross_rows = ""
if cross:
    cross_rows = "| source family (in train_dev) | phishing rows | recall@1%FPR | recall@0.1%FPR |\n|---|---:|---:|---:|\n"
    for fam, r in cross.items():
        cross_rows += (f"| {fam} | {fmt(r.get('n_phish'))} | {fmt(r.get('recall@1%FPR'))} | "
                       f"{fmt(r.get('recall@0.1%FPR'))} |\n")

# -- sanity fixtures -----------------------------------------------------------
san_txt = ""
if sanity:
    bl = sanity.get("by_label", {})
    san_txt = (f"Hard sanity fixtures: overall accuracy **{fmt(sanity.get('overall_accuracy'))}** "
               f"(legitimate {fmt(bl.get('legitimate', {}).get('accuracy'))} / "
               f"phishing {fmt(bl.get('phishing', {}).get('accuracy'))} at the balanced threshold).")

# -- thresholds ----------------------------------------------------------------
thr = metrics.get("thresholds") or evalv2.get("thresholds") or {}
thr_txt = ", ".join(f"`{k}` = {fmt(t, 4)}" for k, t in thr.items()) if thr else "n/a"

# -- gates ---------------------------------------------------------------------
gates_txt = "n/a"
if gates:
    gates_txt = "**PASSED**" if gates.get("all_passed") else "**FAILED — see results/gates.json**"

# -- data summary --------------------------------------------------------------
cb = manifest.get("class_balance", {})
sc = manifest.get("split_counts", {})
gates_note = ("" if gates.get("all_passed")
              else "\nG3 (real-world) is measured with limited external data; any failure is documented in `results/gates.json` and `docs/LIMITS.md`.")

readme = f"""# Phishing URL Detection v2

**Ahmed Sameh**

A leakage-resistant URL-only phishing detector. It canonicalizes equivalent inputs, splits by
registrable domain, trains a lexical + character-n-gram stack, and exposes one predictor through
FastAPI and Streamlit. It never resolves, crawls, or downloads a submitted URL. Every number below
is generated from `results/*.json` by `scripts/render_readme.py`.

## Why v2 exists

The v1 notebook looked strong in-distribution (its own test ROC-AUC {fmt((v1.get('reference_own_test') or {}).get('roc_auc'))})
but collapses under a domain-grouped, cross-source protocol: on the sealed PhreshPhish-test slice its
recall@1%FPR is {fmt((v1.get('new_protocol') or {{}}).get('eval_sealed', dict()).get('recall@0.010FPR'))} and it flags
{fmt(100 * ((v1.get('new_protocol') or {{}}).get('eval_tranco', dict()).get('at_v1_threshold', dict()).get('fpr', 0)), 1)}% of benign
Tranco homepages. v2 was rebuilt to avoid those collection artifacts.

## Measured results

{before_rows}
{ho_rows}

## Held-out evaluation (final)

{hold.get('metrics', {}).get('rows', 'n/a')} holdout URLs grouped by registrable domain — touched exactly once.
{santxt if (santxt := san_txt) else ''}

## CV model comparison (train_dev, StratifiedGroupKFold 5 seeds × domains, seed 42)

{cv_rows}

## Cross-source recall (threshold from other families' benign OOF scores)

{cross_rows}

## Calibration and thresholds

Platt risk-score mapping fit on calibration half A; thresholds chosen on half B: {thr_txt}. Scores are calibrated to this corpus mix, not real-world prevalence, and are not deployment probabilities.

## Gates

{gates_txt}{gates_note}

## Run locally

```bash
uv sync
make gates
uv run uvicorn phishing_url_detection.api:app --reload --port 8000
uv run streamlit run app/streamlit_app.py
```

```bash
curl -X POST http://127.0.0.1:8000/predict -H 'content-type: application/json' -d '{{"url":"https://www.google.com/","mode":"balanced"}}'
```

The API returns a calibrated lexical risk score (not a real-world probability), class, threshold, canonical URL, reasons, and model version.
`strict` / `balanced` / `sensitive` select the stored thresholds.

## Data and protocol

Unified corpus: **{manifest.get('rows_kept', 0):,}** URLs<a name=corpus> ({fmt(cb.get('benign', 0))} benign /
{fmt(cb.get('phishing', 0))} phishing) across {fmt(manifest.get('registrable_domains'))} registrable domains.
Split roles by domain hash: {', '.join(f'{k} {fmt(v)}' for k, v in sc.items())}.
Preprocessors are fit on train roles only; zero train/eval domain overlap is asserted in G4.
See `data/DATA_CARD.md` and `data/PROVENANCE.md` (rendered from `data/processed/manifest.json`).

## Limitations and ethics

Lexical-only: no page content, DNS, WHOIS, reputation, or liveness. New-domain drift,
hosted-platform ambiguity, and adversarial obfuscation can reduce recall. No URL string is ever
requested or resolved. Use for anti-phishing research and defensive triage only.
"""
Path("README.md").write_text(readme)
print("README.md rendered from results/*.json")
