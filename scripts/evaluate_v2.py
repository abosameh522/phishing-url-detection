"""Stage 4: evaluate the v2 model under the new grouped protocol.

All numbers written here are generated from the bundled model and the unified corpus.
  - results/v2_evaluation.json          per-slice + per-source metrics with CIs
  - results/final_holdout.json          holdout touched exactly once
  - results/hard_sanity_results.json    hard sanity fixtures (separate from easy set)
  - results/before_vs_after.md          honest v1-vs-v2 comparison from measured JSONs

Slices:
  eval_sealed | eval_fresh | eval_tranco | holdout (touched once)
Confidence intervals: domain-cluster bootstrap; registrable domains are hashed into
1000 buckets and buckets are resampled, which is a conservative block-bootstrap over
domains (exact per-domain resampling is prohibitively slow for ~500k domains).
"""
from pathlib import Path
import json, sys, subprocess, csv, time, hashlib, os
import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, "src")
from phishing_url_detection.features import featurize
from phishing_url_detection.canonical import canonicalize
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve

SEED = 42
N_BOOT = 300
N_BUCKETS = 1000


def load_bundle():
    return joblib.load("results/model_bundle.joblib")


def score_batch(b, urls):
    """Calibrated probabilities — the SAME functional form the API predictor uses
    (canonical -> featurize -> blend -> Platt). v2.0 evaluation applied bundle thresholds
    to raw blend scores, which is a different operating point (results/serve_eval_parity.json
    proves the skew: same URL, API phishing vs eval legitimate)."""
    # Match the serving path exactly: canonicalization precedes both feature paths.
    urls = [canonicalize(u) for u in urls]
    X = featurize(urls)
    p_lgbm = b["lgbm"].predict_proba(X)[:, 1]
    p_lin = b["lr"].predict_proba(b["tfidf"].transform([u.lower() for u in urls]))[:, 1]
    w = float(b.get("w_text", 0.5))
    raw = w * p_lin + (1 - w) * p_lgbm
    cal = b.get("calibration") or {"a": 1.0, "b": 0.0}
    a = float(cal.get("a", 1.0)); bb = float(cal.get("b", 0.0))
    raw = np.clip(raw, 1e-6, 1 - 1e-6)
    z = np.log(raw / (1 - raw))
    return 1 / (1 + np.exp(-(a * z + bb)))


def recall_at_fpr(y, p, target):
    y = np.asarray(y); p = np.asarray(p)
    if y.sum() == 0 or (y == 0).sum() == 0:
        return None, None
    fpr, tpr, thr = roc_curve(y, p)
    m = fpr <= target
    if not m.any():
        return 0.0, 1.0
    i = np.where(m)[0][-1]
    return float(tpr[i]), float(fpr[i])


def mode_table(yv, pv, thresholds):
    out = {}
    for mode, thr in (thresholds or {}).items():
        pred = (pv >= float(thr)).astype(int)
        tn = int(((pred == 0) & (yv == 0)).sum()); fp = int(((pred == 1) & (yv == 0)).sum())
        fn = int(((pred == 0) & (yv == 1)).sum()); tp = int(((pred == 1) & (yv == 1)).sum())
        tpr = tp / max(1, tp + fn); fpr = fp / max(1, fp + tn)
        prev = 0.5  # base-rate-aware precision at an assumed 50/50 prevalence
        out[mode] = {"threshold": float(thr), "tp": tp, "fp": fp, "fn": fn, "tn": tn,
                     "tpr": tpr, "fpr": fpr,
                     "precision_raw": tp / max(1, tp + fp),
                     "precision_at_50pct_prevalence": (tpr * prev) / (tpr * prev + fpr * (1 - prev))}
    return out


def evaluate_frame(df, b, p_col="p", thr_balanced=None):
    yv = (df.label == "phishing").astype(int).to_numpy()
    pv = df[p_col].to_numpy()
    thr_balanced = float(thr_balanced if thr_balanced is not None else b.get("thresholds", {}).get("balanced", 0.5))
    row = {"rows": int(len(df)), "domains": int(df.registrable_domain.nunique()),
           "phishing_rows": int(yv.sum()), "benign_rows": int((yv == 0).sum())}
    if yv.sum() == 0 or (yv == 0).sum() == 0:
        row["note"] = "single-class slice; only flag-rate metrics reported"
        row["flagged_share_at_balanced"] = float((pv >= thr_balanced).mean())
        return row
    row["roc_auc"] = float(roc_auc_score(yv, pv))
    row["average_precision"] = float(average_precision_score(yv, pv))
    for t in [0.001, 0.01, 0.05]:
        r, _ = recall_at_fpr(yv, pv, t)
        row[f"recall@{t:.3f}FPR"] = r
    row["modes"] = mode_table(yv, pv, b.get("thresholds"))
    row["per_source"] = None  # filled by caller for grouping display
    row["bootstrap_ci"] = bucket_bootstrap_ci(df, p_col, target=0.01)
    return row


def bucket_bootstrap_ci(df, p_col, target=0.01, n_boot=N_BOOT, n_buckets=N_BUCKETS):
    doms = df.registrable_domain.to_numpy()
    bucket = (pd.util.hash_array(doms.astype("U")) % n_buckets)
    yv = (df.label == "phishing").astype(int).to_numpy()
    pv = df[p_col].to_numpy()
    groups = pd.Series(np.arange(len(df))).groupby(bucket).apply(lambda s: s.to_numpy()).to_dict()
    rng = np.random.default_rng(SEED)
    all_buckets = np.array(sorted(groups.keys()))
    aucs, aps, recalls = [], [], []
    for _ in range(n_boot):
        pick = rng.choice(all_buckets, size=len(all_buckets), replace=True)
        idx = np.concatenate([groups[b] for b in pick])
        yy, pp = yv[idx], pv[idx]
        if yy.sum() == 0 or (yy == 0).sum() == 0:
            continue
        aucs.append(roc_auc_score(yy, pp))
        aps.append(average_precision_score(yy, pp))
        r, _ = recall_at_fpr(yy, pp, target)
        if r is not None:
            recalls.append(r)
    out = {}
    for name, vals in [("roc_auc", aucs), ("average_precision", aps), (f"recall@{target:.3f}FPR", recalls)]:
        if vals:
            out[name] = {"lo": float(np.percentile(vals, 2.5)), "hi": float(np.percentile(vals, 97.5))}
    return out


def per_source_metrics(df, thr):
    out = {}
    for src, g in df.groupby("source"):
        yv = (g.label == "phishing").astype(int).to_numpy()
        pv = g.p.to_numpy()
        r = {"rows": int(len(g)), "phishing": int(yv.sum()),
             "domains": int(g.registrable_domain.nunique())}
        if yv.sum() and (yv == 0).sum():
            r["roc_auc"] = float(roc_auc_score(yv, pv))
            r["average_precision"] = float(average_precision_score(yv, pv))
            for t in [0.001, 0.01, 0.05]:
                rr, _ = recall_at_fpr(yv, pv, t)
                r[f"recall@{t:.3f}FPR"] = rr
        r["flagged_share_at_balanced"] = float((pv >= thr).mean())
        out[src] = r
    return out


def main():
    b = load_bundle()
    bundle_sha256 = hashlib.sha256(Path("results/model_bundle.joblib").read_bytes()).hexdigest()
    D = pd.read_parquet("data/processed/urls_unified.parquet")
    commit = subprocess.run(["git", "rev-parse", "HEAD"], capture_output=True, text=True).stdout.strip()
    thresholds = b.get("thresholds", {})
    thr_balanced = float(thresholds["balanced"])
    eval_slices = {}

    # ---- open eval slices + tranco + fresh -------------------------------
    for s in ["eval_sealed", "eval_fresh", "eval_tranco"]:
        sub = D[D.split_role == s].copy()
        if len(sub) == 0:
            continue
        t0 = time.time()
        score_fingerprint = {k: str(b.get(k)) for k in
                             ["thresholds", "w_text", "calibration", "version"]}
        score_fingerprint["score_path"] = "canonicalized_calibrated_v3"
        score_fingerprint["bundle_sha256"] = bundle_sha256
        fp = hashlib.sha256(json.dumps(score_fingerprint, sort_keys=True).encode()).hexdigest()[:16]
        cache_p = Path(f"results/slice_{s}_probs_{fp}.npy")
        if cache_p.exists():
            p = np.load(cache_p)
            print(f"[{s}] loaded cached scores", flush=True)
        else:
            p = score_batch(b, sub.url_canonical.tolist())
            np.save(cache_p, p)
        sub["p"] = p
        row = evaluate_frame(sub, b, p_col="p", thr_balanced=thr_balanced)
        row["per_source"] = per_source_metrics(sub, thr_balanced)
        row["seconds"] = round(time.time() - t0, 1)
        eval_slices[s] = row
        sub[["source", "label", "url_canonical", "registrable_domain", "p"]].to_parquet(f"results/slice_{s}_scores.parquet")
        print(f"[{s}] {len(sub)} rows in {row['seconds']}s recall@1%FPR={row.get('recall@0.010FPR')} AUC={row.get('roc_auc')}", flush=True)

    # ---- holdout: touched exactly once -----------------------------------
    if Path("results/final_holdout.json").exists():
        print("holdout already evaluated once; not re-touched", flush=True)
        prior_holdout = json.loads(Path("results/final_holdout.json").read_text())
        if prior_holdout.get("evaluated_once"):
            eval_slices["holdout"] = prior_holdout.get("metrics", {})
    else:
        h = D[D.split_role == "holdout"].copy()
        t0 = time.time()
        score_fingerprint = {k: str(b.get(k)) for k in
                             ["thresholds", "w_text", "calibration", "version"]}
        score_fingerprint["score_path"] = "canonicalized_calibrated_v3"
        score_fingerprint["bundle_sha256"] = bundle_sha256
        fp = hashlib.sha256(json.dumps(score_fingerprint, sort_keys=True).encode()).hexdigest()[:16]
        cache_p = Path(f"results/slice_holdout_probs_{fp}.npy")
        h["p"] = np.load(cache_p) if cache_p.exists() else score_batch(b, h.url_canonical.tolist())
        if not cache_p.exists():
            np.save(cache_p, h["p"].to_numpy())
        hold = evaluate_frame(h, b)
        hold["seconds"] = round(time.time() - t0, 1)
        h[["source", "label", "url_canonical", "registrable_domain", "p"]].to_parquet("results/slice_holdout_scores.parquet")
        Path("results/final_holdout.json").write_text(json.dumps(
            {"metrics": hold, "commit": commit, "evaluated_once": True}, indent=2))
        eval_slices["holdout"] = hold
        print("[holdout] evaluated once", {k: hold.get(k) for k in ["rows", "recall@0.010FPR"]}, flush=True)

    # ---- hard sanity set ---------------------------------------------------
    hs_path = Path("tests/hard_sanity_urls.csv")
    hs_out = None
    if hs_path.exists():
        rows = list(csv.DictReader(hs_path.open()))
        safe = []
        for r in rows:
            try:
                safe.append(canonicalize(r["url"]))
            except Exception:
                safe.append(r["url"])
        p = score_batch(b, safe)
        thr = float(thresholds["balanced"])
        preds = (p >= thr).astype(int)
        yh = np.array([1 if r["label"] == "phishing" else 0 for r in rows])
        by_lbl = {}
        for lbl, flag in [("legitimate", 0), ("phishing", 1)]:
            m = yh == flag
            by_lbl[lbl] = {"rows": int(m.sum()), "accuracy": float((preds[m] == flag).mean())}
        hs_out = {"threshold_mode": "balanced", "threshold": thr,
                  "overall_accuracy": float((preds == yh).mean()), "by_label": by_lbl,
                  "note": "fixtures; run separately from the easy sanity set"}
        Path("results/hard_sanity_results.json").write_text(json.dumps(hs_out, indent=2))
        print("[hard-sanity]", {k: round(v, 4) if isinstance(v, float) else v for k, v in hs_out["by_label"].items()}, flush=True)

    # ---- write v2_evaluation.json -----------------------------------------
    Path("results/v2_evaluation.json").write_text(json.dumps({
        "protocol": "grouped by registrable domain; model trained on train_dev only; blend on validation;"
                    " Platt on calibration half A; thresholds on half B; holdout touched once",
        "commit": commit, "bundle_version": b.get("version"),
        "w_text": b.get("w_text"), "thresholds": thresholds,
        "slices": eval_slices, "hard_sanity": hs_out}, indent=2))
    print("WROTE results/v2_evaluation.json", flush=True)

    # ---- before vs after ---------------------------------------------------
    lines = ["# Before vs after (v1 vs v2)", "",
             "Every number is read from `results/v1_rescore.json` and `results/v2_evaluation.json`;", "no value is hand-written.", "",
             "| slice | model | rows | recall@1%FPR | ROC-AUC | AP |", "|---|---|---|---|---|---|"]
    v1_path = Path("results/v1_rescore.json")
    if v1_path.exists():
        v1 = json.loads(v1_path.read_text())
        for s, row in (v1.get("new_protocol") or {}).items():
            atv1 = row.get("at_v1_threshold") or {}
            lines.append(f"| {s} | v1 (refit, same train pool) | {row.get('rows')} | "
                         f"{row.get('recall@0.010FPR')} | {atv1.get('roc_auc')} | {atv1.get('ap')} |")
    else:
        lines.append("(v1 rescore not yet available)")
    for s, row in eval_slices.items():
        lines.append(f"| {s} | v2 | {row.get('rows')} | {round(row.get('recall@0.010FPR') or 0, 4)} | "
                     f"{round(row.get('roc_auc') or 0, 4)} | {round(row.get('average_precision') or 0, 4)} |")
    if hs_out:
        lines += ["", "## hard sanity fixtures", f"overall accuracy {hs_out['overall_accuracy']:.3f};",
                  f"legitimate {hs_out['by_label']['legitimate']['accuracy']:.3f} / phishing {hs_out['by_label']['phishing']['accuracy']:.3f} at threshold {hs_out['threshold']}."]
    Path("results/before_vs_after.md").write_text("\n".join(lines))
    print("WROTE results/before_vs_after.md", flush=True)


if __name__ == "__main__":
    main()
