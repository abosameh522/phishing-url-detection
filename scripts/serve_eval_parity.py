"""Serve/eval parity: score the same URLs through (a) the exact API predictor object and
(b) the evaluation code path (score_batch). Writes results/serve_eval_parity.json.

Diagnosis from the bug hunt: evaluate_v2.score_batch returns the RAW blend
(w*p_lin + (1-w)*p_lgbm) and applies the bundle thresholds directly, while the bundle
thresholds AND the API calibrated probability live on the Platt-calibrated scale
(calibrate(raw) = sigmoid(a*logit(raw)+b), a=1.76 > 1 stretches about 0.5). The same
numeric threshold means two different things on the two paths.
"""
from pathlib import Path
import json, sys, hashlib
import numpy as np
import pandas as pd
import joblib

sys.path.insert(0, "src")
from phishing_url_detection.features import featurize
from phishing_url_detection.canonical import canonicalize
from phishing_url_detection.model import load


def calib(raw, a, b):
    raw = np.clip(np.asarray(raw, dtype=float), 1e-6, 1 - 1e-6)
    z = np.log(raw / (1 - raw))
    return 1 / (1 + np.exp(-(a * z + b)))


def eval_score_batch(b, urls):
    """Exact evaluation path (evaluate_v2.score_batch): raw blend, no Platt."""
    X = featurize(list(urls))
    p_lgbm = b["lgbm"].predict_proba(X)[:, 1]
    p_lin = b["lr"].predict_proba(b["tfidf"].transform([u.lower() for u in urls]))[:, 1]
    w = float(b.get("w_text", 0.5))
    return w * p_lin + (1 - w) * p_lgbm


def main():
    b = joblib.load("results/model_bundle.joblib")
    a = float(b["calibration"]["a"]); bb = float(b["calibration"]["b"])
    thr_bal = float(b["thresholds"]["balanced"])
    p = load()  # exact object the FastAPI startup() uses

    probe = [
        "https://www.google.com/", "github.com", "https://www.amazon.com/s?k=books",
        "stackoverflow.com/questions/1", "en.wikipedia.org/wiki/Main_Page",
        "https://www.microsoft.com/en-us/", "mansoura.edu.eg",
        "docs.google.com/document/d/abc", "secure-google-login.example.top/verify",
        "github.com.evil.example/confirm",
    ]

    D = pd.read_parquet("data/processed/urls_unified.parquet",
                        columns=["url_canonical", "registrable_domain", "split_role"])
    tr = D[D.split_role == "eval_tranco"].url_canonical.sample(200, random_state=42).tolist()

    rows = []
    for u in probe + tr[:50]:
        c_api = canonicalize(u)                                   # API path
        api_out = p.predict(u, mode="balanced")
        c_eval = u                                                # eval path uses stored canonical directly
        raw = float(eval_score_batch(b, [c_eval])[0])
        cal = float(calib([raw], a, bb)[0])
        rows.append({
            "input": u,
            "api_canonical": c_api, "eval_canonical": c_eval,
            "canonical_forms_equal": c_api == c_eval,
            "eval_raw": raw, "api_calibrated": api_out["probability"],
            "cal_of_eval_raw": cal,
            "api_prob_minus_cal_of_eval_raw": abs(api_out["probability"] - cal),
            "api_class_balanced": api_out["class"],
            "eval_class_raw_vs_thr": "phishing" if raw >= thr_bal else "legitimate",
        })

    # full-tranco FPR on both paths (corrected eval = calibrated)
    urls = D[D.split_role == "eval_tranco"].url_canonical.tolist()
    raw = eval_score_batch(b, urls)
    cal = calib(raw, a, bb)
    fpr = {
        "eval_path_raw_ge_balanced": float((raw >= thr_bal).mean()),
        "api_path_calibrated_ge_balanced": float((cal >= thr_bal).mean()),
        "raw_equiv_of_balanced_threshold": float(1 / (1 + np.exp(-((np.log(thr_bal / (1 - thr_bal)) - bb) / a)))),
    }
    example_flagged = []
    for i in np.where(cal >= thr_bal)[0][:10]:
        example_flagged.append(urls[i])

    out = {
        "bundle": {"a": a, "b": bb, "thresholds": b["thresholds"], "w_text": b.get("w_text"),
                   "version": b.get("version")},
        "diagnosis": ("evaluate_v2.score_batch returns the RAW blend and applies calibrated-domain "
                      "thresholds; the API calibrates first. Same number => different operating point."),
        "tranco_flagged_share": fpr,
        "example_flagged_urls_api_path": example_flagged,
        "rows": rows,
        "n_rows_api_prob_minus_cal_gt_1e_6": int(sum(r["api_prob_minus_cal_of_eval_raw"] > 1e-6 for r in rows)),
        "n_rows_class_mismatch": int(sum(r["api_class_balanced"] != r["eval_class_raw_vs_thr"] for r in rows)),
    }
    Path("results/serve_eval_parity.json").write_text(json.dumps(out, indent=2))
    print("canonical forms all equal:", all(r["canonical_forms_equal"] for r in rows))
    print("class mismatches:", out["n_rows_class_mismatch"], "/", len(rows))
    print(json.dumps(fpr, indent=2))
    print("example flagged (API path):", example_flagged[:6])
    for r in rows[:10]:
        print(f"  {r['input'][:44]:46s} raw={r['eval_raw']:.3f} cal={r['api_calibrated']:.3f} "
              f"api={r['api_class_balanced'][:4]} eval={r['eval_class_raw_vs_thr'][:4]}")


if __name__ == "__main__":
    main()
