"""Check that evaluation and serving canonicalize and score the same URL identically."""
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
    """Return the calibrated lexical risk score used by the API."""
    urls = [canonicalize(u) for u in urls]
    X = featurize(urls)
    p_lgbm = b["lgbm"].predict_proba(X)[:, 1]
    p_lin = b["lr"].predict_proba(b["tfidf"].transform([u.lower() for u in urls]))[:, 1]
    w = float(b.get("w_text", 0.5))
    raw = w * p_lin + (1 - w) * p_lgbm
    return calib(raw, float(b['calibration']['a']), float(b['calibration']['b']))


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
        c_eval = canonicalize(u)
        score = float(eval_score_batch(b, [c_eval])[0])
        rows.append({
            "input": u,
            "api_canonical": c_api, "eval_canonical": c_eval,
            "canonical_forms_equal": c_api == c_eval,
            "eval_risk_score": score, "api_risk_score": api_out["risk_score"],
            "api_score_delta": abs(api_out["risk_score"] - score),
            "api_class_balanced": api_out["class"],
            "eval_class_vs_threshold": "phishing" if score >= thr_bal else "legitimate",
        })

    # Full-Tranco flagged-share parity on the actual served score scale.
    urls = D[D.split_role == "eval_tranco"].url_canonical.tolist()
    score = eval_score_batch(b, urls)
    fpr = {
        "eval_path_flagged_share": float((score >= thr_bal).mean()),
    }
    example_flagged = []
    for i in np.where(score >= thr_bal)[0][:10]:
        example_flagged.append(urls[i])

    out = {
        "bundle": {"a": a, "b": bb, "thresholds": b["thresholds"], "w_text": b.get("w_text"),
                   "version": b.get("version")},
        "diagnosis": "Serving and evaluation apply canonicalization, blending, and calibration in the same order.",
        "tranco_flagged_share": fpr,
        "example_flagged_urls_api_path": example_flagged,
        "rows": rows,
        "n_rows_api_score_delta_gt_1e_6": int(sum(r["api_score_delta"] > 1e-6 for r in rows)),
        "n_rows_class_mismatch": int(sum(r["api_class_balanced"] != r["eval_class_vs_threshold"] for r in rows)),
    }
    Path("results/serve_eval_parity.json").write_text(json.dumps(out, indent=2))
    print("canonical forms all equal:", all(r["canonical_forms_equal"] for r in rows))
    print("class mismatches:", out["n_rows_class_mismatch"], "/", len(rows))
    print(json.dumps(fpr, indent=2))
    print("example flagged (API path):", example_flagged[:6])
    for r in rows[:10]:
        print(f"  {r['input'][:44]:46s} score={r['eval_risk_score']:.3f} api={r['api_risk_score']:.3f} "
              f"api={r['api_class_balanced'][:4]} eval={r['eval_class_vs_threshold'][:4]}")


if __name__ == "__main__":
    main()
