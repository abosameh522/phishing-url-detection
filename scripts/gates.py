"""Gates G1-G5 + overall result. Every number is read from generated artifacts.

G1 sanity (easy fixtures):     legitimate_accuracy >= .95 and phishing_accuracy >= .85
G2 format invariance:          canonicalize() collapses scheme/www/port/slash variants
G3 real-world:                 eval_tranco flagged share <= 2% at balanced threshold AND
                               cross-source recall@1%FPR (eval_sealed) > v1's matched number
G4 no leakage:                 no registrable-domain overlap between any training role and
                               any evaluation role in the unified parquet
G5 reproducibility:            model metrics + evaluation JSONs exist and carry a commit hash
"""
from pathlib import Path
import json, re, sys
import pandas as pd

sys.path.insert(0, "src")
from phishing_url_detection.canonical import canonicalize
from phishing_url_detection.model import load

report = {}

# ---- G1 (easy sanity fixtures) -------------------------------------------
model_ok = Path("results/model_bundle.joblib").exists()
if model_ok:
    try:
        p = load()
        rows = list(__import__("csv").DictReader(open("tests/sanity_urls.csv")))
        groups = {}
        for r in rows:
            groups.setdefault(r["label"], []).append(r)
        # accuracy at every declared operating mode (spec check: 'balanced')
        acc2 = {}
        for mode in ["strict", "balanced", "sensitive"]:
            acc2[mode] = {}
            for label, rs in groups.items():
                good = 0
                for r in rs:
                    try:
                        out = p.predict(r["url"], mode=mode)
                        good += (out["class"] == "phishing") == (label == "phishing")
                    except Exception:
                        pass
                acc2[mode][label] = good / len(rs)
        report["G1"] = {"per_mode": acc2, "note": "spec check uses the 'balanced' operating point"}
        G1 = acc2["balanced"].get("legitimate", 0) >= .95 and acc2["balanced"].get("phishing", 0) >= .85
    except Exception as e:
        report["G1"] = {"error": str(e)}; G1 = False
else:
    G1 = False; report["G1"] = "model bundle missing"

# ---- G2 format invariance --------------------------------------------------
variants = ["https://www.google.com/", "http://google.com", "www.google.com", "www2.google.com",
            "google.com/", "http://google.com:80/", "https://google.com?#", "https://google.com:443"]
try:
    collapsed = {canonicalize(v) for v in variants}
    report["G2"] = {"variants": len(variants), "canonical_forms": len(collapsed)}
    G2 = len(collapsed) == 1
except Exception as e:
    report["G2"] = {"error": str(e)}; G2 = False

# ---- G3 real-world ---------------------------------------------------------
v2_path = Path("results/v2_evaluation.json")
tranco_fpr = sealed_recall = None
v1_sealed = None
if v2_path.exists():
    ev = json.loads(v2_path.read_text())
    tr = ev.get("slices", {}).get("eval_tranco", {})
    # flagged share at balanced threshold is the empirical FPR on benign-only homepages
    tranco_fpr = tr.get("flagged_share_at_balanced")
    sealed_recall = ev.get("slices", {}).get("eval_sealed", {}).get("recall@0.010FPR")
v1_path = Path("results/v1_rescore.json")
if v1_path.exists():
    v1 = json.loads(v1_path.read_text())
    v1_sealed = (v1.get("new_protocol", {}).get("eval_sealed") or {}).get("recall@0.010FPR")
G3_flags = {}
G3_flags["tranco_fpr_value"] = tranco_fpr
G3_flags["sealed_recall@1%FPR_v2"] = sealed_recall
G3_flags["sealed_recall@1%FPR_v1"] = v1_sealed
G3 = (tranco_fpr is not None and tranco_fpr <= 0.02) and \
     (sealed_recall is not None and v1_sealed is not None and sealed_recall > v1_sealed)
report["G3"] = G3_flags

# ---- G4 leakage -------------------------------------------------------------
parq = Path("data/processed/urls_unified.parquet")
if parq.exists():
    D = pd.read_parquet(parq, columns=["split_role", "registrable_domain"])
    train_roles = {"train_dev", "validation", "calibration", "holdout"}
    eval_roles = {"eval_sealed", "eval_fresh", "eval_tranco"}
    trd = set(D.loc[D.split_role.isin(train_roles), "registrable_domain"])
    evd = set(D.loc[D.split_role.isin(eval_roles), "registrable_domain"])
    overlap = trd & evd
    report["G4"] = {"train_eval_domain_overlap": len(overlap)}
    G4 = len(overlap) == 0
else:
    G4 = False; report["G4"] = "parquet missing"

# ---- G5 reproducibility -----------------------------------------------------
ok_v2 = v2_path.exists() and "commit" in json.loads(v2_path.read_text())
ok_ho = not Path("results/final_holdout.json").exists() or "commit" in json.loads(Path("results/final_holdout.json").read_text())
report["G5"] = {"metrics_json": ok_v2, "holdout_json": ok_ho}
G5 = ok_v2 and ok_ho

report["all_passed"] = bool(G1 and G2 and G3 and G4 and G5)
Path("results/gates.json").write_text(json.dumps(report, indent=2))
print(json.dumps(report, indent=2))
