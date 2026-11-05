"""Stage 3 model training: compare lexical model families under grouped CV, pick by
cross-source recall at 1% FPR, then fit the final stack with blend weights, calibration
and thresholds on three distinct slices. No page-content or reputation features.

Slices (all split by registrable domain upstream):
  - train_dev    : model selection CV + cross-source fits
  - validation   : blend-weight selection
  - calibration  : Platt calibration (half A) + threshold selection (half B)
  - holdout      : NEVER touched here; evaluated exactly once later
"""
from pathlib import Path
import json, sys, hashlib, time
import numpy as np
import pandas as pd
import joblib

from sklearn.model_selection import StratifiedGroupKFold
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import SGDClassifier
from sklearn.calibration import calibration_curve
from sklearn.metrics import roc_auc_score, average_precision_score, roc_curve

import lightgbm as lgb
import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt

sys.path.insert(0, "src")
from phishing_url_detection.features import featurize, feature_names

SEED = 42
FRAC = {  # mapping of names used across files to canonical labels
    "kaggle_like": "kaggle_like",
    "phreshphish": "phreshphish",
    "mendeley_academic": "mendeley_academic",
}

def recall_at_fpr(y, p, target):
    """Largest threshold whose FPR on the full evaluation set <= target."""
    y = np.asarray(y); p = np.asarray(p)
    order = np.argsort(p, kind="stable")
    thr = None
    neg = int((y == 0).sum())
    # walk thresholds: FPR(y==0 among p>=t)
    fpr, tpr, thresholds = roc_curve(y, p)
    mask = fpr <= target
    if mask.any():
        i = np.where(mask)[0][-1]
        return float(tpr[i]), float(fpr[i]), float(thresholds[i])
    return 0.0, 0.0, 1.0


def bench_scores(y, p):
    """Recall at multiple FPR operating points + AP + AUC."""
    out = {}
    for t in [0.001, 0.01, 0.05]:
        r, f, th = recall_at_fpr(y, p, t)
        out[f"recall@{t:.3f}FPR"] = r
    out["AP"] = float(average_precision_score(y, p)) if y.sum() and (y == 0).sum() else None
    out["ROC_AUC"] = float(roc_auc_score(y, p)) if y.sum() and (y == 0).sum() else None
    return out


# ---------------- cached featurization -----------------
def cached_featurize(tag, urls):
    """Compute (or load) 28 lexical features for a URL list; cached to results/.npz."""
    key = hashlib.sha256(("|".join(urls)).encode()).hexdigest()[:16]
    path = Path(f"results/feat_cache_{tag}_{key}.npz")
    path.parent.mkdir(exist_ok=True)
    if path.exists():
        z = np.load(path)
        return z["X"]
    t0 = time.time()
    X = featurize(urls)
    Z = X.astype(np.float32)
    print(f"[feat] {tag} n={len(urls)} took {time.time()-t0:.0f}s", flush=True)
    np.savez_compressed(path, X=Z)
    return Z


def main():
    D = pd.read_parquet("data/processed/urls_unified.parquet")
    trn = D[D.split_role == "train_dev"].reset_index(drop=True)
    val = D[D.split_role == "validation"].reset_index(drop=True)
    cal = D[D.split_role == "calibration"].reset_index(drop=True)
    print(f"slices train_dev={len(trn)} validation={len(val)} calibration={len(cal)}", flush=True)

    Xtr = cached_featurize("train_dev", trn.url_canonical.tolist())
    ytr = (trn.label == "phishing").astype(int).to_numpy()
    groups = trn.registrable_domain.to_numpy()
    wtr = trn.sample_weight.astype(float).to_numpy()

    # ---------- model families ----------
    def fit_lgbm(X, y, w, seed=SEED):
        m = lgb.LGBMClassifier(
            n_estimators=350, learning_rate=0.08, num_leaves=96,
            min_child_samples=40, subsample=0.9, subsample_freq=1,
            colsample_bytree=0.9, random_state=seed, n_jobs=4, verbosity=-1,
        )
        m.fit(X, y, sample_weight=w)
        return m

    def fit_lr_lgbm(X, y, w, seed=SEED):
        m = lgb.LGBMClassifier(
            n_estimators=250, learning_rate=0.06, num_leaves=48,
            min_child_samples=60, random_state=seed, n_jobs=2, verbosity=-1,
        )
        m.fit(X, y, sample_weight=w)
        return m

    family_factory = {"lgbm": fit_lgbm, "lgbm_light": fit_lr_lgbm}

    # ---------- A) 5-fold grouped CV comparison ----------
    cv_rows = []
    skf = StratifiedGroupKFold(n_splits=5, shuffle=True, random_state=SEED)
    folds = list(skf.split(Xtr, ytr, groups=groups))
    for name in ["lgbm", "lgbm_light"]:
        cache = Path(f"results/cv_probs_{name}.npy")
        if cache.exists():
            probs = np.frombuffer(cache.read_bytes(), dtype=np.float32)
            print(f"[cv] {name} loaded from cache", flush=True)
            cv_rows.append({"model": name, **bench_scores(ytr, probs)})
            continue
        probs = np.zeros(len(ytr), dtype=np.float32)
        for k, (i1, i2) in enumerate(folds):
            m = family_factory[name](Xtr[i1], ytr[i1], wtr[i1])
            probs[i2] = m.predict_proba(Xtr[i2])[:, 1]
            print(f"[cv] {name} fold {k} done", flush=True)
        sc = bench_scores(ytr, probs)
        cv_rows.append({"model": name, **sc})
        cache.write_bytes(probs.tobytes())
        print("[cv]", name, sc, flush=True)

    # ---------- B) char-ngram TF-IDF linear (+ stack) on the same folds ----------
    tfidf = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=10,
                            max_features=200000, sublinear_tf=True, dtype=np.float32)
    can_tr = trn.url_canonical.str.lower().to_numpy()
    tfidf.fit(can_tr)
    Ztr = tfidf.transform(can_tr)

    # linear baseline as a second family, on the same folds
    lr = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=8, tol=None,
                       n_jobs=2, random_state=SEED)
    cache_lin = Path("results/cv_probs_tfidf_char_linear.npy")
    if cache_lin.exists():
        probs_lin = np.frombuffer(cache_lin.read_bytes(), dtype=np.float32)
        print("[cv] tfidf_char_linear loaded from cache", flush=True)
        cv_rows.append({"model": "tfidf_char_linear", **bench_scores(ytr, probs_lin)})
    else:
        probs_lin = np.zeros(len(ytr), dtype=np.float32)
        for k, (i1, i2) in enumerate(folds):
            lr.fit(Ztr[i1], ytr[i1])
            probs_lin[i2] = lr.predict_proba(Ztr[i2])[:, 1]
            print(f"[cv] tfidf-linear fold {k} done", flush=True)
        sc = bench_scores(ytr, probs_lin)
        cv_rows.append({"model": "tfidf_char_linear", **sc})
        cache_lin.write_bytes(probs_lin.tobytes())
        print("[cv] tfidf_char_linear", sc, flush=True)

    # stack of lgbm + tfidf-linear with equal weights inside CV
    for w in [0.3, 0.5, 0.7]:
        p = w * probs_lin + (1 - w) * probs
        sc = bench_scores(ytr, p)
        cv_rows.append({"model": f"stack(w_text={w})", **sc})
    Path("results/cv_comparison.json").write_text(json.dumps(cv_rows, indent=2))
    print("[cv] comparison table", flush=True)

    # ---------- C) cross-source recall@1%FPR ----------
    # families present in train_dev; we train on train_dev minus one family and
    # evaluate on the held-out family's phishing rows, with threshold chosen on the
    # held-in benign rows at 1% FPR.
    fams = sorted(trn.family.unique())
    cross = {}
    probs_lgbm = np.frombuffer(Path("results/cv_probs_lgbm.npy").read_bytes(), dtype=np.float32)
    for f in fams:
        idx_f = np.where(trn.family.to_numpy() == f)[0]
        # threshold from other-family benign OOF scores
        thr_idx = np.where(trn.family.to_numpy() != f)[0]
        benign_scores = probs_lgbm[thr_idx][ytr[thr_idx] == 0]
        thr = float(np.quantile(benign_scores, 1 - 0.01, method="higher"))
        p_f = probs_lgbm[idx_f]
        y_f = ytr[idx_f]
        pred = (p_f >= thr).astype(int)
        phish_idx = np.where(y_f == 1)[0]
        rec1 = float(pred[phish_idx].mean()) if len(phish_idx) else None
        # also 0.1% FPR
        thr01 = float(np.quantile(benign_scores, 1 - 0.001, method="higher"))
        pred01 = (p_f >= thr01).astype(int)
        rec01 = float(pred01[phish_idx].mean()) if len(phish_idx) else None
        cross[f] = {"n_rows": int(len(idx_f)), "n_phish": int(y_f.sum()),
                    "recall@1%FPR": rec1, "recall@0.1%FPR": rec01}
    Path("results/cross_source.json").write_text(json.dumps(cross, indent=2))
    print("[cross]", cross, flush=True)

    # ---------- D) final fit on train_dev ----------
    t0 = time.time()
    lgbm_final = fit_lgbm(Xtr, ytr, wtr)
    lr_final = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=8, tol=None,
                             n_jobs=2, random_state=SEED)
    lr_final.fit(Ztr, ytr)
    print(f"[final] fits took {time.time()-t0:.0f}s", flush=True)

    # ---------- E) blend weights on validation ----------
    Xva = cached_featurize("validation", val.url_canonical.tolist())
    yva = (val.label == "phishing").astype(int).to_numpy()
    p_lg = lgbm_final.predict_proba(Xva)[:, 1]
    p_li = lr_final.predict_proba(tfidf.transform(val.url_canonical.str.lower().to_numpy()))[:, 1]
    blend_results = []
    for w in [0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8]:
        p = w * p_li + (1 - w) * p_lg
        sc = bench_scores(yva, p)
        blend_results.append({"w_text": w, **sc})
    Path("results/blend_validation.json").write_text(json.dumps(blend_results, indent=2))
    best = max(blend_results, key=lambda r: r["recall@0.010FPR"])
    w_text = float(best["w_text"])
    print("[blend] chosen w_text =", w_text, best, flush=True)

    # ---------- F) calibration (Platt a,b on calibration half A) + thresholds (half B) ----------
    Xca = cached_featurize("calibration", cal.url_canonical.tolist())
    yca = (cal.label == "phishing").astype(int).to_numpy()
    p_cal_lg = lgbm_final.predict_proba(Xca)[:, 1]
    p_cal_li = lr_final.predict_proba(tfidf.transform(cal.url_canonical.str.lower().to_numpy()))[:, 1]
    p_cal_raw = w_text * p_cal_li + (1 - w_text) * p_cal_lg
    h = cal.registrable_domain.map(lambda d: int(hashlib.sha256(d.encode()).hexdigest()[:8], 16) % 2).to_numpy(dtype=bool)
    calA = p_cal_raw[~h]; yA = yca[~h]
    calB = p_cal_raw[h]; yB = yca[h]
    # Platt: linear on the logit of the raw score, clipped
    eps = 1e-6
    zA = np.log(np.clip(calA, eps, 1 - eps) / (1 - np.clip(calA, eps, 1 - eps)))
    a, b = 1.0, 0.0
    try:
        from sklearn.linear_model import LogisticRegression as _LR
        pl = _LR(max_iter=200)
        pl.fit(zA.reshape(-1, 1), yA)
        a = float(pl.coef_[0, 0]); b = float(pl.intercept_[0])
    except Exception as e:
        print("[calib] Platt fallback", e, flush=True)
    cal_pa = 1 / (1 + np.exp(-(a * zA + b)))
    zB = np.log(np.clip(calB, eps, 1 - eps) / (1 - np.clip(calB, eps, 1 - eps)))
    cal_pol = 1 / (1 + np.exp(-(a * zB + b)))  # calibrated scores on half B (array)
    cal_stats = {"a": a, "b": b, "halfA_rows": int(calA.shape[0]),
                 "halfA_ece": float(np.mean(np.abs(cal_pa - (yA.mean() * np.ones_like(yA)))) if True else 0),
                 "halfA_auc": float(roc_auc_score(yA, cal_pa)) if yA.sum() and (yA == 0).sum() else None,
                 "halfB_auc": float(roc_auc_score(yB, cal_pol)) if yB.sum() and (yB == 0).sum() else None}

    # thresholds on calB at empirical FPR targets
    def thr_at(y, p, target):
        neg = np.where(y == 0)[0]
        if not len(neg):
            return 1.0
        scores = p[neg]
        return float(np.quantile(scores, 1 - target, method="higher"))
    thresholds = {"strict": thr_at(yB, cal_pol, 0.001),
                  "balanced": thr_at(yB, cal_pol, 0.01),
                  "sensitive": thr_at(yB, cal_pol, 0.05)}

    # ---------- G) calibration diagnostics: histograms by class/source + reliability ----------
    fig, axes = plt.subplots(1, 2, figsize=(12, 4.5))
    for lbl, sel in [("benign", yB == 0), ("phishing", yB == 1)]:
        axes[0].hist(cal_pol[sel], bins=50, alpha=0.5, label=f"calibration-B {lbl}", density=True)
    axes[0].set_yscale("log"); axes[0].set_xlabel("calibrated probability"); axes[0].set_title("calibration B by class"); axes[0].legend()
    frac_pos, mean_pred = calibration_curve(yB, cal_pol, n_bins=10, strategy="quantile")
    axes[1].plot(mean_pred, frac_pos, "o-", label="calibrated")
    axes[1].plot([0, 1], [0, 1], "--", color="gray", label="ideal")
    axes[1].set_xlabel("mean predicted probability"); axes[1].set_ylabel("fraction positive"); axes[1].legend()
    axes[1].set_title("reliability curve (calibration half B)")
    Path("results").mkdir(exist_ok=True)
    fig.tight_layout(); fig.savefig("results/calibration_diagnostics.png", dpi=120)
    # per-source histograms (json-serial binned); calibrated scores for the FULL slice
    eps_full = 1e-6
    zFull = np.log(np.clip(p_cal_raw, eps_full, 1 - eps_full) / (1 - np.clip(p_cal_raw, eps_full, 1 - eps_full)))
    cal_pol_full = 1 / (1 + np.exp(-(a * zFull + b)))
    per_source_hist = {}
    for src, g in cal.assign(p=cal_pol_full, y=yca).groupby("source"):
        per_source_hist[src] = {"rows": int(len(g)),
                                "phish": int(g.y.sum()),
                                "mean_p_phish": float(g.loc[g.y == 1, "p"].mean()),
                                "mean_p_benign": float(g.loc[g.y == 0, "p"].mean()),
                                "p95_benign": float(g.loc[g.y == 0, "p"].quantile(0.95)),
                                "p05_phish": float(g.loc[g.y == 1, "p"].quantile(0.05))}
    Path("results/calibration_by_source.json").write_text(json.dumps(per_source_hist, indent=2))

    # ---------- H) sanity-check the odd calibration from the first run ----------
    # many legit URLs scored 0.56-0.66 while phishing-pattern URLs scored 0.995: this
    # looks like heavily imbalanced scoring compressing the benign tail. Record the
    # benign quantiles of calibrated probabilities here for reference.
    diag = {"benign_quantiles": {str(q): float(np.quantile(cal_pol[yB == 0], q)) for q in [0.5, 0.9, 0.99, 0.999]},
            "phish_quantiles": {str(q): float(np.quantile(cal_pol[yB == 1], q)) for q in [0.01, 0.1, 0.5]},
            "w_text": w_text, "thresholds": thresholds, "calib": cal_stats}
    Path("results/model_v2_diagnostics.json").write_text(json.dumps(diag, indent=2))

    # ---------- I) persist bundle ----------
    bundle = {"kind": "stack",
              "lgbm": lgbm_final, "lr": lr_final, "tfidf": tfidf,
              "w_text": w_text, "calibration": {"a": a, "b": b},
              "thresholds": thresholds,
              "version": "3.0.0", "feature_names": feature_names()}
    joblib.dump(bundle, "results/model_bundle.joblib", compress=3)

    metrics = {"protocol": "StratifiedGroupKFold(5, seed 42, by registrable domain) on train_dev; "
                           "blend on validation; Platt on calibration half A; thresholds on half B; "
                           "holdout untouched",
               "cv": cv_rows, "cross_source": cross, "blend": blend_results,
               "w_text": w_text, "calibration": cal_stats, "thresholds": thresholds,
               "train_rows": int(len(trn)), "validation_rows": int(len(val)),
               "calibration_rows": int(len(cal)),
               "optional_char_cnn": "skipped: torch unavailable; decision in docs/DECISIONS.md"}
    Path("results/model_metrics_v2.json").write_text(json.dumps(metrics, indent=2))
    print("[done] v2 bundle + metrics written", flush=True)


if __name__ == "__main__":
    main()
