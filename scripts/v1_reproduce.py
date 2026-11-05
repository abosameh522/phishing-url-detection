"""Faithful reproduction + re-scoring of the v1 notebook pipeline with checkpointing.

Re-fits the legacy pipeline (cells 3,14,16,29,32,58-66 of notebooks/legacy) on the new
train pool, then re-scores it on eval_sealed/holdout under the new grouped protocol.
Checkpoint file: results/v1_checkpoint.joblib (safe to delete to force a full re-fit).
"""
import json
import re, math, ipaddress, time
from collections import Counter
from urllib.parse import urlsplit
from pathlib import Path
import pandas as pd
import numpy as np
import tldextract
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import (roc_curve, roc_auc_score, average_precision_score,
                             precision_score, recall_score, f1_score, confusion_matrix)
from sklearn.pipeline import Pipeline
from sklearn.compose import ColumnTransformer
from sklearn.impute import SimpleImputer
from sklearn.preprocessing import OneHotEncoder, StandardScaler
from sklearn.linear_model import LogisticRegression, SGDClassifier
from sklearn.dummy import DummyClassifier
from sklearn.ensemble import HistGradientBoostingClassifier, RandomForestClassifier
from sklearn.feature_extraction.text import TfidfVectorizer
import joblib

ext = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
CK_PATH = Path("results/v1_checkpoint.joblib")
ck = joblib.load(CK_PATH) if CK_PATH.exists() else {}
def save_ck(): joblib.dump(ck, CK_PATH, compress=1)

# --------------------------- v1 feature code (verbatim) ---------------------------
def parse_url(url):
    tmp = url
    if not re.match(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", url) and not url.startswith("//"):
        tmp = "//" + url
    try:
        return urlsplit(tmp)
    except ValueError:
        # v1 dropped rows without a usable host; emulate by returning an empty netloc
        return urlsplit("//")

words = ["login", "signin", "verify", "account", "password",
         "secure", "update", "banking", "confirm", "wallet"]

def entropy(s):
    n = len(s)
    if n == 0: return 0
    cnt = Counter(s); val = 0
    for v in cnt.values():
        p = v / n; val -= p * math.log2(p)
    return val

def get_features(url):
    p = parse_url(url)
    host = p.hostname or ""
    tmp = ext(host)
    text = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url)
    if text.startswith("//"): text = text[2:]
    n = len(text)
    digits = sum(c in "0123456789" for c in text)
    special = sum(c in ".-/@?=&%_:+~#" for c in text)
    low = text.lower(); path_low = p.path.lower()
    cnt = host_cnt = path_cnt = 0
    for word in words:
        if word in low: cnt += 1
        if word in host: host_cnt += 1
        if word in path_low: path_cnt += 1
    sub = len(tmp.subdomain.split(".")) if tmp.subdomain else 0
    depth = sum(1 for part in p.path.split("/") if part)
    params = sum(1 for part in p.query.split("&") if part)
    try: ipaddress.ip_address(host); is_ip = 1
    except ValueError: is_ip = 0
    punycode = 1 if any(part.startswith("xn--") for part in host.split(".")) else 0
    return {"url_length": n, "domain_length": len(host), "path_length": len(p.path),
            "query_length": len(p.query), "dot_count": text.count("."),
            "digit_count": digits, "hyphen_count": text.count("-"),
            "at_count": text.count("@"), "slash_count": text.count("/"),
            "question_count": text.count("?"), "equal_count": text.count("="),
            "amp_count": text.count("&"), "percent_count": text.count("%"),
            "underscore_count": text.count("_"), "special_count": special,
            "subdomain_count": sub, "host_digit_count": len(re.findall(r"[0-9]", host)),
            "host_hyphen_count": host.count("-"), "digit_ratio": digits / n,
            "path_depth": depth, "param_count": params, "has_ip": is_ip,
            "has_punycode": punycode, "suspicious_count": cnt,
            "host_suspicious_count": host_cnt, "path_suspicious_count": path_cnt,
            "host_entropy": entropy(host), "tld": tmp.suffix, "tld_length": len(tmp.suffix),
            "scheme_known": int(bool(p.scheme)),
            "has_https": int(p.scheme.lower() == "https")}

def strip_scheme(s):
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)
    return s[2:] if s.startswith("//") else s

def recall_at_fpr(y, p, target=0.05):
    fpr, tpr, thr = roc_curve(y, p)
    i = np.where(fpr <= target)[0][-1] if (fpr <= target).any() else 0
    return tpr[i], fpr[i], thr[i]

def make_preprocessor(scale=True):
    steps = [("imputer", SimpleImputer(strategy="median"))]
    if scale: steps.append(("scaler", StandardScaler()))
    num_tf = Pipeline(steps=steps)
    cat_tf = Pipeline(steps=[("imputer", SimpleImputer(strategy="most_frequent")),
                             ("encoder", OneHotEncoder(handle_unknown="infrequent_if_exist",
                                                       min_frequency=100, sparse_output=False))])
    return ColumnTransformer(transformers=[("num", num_tf, ck["feats"]["numeric"]),
                                           ("cat", cat_tf, ck["feats"]["categorical"])])

def target_recall(y, p, thr):
    pred = (np.asarray(p) >= thr).astype(int)
    tn, fp, fn, tp = confusion_matrix(y, pred).ravel()
    return {"recall": tp / max(1, tp + fn), "fpr": fp / max(1, fp + tn),
            "precision": precision_score(y, pred, zero_division=0),
            "f1": f1_score(y, pred, zero_division=0),
            "roc_auc": roc_auc_score(y, p), "ap": average_precision_score(y, p),
            "tp": int(tp), "fp": int(fp), "fn": int(fn), "tn": int(tn)}

# ------------------------------ main ------------------------------
if __name__ == "__main__":
    D = pd.read_parquet("data/processed/urls_unified.parquet")
    pool = D[D.split_role.isin(["train_dev", "validation", "calibration"])]

    # ---- Stage A: v1-style prepared data + first-fold 80/20 grouped split ----
    if "feats" not in ck:
        data = pool[["url_raw", "label"]].copy()
        data.columns = ["url", "label"]
        data["host"] = [parse_url(u).hostname or "" for u in data["url"]]
        data = data[data["host"] != ""].copy()
        data["domain"] = [ext(h).top_domain_under_public_suffix or h for h in data["host"]]
        data = data[["url", "host", "domain", "label"]].reset_index(drop=True)
        print("v1 prepared rows:", len(data), flush=True)

        split = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
        train_idx, test_idx = next(split.split(data, data["label"], groups=data["domain"]))
        train_df = data.iloc[train_idx].reset_index(drop=True)
        test_df = data.iloc[test_idx].reset_index(drop=True)
        print("v1 split -> train:", len(train_df), "test:", len(test_df),
              "domain overlap:", len(set(train_df.domain) & set(test_df.domain)), flush=True)

        train_features = pd.DataFrame([get_features(u) for u in train_df["url"]])
        test_features = pd.DataFrame([get_features(u) for u in test_df["url"]])
        ck["feats"] = {
            "train_url": train_df["url"].tolist(),
            "test_url": test_df["url"].tolist(),
            "train_domain": train_df["domain"].tolist(),
            "X_train": train_features.drop(columns=["scheme_known", "has_https"]),
            "X_test": test_features.drop(columns=["scheme_known", "has_https"]),
            "y_train": (train_df["label"] == "phishing").astype(int).to_numpy(),
            "y_test": (test_df["label"] == "phishing").astype(int).to_numpy(),
            "numeric": train_features.drop(columns=["scheme_known", "has_https"]).select_dtypes(include="number").columns.tolist(),
            "categorical": train_features.drop(columns=["scheme_known", "has_https"]).select_dtypes(exclude="number").columns.tolist(),
        }
        save_ck()
    # rebuild context from checkpoint
    X_train, X_test, y_train, y_test = ck["feats"]["X_train"], ck["feats"]["X_test"], ck["feats"]["y_train"], ck["feats"]["y_test"]
    groups = np.array(ck["feats"]["train_domain"])
    folds = list(StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42).split(X_train, y_train, groups=groups))
    print("checkpoint stage: feats ok", flush=True)

    # ---- Stage B: v1 OOF CV fits (Dummy, LogReg, HistGB, RF) ----

    ck.setdefault("oof", {}); ck.setdefault("results", [])
    oof = {k: np.asarray(v, dtype=np.float32) for k, v in ck["oof"].items()}

    def cv_fit(name, model):
        t0 = time.time()
        oof_pred = np.zeros(len(y_train), dtype=np.float32)
        for k, (tr, va) in enumerate(folds):
            model.fit(X_train.iloc[tr], y_train[tr])
            oof_pred[va] = model.predict_proba(X_train.iloc[va])[:, 1]
        r, f, t = recall_at_fpr(y_train, oof_pred)
        res = {"model": name, "recall@5%FPR": round(float(r), 4),
               "AP": round(float(average_precision_score(y_train, oof_pred)), 4),
               "ROC-AUC": round(float(roc_auc_score(y_train, oof_pred)), 4),
               "seconds": round(time.time() - t0, 1)}
        oof[name] = oof_pred
        ck["oof"][name] = oof_pred.tolist()
        ck["results"] = [x for x in ck["results"] if x["model"] != name] + [res]
        save_ck()
        print("   ", res, flush=True)

    MODELS = {
        "Dummy": Pipeline([("pre", make_preprocessor(scale=False)), ("clf", DummyClassifier(strategy="prior"))]),
        "LogReg": Pipeline([("pre", make_preprocessor(scale=True)), ("clf", LogisticRegression(max_iter=1000, class_weight="balanced"))]),
        "HistGB": Pipeline([("pre", make_preprocessor(scale=False)), ("clf", HistGradientBoostingClassifier(learning_rate=0.1, max_iter=150, random_state=42))]),
        "RandomForest": Pipeline([("pre", make_preprocessor(scale=False)), ("clf", RandomForestClassifier(n_estimators=200, min_samples_leaf=2, n_jobs=-1, random_state=42))]),
    }
    for name, model in MODELS.items():
        if name not in oof:
            print("[cv]", name, flush=True)
            cv_fit(name, model)
    print("checkpoint stage: oof ok", ck["results"], flush=True)

    # ---- Stage C: TextNgram (char 3-5 TF-IDF + SGD) OOF ----
    MODELS["text"] = Pipeline([
        ("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=5,
                                  max_features=150000, sublinear_tf=True, dtype=np.float32)),
        ("clf", SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=10, tol=None, random_state=42)),
    ])
    text_train = pd.Series(ck["feats"]["train_url"]).map(strip_scheme).str.lower()
    if "TextNgram" not in oof:
        print("[cv] TextNgram", flush=True)
        tfidf = MODELS["text"].named_steps["tfidf"]; tfidf.fit(text_train)
        Ztr_full = tfidf.transform(text_train)
        del tfidf
        text_sgd = MODELS["text"].named_steps["clf"]
        oof_pred = np.zeros(len(y_train), dtype=np.float32)
        for k, (tr, va) in enumerate(folds):
            t0 = time.time()
            sgd_k = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=10, tol=None, random_state=42)
            sgd_k.fit(Ztr_full[tr], y_train[tr])
            oof_pred[va] = sgd_k.predict_proba(Ztr_full[va])[:, 1]
            print(f"    text fold {k} ({time.time()-t0:.0f}s)", flush=True)
        r, f, t = recall_at_fpr(y_train, oof_pred)
        res = {"model": "TextNgram", "recall@5%FPR": round(float(r), 4),
               "AP": round(float(average_precision_score(y_train, oof_pred)), 4),
               "ROC-AUC": round(float(roc_auc_score(y_train, oof_pred)), 4)}
        oof["TextNgram"] = oof_pred
        ck["oof"]["TextNgram"] = oof_pred.tolist()
        ck["results"] = [x for x in ck["results"] if x["model"] != "TextNgram"] + [res]
        save_ck()
    else:
        # rebuild tfidf vocabulary for the fit (vocab is data-derived; refit fast)
        tfidf = MODELS["text"].named_steps["tfidf"]; tfidf.fit(text_train)
        del tfidf

    # blend sweep on OOF (self-consistent with v1 cells 63-65)
    for w in [0.0, 0.2, 0.3, 0.4, 0.5, 0.6, 0.7, 0.8, 0.9, 1.0]:
        p = w * oof["TextNgram"] + (1 - w) * oof["HistGB"]
        r, f, t = recall_at_fpr(y_train, p)
        print(f"blend w_text={w}: recall@5%FPR={r:.4f} AP={average_precision_score(y_train, p):.4f} AUC={roc_auc_score(y_train, p):.4f}", flush=True)

    # ---- Stage D: v1 final config + fit (w_text=0.7, thr from OOF @5%FPR) ----
    W_TEXT = 0.7
    p_val = W_TEXT * oof["TextNgram"] + (1 - W_TEXT) * oof["HistGB"]
    rec, fpr, thr_final = recall_at_fpr(y_train, p_val)
    print(f"v1 config: W_TEXT={W_TEXT} threshold={thr_final:.6f} oof_recall@5%FPR={rec:.4f}", flush=True)

    if "final" not in ck:
        final_hgb = MODELS["HistGB"]; final_hgb.fit(X_train, y_train)
        tfidf = TfidfVectorizer(analyzer="char", ngram_range=(3, 5), min_df=5,
                                max_features=150000, sublinear_tf=True, dtype=np.float32)
        text_fit = tfidf.fit_transform(text_train)
        sgd_final = SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=10, tol=None, random_state=42)
        sgd_final.fit(text_fit, y_train)
        ck["final"] = {"hgb": final_hgb, "tfidf": tfidf, "sgd": sgd_final,
                       "w_text": W_TEXT, "threshold": float(thr_final)}
        save_ck()
        print("checkpoint stage: final ok", flush=True)

    hb = ck["final"]
    # ---- Stage E: v1 on its own test (in-distribution, for reference) ----
    Xte = X_test
    ph = hb["hgb"].predict_proba(Xte)[:, 1]
    text_test = pd.Series(ck["feats"]["test_url"]).map(strip_scheme).str.lower()
    pt = hb["sgd"].predict_proba(hb["tfidf"].transform(text_test))[:, 1]
    p_test = W_TEXT * pt + (1 - W_TEXT) * ph
    ref = target_recall(y_test, p_test, hb["threshold"])
    print("v1 own-test (in-distribution, thr=%.3f):" % hb["threshold"], {k: round(v, 4) if isinstance(v, float) else v for k, v in ref.items()}, flush=True)

    # ---- Stage F: v1 re-scored under the NEW grouped protocol ----
    out = {"reference_own_test": ref, "config": {"w_text": W_TEXT, "threshold": hb["threshold"]}, "oof_results": ck["results"]}
    new_protocol = {}
    for slice_name in ["eval_sealed", "holdout", "eval_tranco", "validation"]:
        sub = D[D.split_role == slice_name]
        if len(sub) == 0: continue
        yv = (sub["label"] == "phishing").astype(int).to_numpy()
        feat = pd.DataFrame([get_features(u) for u in sub["url_canonical"]])
        Xv = feat.drop(columns=["scheme_known", "has_https"])
        Xv = Xv.reindex(columns=X_train.columns, fill_value=0)
        pv_h = hb["hgb"].predict_proba(Xv)[:, 1]
        pv_t = hb["sgd"].predict_proba(hb["tfidf"].transform(sub["url_canonical"].str.lower().to_numpy()))[:, 1]
        pv = W_TEXT * pv_t + (1 - W_TEXT) * pv_h
        row = {"rows": int(len(sub)), "phish": int(yv.sum())}
        # v1's own operating point
        row["at_v1_threshold"] = target_recall(yv, pv, hb["threshold"])
        # matched-protocol operating points: recall at fixed FPR targets
        for t in [0.001, 0.01, 0.05]:
            if len(np.unique(yv)) == 2:
                r, f, th = recall_at_fpr(yv, pv, t)
                row[f"recall@{t:.3f}FPR"] = float(r); row[f"fpr@{t:.3f}"] = float(f); row[f"thr@{t:.3f}"] = float(th)
        new_protocol[slice_name] = row
        print("[new-protocol]", slice_name, {k: (round(v, 4) if isinstance(v, float) else v) for k, v in row.items()}, flush=True)
    out["new_protocol"] = new_protocol
    Path("results").mkdir(exist_ok=True)
    Path("results/v1_rescore.json").write_text(json.dumps({k: v for k, v in out.items()}, indent=2, default=str))
    print("WROTE results/v1_rescore.json", flush=True)
