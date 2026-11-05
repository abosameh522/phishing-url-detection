"""Faithful reproduction of v1 notebook pipeline (cells 3,14,16,29,32,58-66)."""
import re, math, ipaddress, time
from collections import Counter
from urllib.parse import urlsplit
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
    if n == 0:
        return 0
    cnt = Counter(s)
    val = 0
    for v in cnt.values():
        p = v / n
        val -= p * math.log2(p)
    return val

def get_features(url):
    p = parse_url(url)
    host = p.hostname or ""
    tmp = ext(host)
    text = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", url)
    if text.startswith("//"):
        text = text[2:]
    n = len(text)
    digits = 0
    special = 0
    for c in text:
        if c in "0123456789":
            digits += 1
        if c in ".-/@?=&%_:+~#":
            special += 1
    low = text.lower()
    path_low = p.path.lower()
    cnt = 0
    host_cnt = 0
    path_cnt = 0
    for word in words:
        if word in low:
            cnt += 1
        if word in host:
            host_cnt += 1
        if word in path_low:
            path_cnt += 1
    sub = 0
    if tmp.subdomain:
        sub = len(tmp.subdomain.split("."))
    depth = 0
    for part in p.path.split("/"):
        if part:
            depth += 1
    params = 0
    for part in p.query.split("&"):
        if part:
            params += 1
    is_ip = 0
    try:
        ipaddress.ip_address(host)
        is_ip = 1
    except ValueError:
        pass
    punycode = 0
    for part in host.split("."):
        if part.startswith("xn--"):
            punycode = 1
    return {
        "url_length": n,
        "domain_length": len(host),
        "path_length": len(p.path),
        "query_length": len(p.query),
        "dot_count": text.count("."),
        "digit_count": digits,
        "hyphen_count": text.count("-"),
        "at_count": text.count("@"),
        "slash_count": text.count("/"),
        "question_count": text.count("?"),
        "equal_count": text.count("="),
        "amp_count": text.count("&"),
        "percent_count": text.count("%"),
        "underscore_count": text.count("_"),
        "special_count": special,
        "subdomain_count": sub,
        "host_digit_count": len(re.findall(r"[0-9]", host)),
        "host_hyphen_count": host.count("-"),
        "digit_ratio": digits / n,
        "path_depth": depth,
        "param_count": params,
        "has_ip": is_ip,
        "has_punycode": punycode,
        "suspicious_count": cnt,
        "host_suspicious_count": host_cnt,
        "path_suspicious_count": path_cnt,
        "host_entropy": entropy(host),
        "tld": tmp.suffix,
        "tld_length": len(tmp.suffix),
        "scheme_known": int(bool(p.scheme)),
        "has_https": int(p.scheme.lower() == "https"),
    }

def strip_scheme(s):
    s = re.sub(r"^[a-zA-Z][a-zA-Z0-9+.-]*://", "", s)
    return s[2:] if s.startswith("//") else s

def recall_at_fpr(y, p, target=0.05):
    fpr, tpr, thr = roc_curve(y, p)
    i = np.where(fpr <= target)[0][-1]
    return tpr[i], fpr[i], thr[i]

def make_preprocessor(scale=True):
    steps = [("imputer", SimpleImputer(strategy="median"))]
    if scale:
        steps.append(("scaler", StandardScaler()))
    num_tf = Pipeline(steps=steps)
    cat_tf = Pipeline(steps=[
        ("imputer", SimpleImputer(strategy="most_frequent")),
        ("encoder", OneHotEncoder(handle_unknown="infrequent_if_exist",
                                  min_frequency=100,
                                  sparse_output=False)),
    ])
    return ColumnTransformer(transformers=[
        ("num", num_tf, numeric_features),
        ("cat", cat_tf, categorical_features),
    ])

if __name__ == "__main__":
    # Load training pool from the rebuilt corpus
    D = pd.read_parquet("data/processed/urls_unified.parquet")
    train_pool = D[D.split_role.isin(["train_pool","train_dev","validation","calibration"])]
    print("v1 training pool rows:", len(train_pool))

    # Step 1: data['url'], 'label', 'domain' (domain = tldextract top_domain_under_public_suffix)
    import tldextract as te2
    ext2 = te2.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)
    data = train_pool[["url_raw", "label"]].copy()
    data["url"] = data["url_raw"]  # v1 column name
    data["host"] = [parse_url(u).hostname or "" for u in data["url"]]
    data = data[data["host"] != ""].copy()
    data["domain"] = [ext2(h).top_domain_under_public_suffix or h for h in data["host"]]
    data = data[["url","host","domain","label"]].reset_index(drop=True)
    print("Clean rows:", len(data))

    # Step 2: 80/20 split via first fold of StratifiedGroupKFold
    split = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
    train_idx, test_idx = next(split.split(data, data["label"], groups=data["domain"]))
    train_df = data.iloc[train_idx].reset_index(drop=True)
    test_df = data.iloc[test_idx].reset_index(drop=True)
    print("V1 split -> train:", len(train_df), "test:", len(test_df),
          "domain overlap:", len(set(train_df["domain"]) & set(test_df["domain"])))

    # Step 3: features
    arr = [get_features(u) for u in train_df["url"]]
    train_features = pd.DataFrame(arr, index=train_df.index)
    arr = [get_features(u) for u in test_df["url"]]
    test_features = pd.DataFrame(arr, index=test_df.index)
    X_train = train_features.drop(columns=["scheme_known","has_https"])
    X_test = test_features.drop(columns=["scheme_known","has_https"])
    y_train = (train_df["label"] == "phishing").astype(int)
    y_test = (test_df["label"] == "phishing").astype(int)
    numeric_features = X_train.select_dtypes(include="number").columns.tolist()
    categorical_features = X_train.select_dtypes(exclude="number").columns.tolist()

    # Step 4: CV folds on the full training set (v1 computes OOF on all train)
    groups = train_df["domain"].to_numpy()
    cv = StratifiedGroupKFold(n_splits=3, shuffle=True, random_state=42)
    folds = list(cv.split(X_train, y_train, groups=groups))

    models = {"Dummy": Pipeline([("pre", make_preprocessor(scale=False)), ("clf", DummyClassifier(strategy="prior"))])}
    oof = {}
    results = []
    for name, model in models.items():
        oof_pred = np.zeros(len(X_train))
        for k,(tr,va) in enumerate(folds):
            model.fit(X_train.iloc[tr], y_train.iloc[tr])
            oof_pred[va] = model.predict_proba(X_train.iloc[va])[:,1]
        r,f,t = recall_at_fpr(y_train, oof_pred)
        results.append({"model":name,"recall@5%FPR":round(r,4),"AP":round(average_precision_score(y_train,oof_pred),4),"ROC-AUC":round(roc_auc_score(y_train,oof_pred),4)})
        oof[name]=oof_pred
    print("OOF results:", results)

    models["LogReg"]=Pipeline([("pre",make_preprocessor(scale=True)),("clf",LogisticRegression(max_iter=1000,class_weight="balanced"))])
    models["HistGB"]=Pipeline([("pre",make_preprocessor(scale=False)),("clf",HistGradientBoostingClassifier(learning_rate=0.1,max_iter=150,random_state=42))])
    models["RandomForest"]=Pipeline([("pre",make_preprocessor(scale=False)),("clf",RandomForestClassifier(n_estimators=200,min_samples_leaf=2,n_jobs=-1,random_state=42))])
    for name, model in models.items():
        if name in oof: continue
        oof_pred = np.zeros(len(X_train))
        for k,(tr,va) in enumerate(folds):
            model.fit(X_train.iloc[tr], y_train.iloc[tr])
            oof_pred[va] = model.predict_proba(X_train.iloc[va])[:,1]
        r,f,t = recall_at_fpr(y_train, oof_pred)
        results.append({"model":name,"recall@5%FPR":round(r,4),"AP":round(average_precision_score(y_train,oof_pred),4),"ROC-AUC":round(roc_auc_score(y_train,oof_pred),4),"seconds":round(time.time(),0)})
        oof[name]=oof_pred
    print("OOF results:", results)

    # Text ngram
    text_train = train_df["url"].map(strip_scheme).str.lower().reset_index(drop=True)
    text_model = Pipeline([("tfidf", TfidfVectorizer(analyzer="char", ngram_range=(3,5), min_df=5, max_features=150000, sublinear_tf=True, dtype=np.float32)),
                           ("clf", SGDClassifier(loss="log_loss", alpha=1e-6, max_iter=10, tol=None, random_state=42))])
    oof_text = np.zeros(len(text_train))
    for k,(tr,va) in enumerate(folds):
        text_model.fit(text_train.iloc[tr], y_train.iloc[tr])
        oof_text[va] = text_model.predict_proba(text_train.iloc[va])[:,1]
    oof["TextNgram"]=oof_text
    r,f,t = recall_at_fpr(y_train, oof_text)
    print("TextNgram alone: recall@5%FPR=%.4f AP=%.4f AUC=%.4f" % (r,f,t))

    # Blend weight search
    rows=[]
    for w in [0.0,0.2,0.3,0.4,0.5,0.6,0.7,0.8,0.9,1.0]:
        p=w*oof["TextNgram"]+(1-w)*oof["HistGB"]
        rr,fr,tr_ = recall_at_fpr(y_train, p)
        rows.append({"w_text":w,"recall@5%FPR":round(rr,4),"AP":round(average_precision_score(y_train,p),4),"ROC-AUC":round(roc_auc_score(y_train,p),4)})
    import pandas as pd2
    print(pd2.DataFrame(rows).set_index("w_text").to_string())

    # Final v1: W_TEXT=0.7, threshold from recall@5%FPR
    W_TEXT=0.7
    p_val=W_TEXT*oof["TextNgram"]+(1-W_TEXT)*oof["HistGB"]
    rec,fpr,thr_final=recall_at_fpr(y_train, p_val)
    pred_val=(p_val>=thr_final).astype(int)
    tn,fp,fn,tp=confusion_matrix(y_test if False else y_train, pred_val).ravel()
    # Note: v1 final fit uses THRESHOLD on X_test in notebook cell 66 -> recompute p_test
    print("\n=== v1 config ===")
    print("W_TEXT:", W_TEXT, "threshold:", round(float(thr_final),6))
    print("OOF train recall@5FPR:", round(rec,4), "FPR:", round(float(fpr),4))
    print("OOF precision:", round(precision_score(y_train,pred_val),4), "F1:", round(f1_score(y_train,pred_val),4))

    # Reproduce cell 66 on test set (the notebook's actual final eval)
    t0=time.time()
    final_hgb=models["HistGB"]
    final_hgb.fit(X_train, y_train)
    text_test=test_df["url"].map(strip_scheme).str.lower().reset_index(drop=True)
    final_text=text_model
    final_text.fit(text_test if False else text_train, y_train)
    p_hgb=final_hgb.predict_proba(X_test)[:,1]
    p_text=final_text.predict_proba(text_test)[:,1]
    p_test=W_TEXT*p_text+(1-W_TEXT)*p_hgb
    pred=(p_test>=thr_final).astype(int)
    tn,fp,fn,tp=confusion_matrix(y_test,pred).ravel()
    print("\n=== v1 TEST RESULTS (cell 66) ===")
    print(f"Recall    : {tp/(tp+fn):.4f}")
    print(f"FPR       : {fp/(fp+tn):.4f}")
    print(f"Precision : {precision_score(y_test,pred):.4f}")
    print(f"F1        : {f1_score(y_test,pred):.4f}")
    print(f"AP        : {average_precision_score(y_test,p_test):.4f}")
    print(f"ROC-AUC   : {roc_auc_score(y_test,p_test):.4f}")
    print(f"TP={tp} FP={fp} FN={fn} TN={tn}")

    # v1 eval under the NEW protocol: on the rebuilt corpus eval slices
    print("\n=== v1 re-scored under NEW protocol (domain-grouped CV) ===")
    for split in ["eval_sealed","holdout"]:
        sub=D[D.split_role==split]
        if len(sub)==0: continue
        feat=[get_features(u) for u in sub["url"]]
        Xv=pd.DataFrame(feat).drop(columns=["scheme_known","has_https"])
        xv=Xv.align(X_train,join="left",axis=1)[0].fillna(0)
        p=final_hgb.predict_proba(xv)[:,1]
        pt=final_text.predict_proba(sub["url"].map(strip_scheme).str.lower().reset_index(drop=True))[:,1]
        pv=W_TEXT*pt+(1-W_TEXT)*p
        y=(sub["label"]=="phishing").astype(int)
        print(split, "rows:",len(sub), "phish:",int(y.sum()))
        for mode,t in [("strict",0.987),("balanced",0.795),("sensitive",0.698)]:
            pr=(pv>=t).astype(int)
            tn,fp,fn,tp=confusion_matrix(y,pr).ravel()
            print(f"  {mode} t={t:.3f} recall={tp/(tp+fn):.4f} fpr={fp/(fp+tn):.4f} prec={precision_score(y,pr):.4f}")
        # recall at FPR
        fr,fa,tf=recall_at_fpr(y,pv)
        print(f"  recall@1%FPR={fr:.4f}  recall@0.1%FPR=", end="")
        fr01,fa01,tf01=recall_at_fpr(y,pv,0.001)
        print(f"{fr01:.4f}")

    joblib.dump({"w_text":W_TEXT,"threshold":float(thr_final)}, "results/v1_final_config.joblib")
    print("\nSaved results/v1_final_config.joblib")
