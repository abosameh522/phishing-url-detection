"""Build the unified metadata-only URL table from locally-snapshotting sources; never contacts URLs."""
from pathlib import Path
from datetime import datetime, timezone
import csv, hashlib, json, re, time
from urllib.parse import urlsplit

import pandas as pd
import pyarrow.parquet as pq

ROOT = Path(".")
now = datetime.now(timezone.utc).isoformat()

rows = []
drops = {}
source_counts = {}


def add(raw, label, source, family, role, date="", target="", lang="",
        license_str="unknown", hard_negative=False, hard_positive=False, weight=1.0):
    raw = (str(raw) if raw is not None else "").strip()
    if label not in ("benign", "phishing"):
        drops["unsupported_label"] = drops.get("unsupported_label", 0) + 1
        return
    try:
        if len(raw) > 2048 or any(ord(c) < 32 for c in raw):
            raise ValueError("invalid chars/length")
        from phishing_url_detection.canonical import canonicalize, raw_flags
        from phishing_url_detection.features import registrable_domain
        c = canonicalize(raw)
        reg = registrable_domain(c)
        p = urlsplit(c if "://" in c else "//" + c)
        host = p.hostname or ""
        if not reg or not host:
            raise ValueError("missing host")
    except Exception:
        drops[f"{source}:unparseable"] = drops.get(f"{source}:unparseable", 0) + 1
        return
    rows.append({
        "url_raw": raw, "url_canonical": c, "label": label, "source": source,
        "family": family, "split_role": role, "date": str(date or "")[:10],
        "brand_target": str(target or ""), "lang": str(lang or ""),
        "registrable_domain": reg, "host": host,
        "tld": reg.split(".")[-1] if "." in reg else "",
        **raw_flags(raw),
        "hard_negative": bool(hard_negative), "hard_positive": bool(hard_positive),
        "collected_at": now, "license": license_str, "sample_weight": float(weight),
    })


def read_parquets(folder, source, family, role, license_str):
    paths = sorted(Path(folder).glob("*.parquet"))
    n = 0
    LABEL_MAP = {"benign": "benign", "phish": "phishing", "phishing": "phishing"}
    for path in paths:
        t = pq.read_table(path, columns=["url", "label", "target", "date", "lang"])
        d = t.to_pydict()
        for i, u in enumerate(d["url"]):
            if not u:
                continue
            label = LABEL_MAP.get(str(d["label"][i]).lower())
            if label is None:
                drops["unsupported_label"] = drops.get("unsupported_label", 0) + 1
                continue
            date = d["date"][i]
            add(u, label, source, family, role, str(date or "")[:10],
                str(d["target"][i] or ""), str(d["lang"][i] or ""), license_str)
            n += 1
    source_counts[source] = n


# ---------- 1) Local Kaggle-style source ----------
p = Path("malicious_phish.csv")
if p.exists():
    n = 0
    for r in csv.DictReader(open(p, encoding="utf-8", errors="replace", newline="")):
        lab = r.get("type", "").strip().lower()
        if lab in ("benign", "phishing"):
            add(r.get("url"), lab, "malicious_phish.csv", "kaggle_like",
                "train_pool", "2017", license_str="provenance uncertain, Kaggle mirror")
            n += 1
    source_counts["malicious_phish.csv"] = n

# ---------- 2) PhreshPhish: train -> pool; test -> eval_sealed ----------
pp = Path("data/external/phreshphish")
if (pp / "train").exists():
    read_parquets(pp / "train", "PhreshPhish train", "phreshphish", "train_pool",
                  "CC BY 4.0; anti-phishing research only")
if (pp / "test").exists():
    read_parquets(pp / "test", "PhreshPhish test", "phreshphish", "eval_sealed",
                  "CC BY 4.0; anti-phishing research only")

# ---------- 3) Mendeley academic sets ----------
# MURL: url + type (benign, phishing, malware, defacement -> phishing; legit -> benign)
murl = Path("data/external/mendeley/MURL_1_Malicious URL Detection.csv")
if murl.exists():
    seen = set()
    for r in csv.DictReader(open(murl, encoding="utf-8", errors="replace", newline="")):
        raw = r.get("url", "").strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        raw = raw.lstrip("//")
        lab = r.get("type", "").strip().lower()
        if lab in ("benign", "legitimate"):
            add(raw, "benign", "MURL", "mendeley_academic", "train_pool", "2020",
                license_str="Mendeley public data; verify licence metadata")
        elif lab in ("phishing", "malware", "defacement"):
            add(raw, "phishing", "MURL", "mendeley_academic", "train_pool", "2020",
                license_str="Mendeley public data; verify licence metadata")
    source_counts["MURL"] = len(seen)

# PhishBD_2026: url + label (0=benign,1=phishing)
pbd = Path("data/external/mendeley/PhishBD_2026_2_PhishBD_2026_73_features.csv")
if pbd.exists():
    seen = set()
    for r in csv.DictReader(open(pbd, encoding="utf-8", errors="replace", newline="")):
        raw = r.get("url", "").strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        raw = raw.lstrip("//")
        lab = str(r.get("label", "")).strip()
        if lab in ("0", 0, "benign"):
            add(raw, "benign", "PhishBD_2026", "mendeley_academic", "train_pool", "2026",
                license_str="Mendeley public data; verify licence metadata")
        elif lab in ("1", 1, "phishing"):
            add(raw, "phishing", "PhishBD_2026", "mendeley_academic", "train_pool", "2026",
                license_str="Mendeley public data; verify licence metadata")
    source_counts["PhishBD_2026"] = len(seen)

# LegitPhish: URL + ClassLabel (0=benign,1=phishing -> inverted)
lp = Path("data/external/mendeley/LegitPhish_1_url_features_extracted1.csv")
if lp.exists():
    seen = set()
    for r in csv.DictReader(open(lp, encoding="utf-8", errors="replace", newline="")):
        raw = r.get("URL", "").strip()
        if not raw or raw in seen:
            continue
        seen.add(raw)
        raw = raw.lstrip("//")
        lab = str(r.get("ClassLabel", "")).strip()
        if lab in ("0", 0):
            add(raw, "benign", "LegitPhish", "mendeley_academic", "eval_sealed",
                "2021", license_str="Mendeley public data; verify licence metadata")
        elif lab in ("1", 1):
            add(raw, "phishing", "LegitPhish", "mendeley_academic", "eval_sealed",
                "2021", license_str="Mendeley public data; verify licence metadata")
    source_counts["LegitPhish"] = len(seen)

# ---------- 4) Tranco top-10k homepages (benign, evaluation only; rank never a feature) ----------
tranco = Path("data/external/tranco/JZPGY-top10k.csv")
tranco_domains = []
if tranco.exists():
    for r in csv.reader(open(tranco, encoding="utf-8", errors="replace")):
        if len(r) >= 2:
            rank, domain = r[0].strip(), r[1].strip().lower()
            if domain and domain not in tranco_domains:
                tranco_domains.append(domain)
                add("https://" + domain + "/", "benign", "Tranco JZPGY top10k",
                    "tranco", "eval_tranco", date="2026-11-04",
                    license_str="Tranco terms; research snapshot")
source_counts["Tranco JZPGY top10k"] = len(tranco_domains)

# ---------- 5) Fresh phishing feeds (strings only, never dereferenced) ----------
feeds = [
    ("OpenPhish", "data/raw/fresh/openphish_2026-11-05.txt", "community feed terms", "2026-11-05"),
    ("Phishing.Database", "data/external/phishing_database/active.txt",
     "repository licence/terms; verify before redistribution", "2026-11-05"),
]
for src, file, lic, date in feeds:
    path = Path(file)
    n = 0
    if path.exists():
        for line in path.open(encoding="utf-8", errors="replace"):
            s = line.strip()
            if not s or s.startswith("#"):
                continue
            # Phishing.Database includes FTP/spam strings; keep all URL-formatted strings
            if s and (s.startswith(("http://", "https://", "ftp://")) or
                      re.match(r"^[a-z0-9.-]+\.(com|net|org|top|xyz|info|tk)$", s, re.I)):
                add(s, "phishing", src, "fresh_phishing", "eval_fresh", date, license_str=lic)
                n += 1
    source_counts[src] = n

# ---------- 6) Dedupe by canonical URL ----------
priority = {"eval_sealed": 0, "eval_fresh": 1, "eval_tranco": 2, "train_pool": 3}
by = {}
conflicts = set()
for r in rows:
    c = r["url_canonical"]
    old = by.get(c)
    if old and old["label"] != r["label"]:
        conflicts.add(c)
    elif not old or priority[r["split_role"]] < priority[old["split_role"]]:
        by[c] = r
for c in conflicts:
    by.pop(c, None)
source_counts["duplicates_kept"] = len(by)
source_counts["conflicting_urls_removed"] = len(conflicts)

df = pd.DataFrame(by.values())
df = df.sort_values("url_canonical").reset_index(drop=True)

# ---------- 7) Zero train/eval overlap by registrable domain ----------
evalroles = {"eval_sealed", "eval_fresh", "eval_tranco"}
reserved = set(df.loc[df.split_role.isin(evalroles), "registrable_domain"])
overlap_train = df.split_role.eq("train_pool") & df.registrable_domain.isin(reserved)
drops["training_rows_removed_for_eval_domain_overlap"] = int(overlap_train.sum())
df = df.loc[~overlap_train].copy()

# ---------- 8) Deterministic hashed splits inside train_pool only ----------
def bucket(domain):
    return int(hashlib.sha256(domain.encode()).hexdigest()[:8], 16) % 100

roles = []
for d, r in zip(df.registrable_domain, df.split_role):
    if r != "train_pool":
        roles.append(r)
        continue
    h = bucket(d)
    roles.append("holdout" if h < 15 else ("train_dev" if h < 75 else ("validation" if h < 88 else "calibration")))
df["split_role"] = roles

# ---------- 9) Assertions ----------
sets = {s: set(df.loc[df.split_role == s, "registrable_domain"]) for s in df.split_role.unique()}
# every role is present in df (assertion only; if train_pool empty we skip it)
all_roles = list(df.split_role.unique())
for tr in all_roles:
    for ev in all_roles:
        if tr == ev:
            continue
        # ONLY forbid overlap between training roles and evaluation roles
        if ("train" in tr) and ("eval" in ev):
            assert not sets[tr] & sets[ev], f"LEAK: {tr} overlaps {ev}"
assert not df.duplicated("url_canonical").any(), "canonical duplicates remain"
# no model feature of train can come from eval roles: enforced by column choice (lexical only)

# ---------- 10) Write parquet ----------
out = ROOT / "data/processed"
out.mkdir(parents=True, exist_ok=True)
df.to_parquet(out / "urls_unified.parquet", index=False)

# ---------- 11) PhreshPhish benchmark hash matching (strings only) ----------
bench_results = {}
url_by_hash = {}
for d in df.loc[df.source.eq("PhreshPhish test"), ["url_raw", "url_canonical", "label"]].itertuples(index=False):
    url_by_hash[hashlib.sha256(d.url_raw.encode()).hexdigest()] = (d.url_raw, d.label)
bench_dir = Path("data/external/phreshphish/benchmark")
for dirpath in sorted(bench_dir.glob("benchmark-*")):
    hashes = []
    for f in dirpath.glob("*.txt"):
        hashes.extend(x.strip().lower() for x in f.read_text(errors="ignore").splitlines() if x.strip())
    matched = [url_by_hash[h] for h in hashes if h in url_by_hash]
    bench_results[dirpath.name] = {
        "hashes": len(hashes),
        "matched_to_test_urls": len(matched),
        "base_rate_label": dirpath.name.replace("benchmark-", ""),
    }

# ---------- 12) Manifest ----------
manifest = {
    "created_at": now,
    "sources_attempted": [
        "malicious_phish.csv", "PhreshPhish", "ealvaradob/phishing-dataset",
        "MURL", "PhishBD_2026", "PhiUSIIL", "URL-Phish", "LegitPhish",
        "Tranco JZPGY", "OpenPhish", "Phishing.Database", "Common Crawl",
    ],
    "sources_kept": {k: v for k, v in source_counts.items() if k != "duplicates_kept"},
    "sources_skipped": {
        "ealvaradob/phishing-dataset": "repo/URLs resolve 404 (unavailable); see docs/DECISIONS.md D0",
        "MURL": "ingested", "PhishBD_2026": "ingested", "PhiUSIIL": "repo not found (404)",
        "URL-Phish": "repo not found (404)", "LegitPhish": "ingested",
        "Common Crawl": "CDX query deferred - not downloaded in this run",
    },
    "rows_kept": len(df),
    "rows_dropped": drops,
    "conflicting_urls_removed": len(conflicts),
    "class_balance": df.label.value_counts().to_dict(),
    "registrable_domains": int(df.registrable_domain.nunique()),
    "split_counts": df.split_role.value_counts().to_dict(),
    "reserved_eval_domains": len(reserved),
    "phresh_columns_read": ["url", "label", "target", "date", "lang"],
    "phresh_html_loaded": False,
    "phresh_benchmark_file_summary": bench_results,
    "tranco_list_id": "JZPGY",
    "tranco_created_on": "2026-11-04",
    "no_url_requests": True,
    "split_by": "registrable_domain (tldextract, private suffixes)",
}
manifest_path = out / "manifest.json"
manifest_path.write_text(json.dumps(manifest, indent=2))

# ---------- 13) Spot check ----------
spot = df.sample(min(300, len(df)), random_state=42)[["source", "label", "url_raw"]]
spot.to_csv("data/spot_check.csv", index=False)

print("UNIFIED PARQUET WRITTEN:", out / "urls_unified.parquet", "rows:", len(df))
print("split_counts:", dict(df.split_role.value_counts()))
print("class_balance:", dict(df.label.value_counts()))
print("sources_kept:", source_counts)
print("duplicates/conflicts:", source_counts.get("duplicates_kept"), len(conflicts))
print("manifest:", manifest_path)
