# DOWNLOAD_COMMANDS — sources not obtained automatically

Per the rebuild rules, nothing was invented and nothing was leaked. The following sources could not be fetched automatically from this machine. Run these commands yourself; each is idempotent and safe to re-run. After a successful download, re-run `uv run python scripts/ingest_external.py` (it auto-detects new snapshots) and then the rest of the pipeline.

## 1. `ealvaradob/phishing-dataset` (GitHub) — config `urls`
`scripts/ingest_external.py` expects: `data/external/ealvaradob/urls.json`

```bash
mkdir -p data/external/ealvaradob
# Main URLs file (~73 MB json with url/type)
curl -L --fail --retry 3 -o data/external/ealvaradob/urls.json \
  "https://raw.githubusercontent.com/ealvaradob/phishing-dataset/master/urls/urls.json"
# Fallback if the repo uses a branch named main:
# curl -L --fail --retry 3 -o data/external/ealvaradob/urls.json \
#   https://raw.githubusercontent.com/ealvaradob/phishing-dataset/main/urls/urls.json
```
Verification: `python -c "import json;d=json.load(open('data/external/ealvaradob/urls.json'));print(len(d))"` — expect a large list of `{"url": ..., "type": ...}` entries.

Status as of 2026-11-05: URLs under `master`/`main` for `urls/urls.json`, plus repo metadata, returned 404 from this network path (two separate probes). Not cached anywhere locally.

## 2. `PhiUSIIL Phishing URL (Livesafe)` dataset
Reputable mirrors found so far (from academic listings / UCI ML repo):
- UCI: `https://archive.ics.uci.edu/dataset/14101/phishing-url-identification-psi` (needs the exact download URL; UCITool may be needed)
- GitHub mirror attempts (all 404 from this network): `raw.githubusercontent.com/AhmedGabrala/PhiUSIIL/main/PhiUSIIL.csv`, and variants.
- Kaggle: `https://www.kaggle.com/datasets/phiusiill/phiusiill-phishing-url-livesafe` (or similar; requires Chrome cookies/session).

```bash
# Try direct raw first
mkdir -p data/external/phiusiil
curl -L --fail --retry 3 -o data/external/phiusiil/PhiUSIIL.csv \
  "https://raw.githubusercontent.com/AhmedGabrala/PhiUSIIL/main/PhiUSIIL.csv"
```
If that fails, download manually from UCI or Kaggle and place the CSV at `data/external/phiusiil/PhiUSIIL.csv`. Then rerun the ingest script after extending it to read this source.

## 3. `URL-Phish` / `URL-Phish.csv` dataset
Mirrors tried: `raw.githubusercontent.com/nickshum92/URL-Phish`, `abobakr/URL-Phish`, `NickShum/URL-Phish`, `ahmed-ghareeb/URL-Phish` — all 404 or ignore-failed.
Suggested manual sources:
- Kaggle mirror: search "URL-Phish csv"
- Zenodo record: search `URL-Phish phishing urls dataset zenodo`

```bash
mkdir -p data/external/urlphish
# Replace with the URL you locate:
# curl -L --fail --retry 3 -o data/external/urlphish/URL-Phish.csv "https://<resolved-url>"
```

## 4. Common Crawl CDX (benign sample)
Cancellation reason: `index.commoncrawl.org` (CDX) first query timed out at 25 s; second returned a valid `collinfo.json` and index listing (`CC-MAIN-2026-43`, `CC-MAIN-2024-33`, etc.), but the per-page `CC-MAIN-2026-43-index?url=...&output=json` requests did not complete inside the 90-min window. Also CDN-LFS (`cdn-lfs.huggingface.co`) did not respond to a TCP handshake (timeout 5 s), which rules out the large HF data shard route for raw crawls.

```bash
# Pick current index:
curl -s https://index.commoncrawl.org/collinfo.json | python -m json.tool | less
# CC-MAIN-2026-43 is a valid current index per the probe at 2026-11-05T01:xx UTC.
# Fetch one page of Tranco-domain URLs per 1 req/s politeness cap:
for i in 0 1 2 3; do
  curl -s --max-time 60 \
    "https://index.commoncrawl.org/CC-MAIN-2026-43-index?url=%2A.dominio.com&limit=20&output=json" \
    >> data/external/commoncrawl/sample.ndjson || true
  sleep 1
done
```
Not done automatically because the first per-page request timed out and the CDX endpoint was unstable during the window.

## 5. Phishing.Database (already obtained — for reference)
`data/external/phishing_database/active.txt` (789,054 lines) was fully retrieved on the second attempt. No action needed.

## 6. Kaggle mirrors (optional; browser session may be needed)
- `ealvaradob/phishing-dataset` on Kaggle (needs `kaggle` CLI + `~/.kaggle/kaggle.json`):
```bash
kaggle datasets download -d ealvaradob/phishing-dataset --path data/external/ealvaradob
```
- `PhiUSIIL` (Kaggle mirror), and a `URL-Phish` variant mirror:
```bash
kaggle datasets download -d <dataset-slug> --path data/external/<name>
```

## Compliance
- No URL strings from these sets are ever requested/resolved/crawled; they are ingested as strings only.
- PhreshPhish and Mendeley data are already present; do not re-download.
- Tranco `JZPGY` snapshot is pinned and cached locally.
