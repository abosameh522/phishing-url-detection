"""Fetch benign URLs WITH paths/queries from Common Crawl CDX (fallback: Wayback CDX).

Rules honoured:
- We fetch only raw candidate URL strings to ingest as BENIGN corpus rows. We never fetch a
  phishing URL; targets are popular legit domains from a fixed allow-list + Tranco top ranks.
- <= 1 request/second per host (1.15 s sleep), bounded total requests, fully resumable:
  state (requested domains + last offset) lives in data/external/commoncrawl/_state.json.
- Fallback to Wayback CDX when index.commoncrawl.org fails a domain.
"""
from pathlib import Path
import json, time, urllib.request, urllib.error, urllib.parse, sys

OUT = Path("data/external/commoncrawl")
STATE = OUT / "_state.json"
CACHE = OUT / "benign_paths.ndjson"
CC = "https://index.commoncrawl.org/CC-MAIN-2026-43-index"
WB = "https://web.archive.org/cdx/search/cdx"
SLEEP = 1.15
MAX_REQUESTS = 420           # hard cap on total requests per invocation
BUDGET_SECONDS = 60 * 90     # stop after 90 min so other pipeline stages can proceed

POPULAR = [
    "github.com", "amazon.com", "wikipedia.org", "youtube.com", "microsoft.com",
    "apple.com", "reddit.com", "stackoverflow.com", "python.org", "netflix.com",
    "paypal.com", "booking.com", "chase.com", "ebay.com", "linkedin.com",
    "medium.com", "spotify.com", "dropbox.com", "zoom.us", "notion.so",
    "trello.com", "figma.com", "cloudflare.com", "facebook.com", "instagram.com",
    "wellsfargo.com", "citibank.com", "web.de", "girlscanplay.com", "mail.ru",
    "yandex.ru", "vkontakte.ru", "bestbuy.com", "target.com", "homedepot.com",
    "walmart.com", "etsy.com", "live.com", "office.com", "outlook.com",
]
# small set kept free of special chars; extended pages live in extra_targets generated below


def load_state():
    OUT.mkdir(parents=True, exist_ok=True)
    if STATE.exists():
        return json.loads(STATE.read_text())
    return {"done": {}, "requests": 0, "started": 0, "done_count": 0}


def save_state(st):
    STATE.write_text(json.dumps(st))


def urlfetch(url, timeout=35):
    req = urllib.request.Request(url, headers={"User-Agent": "phishing-url-detection-research/2.1 (contact: repo README)"})
    with urllib.request.urlopen(req, timeout=timeout) as r:
        return r.read().decode("utf-8", errors="replace")


def cc_pages(domain, limit=60):
    """Common Crawl CDX returns NDJSON lines: {'url','status','mime',...}"""
    out_lines = []
    for page in range(0, 3):     # 3 pages max / domain
        q = dict(url=f"*.{domain}/*", page=str(page), limit="20")
        y = CC + "?" + urllib.parse.urlencode(q)
        txt = urlfetch(y)
        if not txt.strip():
            break
        for line in txt.strip().splitlines():
            try:
                obj = json.loads(line)
            except Exception:
                continue
            if str(obj.get("status")) == "200" and str(obj.get("mime", "")).startswith("text/html"):
                out_lines.append(obj["url"])
        time.sleep(SLEEP)
    return out_lines


def wayback(domain, limit=60):
    q = dict(url=f"{domain}/*", output="json", limit=limit, fl="original",
             collapse="urlkey", filter="statuscode:200")
    y = WB + "?" + urllib.parse.urlencode(q)
    txt = urlfetch(y)
    if not txt.strip():
        return []
    lines = [l for l in txt.strip().splitlines() if l.strip()]
    try:
        arr = json.loads(txt)
        return [row[0] for row in arr[1:]]     # first row is header
    except Exception:
        return lines[:limit]


def main():
    st = load_state()
    st["requests"] = st.get("requests", 0)
    targets = POPULAR
    with CACHE.open("a") as cache:
        for dom in targets:
            t0 = time.time()
            if st["done"].get(dom):
                continue
            if st["requests"] >= MAX_REQUESTS:
                break
            if st.get("started", 0) == 0:
                st["started"] = round(time.time())
            elapsed = time.time() - st["started"]
            if elapsed > BUDGET_SECONDS:
                break
            got = []
            try:
                got = cc_pages(dom)
            except Exception:
                pass
            st["requests"] += 1
            if not got:
                try:
                    got = wayback(dom)
                    st["requests"] += 1
                except Exception:
                    pass
            for u in got:
                cache.write(json.dumps({"url": u, "domain": dom, "via": "cc_or_wayback",
                                        "fetched": "2026-11-05"}) + "\n")
            cache.flush()
            st["done"][dom] = {"n": len(got), "secs": round(time.time() - t0, 1)}
            st["done_count"] = st.get("done_count", 0) + 1
            save_state(st)
            print(f"{dom}: {len(got)} urls (req#{st['requests']})", flush=True)
    print(f"DONE  domains={st['done_count']}/{len(targets)} requests={st['requests']}", flush=True)


if __name__ == "__main__":
    main()
