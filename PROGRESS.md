# Phishing URL Detection - Rebuild v2 Progress

- **Branch:** `rebuild/v2` (commit 1e5c205 at start)
- **Environment:** Arch/Omarchy, Python 3.12, uv, ~14 GB RAM, RTX 3050 Ti 4 GB
- **Rules:** no fabricated numbers; split by registrable domain; preprocessors fit on train only; never request/open/resolve URLs; no secrets; <=50 MB files in git; no force push; PhreshPhish CC BY 4.0; anti-phishing research only.

## Stage 0: Inventory - DONE

`logs/inventory.md` (2026-11-05). Key: PhreshPhish (56 train + 21 test shards, 975 benchmark files, projected cols only), Mendeley (MURL 783,705; PhishBD_2026 131,167; LegitPhish 101,219), Tranco JZPGY top-10k/1m, OpenPhish 300, Phishing.Database active.txt 789,054 lines complete, commoncrawl/collinfo.json present.

## Stage 1: Finish downloads - DONE

- **PhreshPhish**: train/test/benchmark already complete (prior run); verified 56/56 + 21/21 + 975 files; `html` never loaded.
- **ealvaradob/phishing-dataset**: NOT AVAILABLE — repo/URLs resolve 404 (documented in docs/DECISIONS.md D0, DOWNLOAD_COMMANDS.md).
- **PhiUSIIL**: NOT AVAILABLE — all guessed repo paths 404.
- **URL-Phish**: NOT AVAILABLE — all guessed repo paths 404.
- **Phishing.Database**: verified complete (789,054 URL strings; earlier curl timeout recovered).
- **Mendeley sets (MURL, PhishBD_2026, LegitPhish)**: all downloaded; label schemas verified (MURL: url+type incl. malware/defacement; PhishBD_2026: url+label 0/1; LegitPhish: URL+ClassLabel inverted 0=benign).
- **Common Crawl**: skipped for now (CDX reachable, CC-MAIN-2026-43 index exists; will be attempted in a later short stage if time permits — low priority for recall@1%FPR gain vs. cost).
- No URLs were requested/opened. All strings-only.

## Stage 2: Unified corpus - NEXT (build fresh from all present sources; write PROVENANCE.md, DATA_CARD.md, manifest.json, ARTIFACT_AUDIT.md)

## Stage 3: Models - pending
## Stage 4: Evaluation - pending
## Stage 5: Gates, docs, git - pending

## Follow-up command when ready:
uv run python scripts/ingest_external.py
