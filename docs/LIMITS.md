# LIMITS — v2 model, measured and honest (all numbers from results/*.json)

## Where the model works

- Holdout (147,561 rows, grouped by domain, touched once): ROC-AUC **0.9458** (CI 0.941–0.952),
  recall@1%FPR **0.5622** (CI 0.564 window in `results/final_holdout.json`), recall@5%FPR 0.7473.
- Sealed cross-source slice (PhreshPhish test + LegitPhish, never seen in training): ROC-AUC **0.9627**,
  recall@1%FPR **0.7069** (v1 refit under the same protocol: 0.6765).
- Tranco top-10k homepages: **0.15% flagged** at the balanced threshold (v1 refit flags ~25%).

## Known weaknesses (top 3, with evidence)

1. **Out-of-distribution benign platforms get flagged.** The benign side of the corpus is thin on
   popular platforms with paths/queries (only 13 benign amazon URLs exist in the whole calibration
   slice). `https://www.amazon.com/s?k=books` scores 0.975 (phishing). Consequence: G1 easy-fixture
   legitimate accuracy is 0.786 at balanced / 0.5 at sensitive (spec bar 0.95). Fix requires
   broadening benign coverage with real platform URLs — new data collection, not a code fix.
   Common Crawl CDX (for this exact gap) is documented in `DOWNLOAD_COMMANDS.md`.
2. **Synthetic/private-ip phishing strings score mid-range.** `10.0.0.1/bank/login` (0.580) and
   `http://192.0.2.10/login/paypal` (0.802) fall below the balanced cut (0.9366) although the same
   model puts real corpus IP-host phishing at ~0.995: the char-3-5 TF-IDF linear half reads the
   RFC-1918 octets as ordinary benign numerics when the rest of the string matches no known
   attack pattern. Corpus IP-host phishing rows (1,479/1,480 in calibration) are scored correctly,
   so the failure is specific to strings whose every char n-gram is "new".
3. **Threshold conservatism costs recall.** Balanced threshold 0.9366 was chosen as the 99th
   percentile of calibration-half-B benign scores; its realized FPR is 0.02% on sealed / 0.05% on
   holdout (far under the nominal 1%), and holdout recall at the fixed threshold is 0.28 vs
   0.56 at the true 1%-FPR operating point. All three thresholds (strict 0.9864 / balanced
   0.9366 / sensitive 0.7678) err on the safe side; a consumer wanting the true 1%-FPR cut
   should use `predict_proba` directly (API returns the calibrated probability).

## Other limits

- Lexical/URL-only by design; no page content, DNS, WHOIS, reputation or liveness.
- `eval_fresh` (OpenPhish + Phishing.Database feeds) is phishing-only: 19.8% flagged at balanced —
  feed URLs are heavily obfuscated and cheap-to-classify strategies miss the remainder.
- Char-CNN skipped (torch unavailable, docs/DECISIONS.md D9).
- Sources not obtained: ealvaradob/phishing-dataset, PhiUSIIL, URL-Phish, Common Crawl CDX —
  documented in `DOWNLOAD_COMMANDS.md` with retry commands; nothing was fabricated.
- PhreshPhish benchmark hash lists are sealed evaluation-only (docs/DECISIONS.md D11).
- Easy sanity fixtures (G1) fail at all declared modes; the diagnosis above explains why: it is an
  OOD-coverage issue, not a pipeline defect. Hard fixtures are better already: legitimate 0.995 /
  phishing 0.42 at balanced (results/hard_sanity_results.json); the phishing side suffers from
  the same brand-vs-generic string gap as weakness 2.

## Gate status at time of writing (results/gates.json)

- G2 format invariance: PASS (8 variants -> 1 canonical form)
- G3 real-world: PASS (Tranco 0.0015 ≤ 0.02; sealed recall@1%FPR v2 0.7069 > v1 0.6765)
- G4 no train/eval domain leakage: PASS (0 overlapping registrable domains)
- G5 reproducibility: PASS (training + evaluation artifacts carry a commit hash)
- G1 easy sanity: FAIL (documented above) — as a result, `main` is intentionally not updated.
