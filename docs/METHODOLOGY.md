# Methodology

Cleaning keeps only benign/phishing rows, canonicalizes once, drops malformed or conflicting duplicates, and records a stable registrable domain. Development uses a domain-hash split (70/20/10 within the train pool); the serialized holdout is never used for tuning. The model uses lexical URL features computed without fitting. Thresholds are chosen on the validation slice for nominal 0.1%, 1%, and 5% FPR. Evaluation writes JSON before documentation is rendered.

This local run is intentionally conservative about claims: it has no page content, DNS, WHOIS, reputation, or liveness features and does not request any URL. Cross-source and Tranco evaluation remain required follow-up work because the requested external snapshots were not available in the workspace.
