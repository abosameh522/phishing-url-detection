# Decisions

- Reused the existing project directory and moved `ML_Project.ipynb` to `notebooks/legacy/` unchanged. The extra Downloads notebook was copied as legacy because it was outside the repo.
- Used the supplied CSV as a development source. External sources were not silently fabricated or fetched; the manifest records them as skipped, with licences and the reason in `data/PROVENANCE.md`.
- Canonical URLs are scheme-less (`host/path?query`), lowercase scheme/host, remove leading `www` variants, default ports and fragments, and preserve path/query.
- A SHA-256 registrable-domain hash assigns stable split roles. The holdout is never used to select model parameters.
- The shipped model is a float32 lexical logistic regression plus transparent high-confidence lexical guardrails for IP hosts, punycode, and brand impersonation. Guardrails are part of inference behavior and are reported as a limitation.
- Gate G3 cannot be claimed because no Tranco snapshot is present. The project remains in failed-gates mode until external datasets are added and cross-source metrics are measured.
