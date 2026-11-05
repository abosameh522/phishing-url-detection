# Progress

- Recon: complete. Existing notebook moved to `notebooks/legacy/`; old joblib files retained locally and ignored.
- Data: complete for the supplied local CSV. 510,639 canonical URLs kept; 422,602 benign and 88,037 phishing; 145,328 registrable domains. External sources skipped and logged.
- Model: complete. Domain-hash development split, lexical float32 features, thresholds in `results/model_metrics.json`.
- Evaluation: complete for local sealed/holdout slices; `results/evaluation.json` and `results/final_holdout.json`.
- API/UI: FastAPI in `src/phishing_url_detection/api.py`; Streamlit app in `app/streamlit_app.py`.
- Gates: G1, G2, G4, G5 pass locally; G3 is unavailable and therefore overall gates are failed mode.
- Next: run `make all`, inspect generated reports, commit and publish branch if GitHub authentication is available.
- Git: `rebuild/v2` pushed to `https://github.com/abosameh522/phishing-url-detection`; `main` was not touched because G3 is unavailable. `pre-rebuild-backup` tag points to the initial local snapshot commit.
