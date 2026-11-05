# Provenance — unified corpus

Rendered by `scripts/render_data_docs.py` from `data/processed/manifest.json`
(created 2026-11-05T02:47:37.340964+00:00). Everything below is reproducible from the two files.

- rows kept: 2,012,875
- benign / phishing: 654,874 / 1,358,001
- registrable domains: 917,633
- kept per source: {"malicious_phish.csv": 522214, "PhreshPhish train": 498255, "PhreshPhish test": 168060, "MURL": 783702, "PhishBD_2026": 131167, "LegitPhish": 100873, "Tranco JZPGY top10k": 10000, "OpenPhish": 300, "Phishing.Database": 789054, "conflicting_urls_removed": 6080}
- drops: {"malicious_phish.csv:unparseable": 1296, "PhreshPhish train:unparseable": 351, "PhreshPhish test:unparseable": 1065, "MURL:unparseable": 2854, "PhishBD_2026:unparseable": 82, "Phishing.Database:unparseable": 5147, "training_rows_removed_for_eval_domain_overlap": 594918}
- conflicting_url removals: 6,080
- eval_overlap removals from train: 594,918
- split counts: {"eval_fresh": 766316, "train_dev": 581177, "eval_sealed": 262602, "holdout": 147316, "validation": 131452, "calibration": 114525, "eval_tranco": 9487}
- PhreshPhish benchmark hash matching: {"benchmark-005": {"hashes": 26370, "matched_to_test_urls": 25919, "base_rate_label": "005"}, "benchmark-010": {"hashes": 26640, "matched_to_test_urls": 26188, "base_rate_label": "010"}, "benchmark-050": {"hashes": 26727, "matched_to_test_urls": 26275, "base_rate_label": "050"}, "benchmark-100": {"hashes": 26419, "matched_to_test_urls": 25968, "base_rate_label": "100"}, "benchmark-500": {"hashes": 23755, "matched_to_test_urls": 23359, "base_rate_label": "500"}}
- tranco: id=JZPGY created=2026-11-04
- no_url_requests: True
- phresh_columns_read: ['url', 'label', 'target', 'date', 'lang']
- phresh_html_loaded: False
