# Provenance — unified corpus

Rendered by `scripts/render_data_docs.py` from `data/processed/manifest.json`
(created 2026-11-05T03:13:07.271485+00:00). Everything below is reproducible from the two files.

- rows kept: 2,013,066
- benign / phishing: 630,796 / 1,382,270
- registrable domains: 918,237
- kept per source: {"malicious_phish.csv": 522214, "PhreshPhish train": 498255, "PhreshPhish test": 168060, "MURL": 783702, "PhishBD_2026": 131167, "LegitPhish": 100873, "Tranco JZPGY top10k": 10000, "OpenPhish": 300, "Phishing.Database": 789054, "conflicting_urls_removed": 5461}
- drops: {"malicious_phish.csv:unparseable": 1296, "PhreshPhish train:unparseable": 351, "PhreshPhish test:unparseable": 1065, "MURL:unparseable": 2854, "PhishBD_2026:unparseable": 82, "Phishing.Database:unparseable": 5147, "training_rows_removed_for_eval_domain_overlap": 595346}
- conflicting_url removals: 5,461
- eval_overlap removals from train: 595,346
- split counts: {"eval_fresh": 766316, "train_dev": 580772, "eval_sealed": 263221, "holdout": 147561, "validation": 131135, "calibration": 114574, "eval_tranco": 9487}
- PhreshPhish benchmark hash matching: {"benchmark-005": {"hashes": 26370, "matched_to_test_urls": 25918, "base_rate_label": "005"}, "benchmark-010": {"hashes": 26640, "matched_to_test_urls": 26187, "base_rate_label": "010"}, "benchmark-050": {"hashes": 26727, "matched_to_test_urls": 26274, "base_rate_label": "050"}, "benchmark-100": {"hashes": 26419, "matched_to_test_urls": 25967, "base_rate_label": "100"}, "benchmark-500": {"hashes": 23755, "matched_to_test_urls": 23358, "base_rate_label": "500"}}
- tranco: id=JZPGY created=2026-11-04
- no_url_requests: True
- phresh_columns_read: ['url', 'label', 'target', 'date', 'lang']
- phresh_html_loaded: False
