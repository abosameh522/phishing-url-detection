# Provenance — unified corpus

Rendered by `scripts/render_data_docs.py` from `data/processed/manifest.json`
(created 2026-11-05T16:34:43.510783+00:00). Everything below is reproducible from the two files.

- rows kept: 2,044,164
- benign / phishing: 656,858 / 1,387,306
- registrable domains: 918,238
- kept per source: {"malicious_phish.csv": 522214, "PhreshPhish train": 498255, "PhreshPhish test": 168060, "MURL": 783702, "PhishBD_2026": 131167, "LegitPhish": 100873, "Tranco JZPGY top10k": 10000, "Tranco partition A (train)": 7094, "Tranco partition B (sealed eval)": 2906, "Common Crawl CDX": 1957, "OpenPhish": 300, "Phishing.Database": 789054, "conflicting_urls_removed": 5461}
- drops: {"malicious_phish.csv:unparseable": 1296, "PhreshPhish train:unparseable": 351, "PhreshPhish test:unparseable": 1065, "MURL:unparseable": 2854, "PhishBD_2026:unparseable": 82, "Common Crawl CDX:unparseable": 103, "Phishing.Database:unparseable": 5147, "training_rows_removed_for_eval_domain_overlap": 566102}
- conflicting_url removals: 5,461
- eval_overlap removals from train: 566,102
- split counts: {"eval_fresh": 766316, "train_dev": 604371, "eval_sealed": 263221, "holdout": 154963, "validation": 135148, "calibration": 117379, "eval_tranco": 2766}
- PhreshPhish benchmark hash matching: {"benchmark-005": {"hashes": 26370, "matched_to_test_urls": 25918, "base_rate_label": "005"}, "benchmark-010": {"hashes": 26640, "matched_to_test_urls": 26187, "base_rate_label": "010"}, "benchmark-050": {"hashes": 26727, "matched_to_test_urls": 26274, "base_rate_label": "050"}, "benchmark-100": {"hashes": 26419, "matched_to_test_urls": 25967, "base_rate_label": "100"}, "benchmark-500": {"hashes": 23755, "matched_to_test_urls": 23358, "base_rate_label": "500"}}
- tranco: id=JZPGY created=2026-11-04
- no_url_requests: True
- phresh_columns_read: ['url', 'label', 'target', 'date', 'lang']
- phresh_html_loaded: False
