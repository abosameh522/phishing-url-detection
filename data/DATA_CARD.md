# Data card

This run uses the local `malicious_phish.csv` snapshot only (510,639 unique canonical URLs after cleaning). Labels are the source's `benign` and `phishing` classes. Rows with unsupported labels, malformed hosts, control characters, overlong URLs, or conflicting duplicate labels are removed. No URL is requested or opened.

The requested million-row target was not padded: additional sources require separate verified downloads and are logged as skipped.
