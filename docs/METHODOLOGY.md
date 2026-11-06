# Methodology

The pipeline canonicalizes URL strings, removes malformed records and conflicting labels, and assigns all rows for a registrable domain to one split role. The current corpus contains multiple source families; source disagreement and label quality remain limitations.

Training compares grouped out-of-fold LightGBM and character 3–5-gram TF-IDF linear models. It uses a fingerprinted cache keyed to the exact training data, compares blend variants, selects the blend on validation, calibrates on one half of the calibration slice, and selects operating thresholds on the other half. The holdout is not used for model or threshold selection and is evaluated once.

Evaluation and serving both canonicalize first, apply the same model blend and calibration, and compare against the same stored thresholds. The output is called a risk score because the labeled corpus prevalence does not represent deployment prevalence. Calibration diagnostics are descriptive of this dataset only.

The detector uses URL-string features only. It never opens, resolves, or downloads a submitted URL. Independent data with verified labels and greater benign coverage of current platforms is required for stronger real-world claims.
