# Model limits and measured results

This model is a URL-string triage tool. It does not inspect page content, resolve DNS, verify domain ownership, or query reputation services. A low score cannot establish that a link is safe.

## Current retrain

- Training uses 604,371 domain-grouped `train_dev` rows. Blend selection uses 135,148 validation rows; calibration and threshold selection use a separate 117,379-row slice. The final holdout is domain-grouped and was scored once.
- Holdout: 154,963 URLs / 68,081 registrable domains; ROC-AUC 0.9454 (95% bucket-bootstrap CI 0.9388–0.9506), average precision 0.9436, recall 0.5690 at 1% FPR and 0.7492 at 5% FPR.
- Sealed cross-source evaluation: recall 0.7064 at 1% FPR and ROC-AUC 0.9613. Tranco-only benign evaluation has 1.16% flagged at the balanced threshold.
- Frozen live probe: 92.5% of 80 legitimate URLs classified legitimate; this misses the 95% gate. Six popular legitimate URLs were flagged. Phishing recall on 30 synthetic probe strings is 80% and is informational only.
- Calibration-slice ECE (10 quantile bins) is 0.0051 on half A and 0.0112 on half B. This describes fit to the corpus mix only. The corpus does not represent real-world phishing prevalence, so the API reports a **risk score**, not a real-world probability.
- The surface-cue diagnostic remains outside its declared range (AUC 0.279). This signals source/label artifacts and should not be presented as evidence of robust generalization.

## Known failure patterns

1. **Unseen legitimate brands and hosted platforms can look malicious.** The frozen probe flags Microsoft, Netflix, LinkedIn, Dropbox, Instagram, and a Google Docs URL. New benign platform coverage from independently sourced, verified snapshots is needed. These frozen probes were not used for training or threshold selection.
2. **Some phishing strings are missed.** The hard-sanity phishing subset is detected at 59.1% at the balanced threshold. Generic or private-IP attacks with unseen character patterns remain difficult for a lexical model.
3. **Source-family shift is large.** OOF recall at 1% FPR ranges from 11.2% on kaggle-like phishing rows to 44.7% on PhreshPhish rows. One pooled metric hides this variation.
4. **Thresholds are corpus operating points.** `strict`, `balanced`, and `sensitive` were selected to target 0.1%, 1%, and 5% FPR on a calibration subset. They cannot guarantee those rates in a new deployment population.

## Gate status

G2 canonicalization, G3 held-out comparison/Tranco flagged share, G4 domain separation, and G5 artifact checks pass. G1 fixture accuracy and G6 live legitimate probe fail; therefore `all_passed` is false. The model is suitable for research or defensive triage with human review, not unattended blocking or a safety guarantee.
