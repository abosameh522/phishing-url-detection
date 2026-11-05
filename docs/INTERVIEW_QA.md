# Interview Q&A

1. **Why group by domain?** URLs from one site are correlated; grouping prevents memorizing hosts.
2. **What was the v1 failure?** Formatting and collection artifacts, especially `www.` and explicit schemes.
3. **Why canonicalize?** Equivalent user inputs must produce one representation and one score.
4. **What is leakage?** Fitting transforms or thresholds on final evaluation data.
5. **How is the holdout used?** Once, after decisions are frozen.
6. **Why report recall at fixed FPR?** Operations usually constrain false alarms.
7. **Why 1%?** Five percent creates too many legitimate interruptions; 5% remains comparison-only.
8. **What does calibration mean?** A probability should approximate observed frequency.
9. **Why no HTML fetching?** It is unsafe and violates the string-only evaluation rule.
10. **Why lexical features?** They are fast, explainable, and safe for an API.
11. **What are the limits?** New domains and adversarially crafted URLs can evade lexical rules.
12. **What is a registrable domain?** The effective second-level domain under the public suffix list.
13. **Why drop conflicting duplicates?** A contradictory label cannot be resolved without provenance.
14. **How are thresholds selected?** On validation predictions only.
15. **Why keep a calibration slice?** It separates probability assessment from threshold selection.
16. **What is class imbalance handling?** Balanced class weights during logistic fitting.
17. **What does the API return?** Probability, class, threshold, canonical URL, reasons, and model version.
18. **Why a guardrail?** Obvious IP, punycode, and brand-impersonation patterns need a transparent safety floor.
19. **Does the model resolve DNS?** No.
20. **Can it detect a compromised legitimate site?** Not reliably from URL text alone.
21. **Why no Tranco rank feature?** It leaks reputation and changes over time.
22. **What is cross-source evaluation?** Train on one source family and test on another.
23. **Why is G3 unavailable here?** A pinned Tranco snapshot and external phishing test were not present.
24. **How is reproducibility enforced?** `uv.lock`, fixed seeds, scripts, and generated JSON metrics.
25. **What is the ethical use?** Anti-phishing research and defensive triage only.
26. **How would you improve it?** Add verified diverse sources, time splits, calibration, and monitored drift.
