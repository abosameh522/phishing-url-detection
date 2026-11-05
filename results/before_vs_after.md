# Before vs after (v1 vs v2)

Every number is read from `results/v1_rescore.json` and `results/v2_evaluation.json`;
no value is hand-written.

| slice | model | rows | recall@1%FPR | ROC-AUC | AP |
|---|---|---|---|---|---|
| eval_sealed | v1 (refit, same train pool) | 262602 | 0.0018813221968753692 | 0.6203481749373774 | 0.43980144747073874 |
| holdout | v1 (refit, same train pool) | 147316 | 0.5368183664607583 | 0.9381500086892265 | 0.9406779671467276 |
| eval_tranco | v1 (refit, same train pool) | 9487 | None | nan | 0.0 |
| validation | v1 (refit, same train pool) | 131452 | 0.6502238541566013 | 0.9691092453623638 | 0.9671364273808338 |
| eval_sealed | v2 | 262602 | 0.0001 | 0.5601 | 0.4046 |
| eval_fresh | v2 | 766316 | 0 | 0 | 0 |
| eval_tranco | v2 | 9487 | 0 | 0 | 0 |
| holdout | v2 | 147316 | 0.5855 | 0.9474 | 0.9494 |

## hard sanity fixtures
overall accuracy 0.798;
legitimate 0.995 / phishing 0.455 at threshold 0.9344631078840967.