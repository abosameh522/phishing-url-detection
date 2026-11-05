# Before vs after (v1 vs v2)

Every number is read from `results/v1_rescore.json` and `results/v2_evaluation.json`;
no value is hand-written.

| slice | model | rows | recall@1%FPR | ROC-AUC | AP |
|---|---|---|---|---|---|
| eval_sealed | v1 (refit, same train pool) | 263221 | 0.6765465447637141 | 0.9594228801877105 | 0.9657282239015272 |
| holdout | v1 (refit, same train pool) | 147561 | 0.5364829102314574 | 0.9363675009883016 | 0.9386413629595455 |
| eval_tranco | v1 (refit, same train pool) | 9487 | None | nan | 0.0 |
| validation | v1 (refit, same train pool) | 131135 | 0.6410417776056543 | 0.9669374639986213 | 0.9652493896074698 |
| eval_sealed | v2 | 263221 | 0.7069 | 0.9627 | 0.9691 |
| eval_fresh | v2 | 766316 | 0 | 0 | 0 |
| eval_tranco | v2 | 9487 | 0 | 0 | 0 |
| holdout | v2 | 147561 | 0.5622 | 0.9458 | 0.9474 |

## hard sanity fixtures
overall accuracy 0.785;
legitimate 0.995 / phishing 0.418 at threshold 0.9366320303489568.