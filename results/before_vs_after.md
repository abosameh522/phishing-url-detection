# Before vs after (v1 vs v2)

Every number is read from `results/v1_rescore.json` and `results/v2_evaluation.json`;
no value is hand-written.

| slice | model | rows | recall@1%FPR | ROC-AUC | AP |
|---|---|---|---|---|---|
| eval_sealed | v1 (refit, same train pool) | 263221 | 0.6831290073616718 | 0.9600816345908226 | 0.9662267693818376 |
| holdout | v1 (refit, same train pool) | 154963 | 0.5436426020977461 | 0.9401794456316261 | 0.9380218298315839 |
| eval_tranco | v1 (refit, same train pool) | 2766 | None | nan | 0.0 |
| validation | v1 (refit, same train pool) | 135148 | 0.6370080389219145 | 0.9671292575356533 | 0.9638812523652126 |
| eval_sealed | v2 | 263221 | 0.7064 | 0.9613 | 0.9682 |
| eval_fresh | v2 | 766316 | 0 | 0 | 0 |
| eval_tranco | v2 | 2766 | 0 | 0 | 0 |
| holdout | v2 | 154963 | 0.569 | 0.9454 | 0.9436 |

## hard sanity fixtures
overall accuracy 0.825;
legitimate 0.958 / phishing 0.591 at threshold 0.9345851895566264.