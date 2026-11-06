import pandas as pd
from phishing_url_detection.canonical import canonicalize

def test_canonical_format_invariance():
    variants=['https://www.google.com/','http://google.com','www.google.com','www2.google.com',
              'google.com/','http://google.com:80/','https://google.com?']
    assert len({canonicalize(x) for x in variants})==1

def test_eval_roles_are_disjoint_from_training_roles():
    d=pd.read_parquet('data/processed/urls_unified.parquet', columns=['split_role','registrable_domain'])
    train=d.loc[d.split_role.isin(['train_dev','validation','calibration','holdout']),'registrable_domain']
    evals=d.loc[d.split_role.isin(['eval_sealed','eval_fresh','eval_tranco']),'registrable_domain']
    assert not set(train) & set(evals)

def test_no_duplicate_canonical_urls():
    d=pd.read_parquet('data/processed/urls_unified.parquet', columns=['url_canonical'])
    assert not d.duplicated().any()

def test_sanity_examples():
    from phishing_url_detection.model import load
    p=load()
    assert p.predict('https://www.google.com/')['class']=='legitimate'
    assert p.predict('paypal.com.account-verify.example-secure.top/login')['class']=='phishing'


def _platt(raw, a, b):
    import numpy as np
    raw = np.clip(raw, 1e-6, 1 - 1e-6)
    z = np.log(raw / (1 - raw))
    return 1 / (1 + np.exp(-(a * z + b)))

def _eval_score_batch_fn():
    """Build score_batch exactly as scripts/evaluate_v2.py defines it (exec only that
    function's source), so the test cannot silently diverge from the eval path."""
    import ast, numpy as np, sys
    sys.path.insert(0, "src")
    from phishing_url_detection.features import featurize
    from phishing_url_detection.canonical import canonicalize
    src = ast.parse(open("scripts/evaluate_v2.py").read())
    fn = next(n for n in ast.walk(src)
              if isinstance(n, ast.FunctionDef) and n.name == "score_batch")
    ns = {"featurize": featurize, "canonicalize": canonicalize, "np": np}
    exec(compile(ast.Module(body=[ast.fix_missing_locations(fn)], type_ignores=[]),
                 "<score_batch>", "exec"), ns)
    return ns["score_batch"]


def test_serve_eval_parity_within_1e6():
    """API predictor probability must equal Platt(eval score_batch raw) on the same
    canonical form. Regression test for the v3 root cause (results/serve_eval_parity.json):
    evaluate_v2 used to compare bundle thresholds against the RAW blend."""
    import joblib, numpy as np
    from pathlib import Path
    bundle_p = Path('results/model_bundle.joblib')
    parquet_p = Path('data/processed/urls_unified.parquet')
    if not (bundle_p.exists() and parquet_p.exists()):
        import pytest
        pytest.skip('artifacts missing')
    b = joblib.load(bundle_p)
    cal = b.get("calibration") or {}
    a, bb = float(cal.get("a", 1.0)), float(cal.get("b", 0.0))
    from phishing_url_detection.model import load
    p = load()
    score_batch = _eval_score_batch_fn()

    probe = [r["url"] for r in pd.read_csv("tests/live_probe_urls.csv").to_dict("records")][:12] \
        if Path("tests/live_probe_urls.csv").exists() else []
    D = pd.read_parquet(parquet_p, columns=["url_canonical", "split_role"])
    pool = D.loc[D.split_role.isin(["eval_tranco", "eval_fresh"]), "url_canonical"]
    sample = list(probe) + pool.drop_duplicates().sample(20, random_state=42).tolist()

    api_p = np.array([p.predict(u)["risk_score"] for u in sample])
    eval_p = np.asarray(score_batch(b, sample))
    assert np.abs(api_p - eval_p).max() <= 1e-6


def test_invalid_mode_falls_back_to_balanced_and_output_is_explicit():
    from phishing_url_detection.model import load
    predictor = load()
    normal = predictor.predict('example.com', mode='balanced')
    invalid = predictor.predict('example.com', mode='typo')
    assert invalid['mode'] == 'balanced'
    assert invalid['risk_score'] == normal['risk_score']
    assert 'not a real-world probability' in invalid['score_type']
    assert invalid['class'] == normal['class']
    assert invalid['disclaimer']
    assert invalid['reasons']


def test_eval_score_canonicalizes_before_scoring():
    import joblib
    from pathlib import Path
    bundle_p = Path('results/model_bundle.joblib')
    if not bundle_p.exists():
        import pytest
        pytest.skip('model bundle missing')
    b = joblib.load(bundle_p)
    score_batch = _eval_score_batch_fn()
    p = score_batch(b, ['https://www.google.com/', 'google.com'])
    assert abs(float(p[0]) - float(p[1])) <= 1e-6
