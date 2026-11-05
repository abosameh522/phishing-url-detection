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
