import pandas as pd
from phishing_url_detection.canonical import canonicalize
from phishing_url_detection.model import load

def test_canonical_format_invariance():
    variants=['https://www.google.com/','http://google.com','www.google.com','google.com/']
    assert len({canonicalize(x) for x in variants})==1

def test_domain_groups_are_disjoint():
    d=pd.read_parquet('data/processed/urls_unified.parquet')
    sets={s:set(d.loc[d.split_role==s,'registrable_domain']) for s in ['train_pool','eval_sealed','holdout']}
    assert not sets['train_pool'] & sets['eval_sealed']
    assert not sets['train_pool'] & sets['holdout']
    assert not sets['eval_sealed'] & sets['holdout']

def test_sanity_examples():
    p=load()
    assert p.predict('https://www.google.com/')['class']=='legitimate'
    assert p.predict('paypal.com.account-verify.example-secure.top/login')['class']=='phishing'
