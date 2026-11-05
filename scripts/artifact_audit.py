"""Quantify surface-only artifacts and write source-balanced train weights."""
from pathlib import Path
import json,sys
import numpy as np,pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import roc_auc_score
sys.path.insert(0,'src')
from phishing_url_detection.canonical import raw_flags
D=pd.read_parquet('data/processed/urls_unified.parquet')
D['y']=(D.label=='phishing').astype(int)
D['has_path']=D.url_canonical.str.split('/',n=1).str.len().gt(1).astype(int)
D['has_query']=D.url_canonical.str.contains('?',regex=False).astype(int)
D['path_chars']=D.url_canonical.str.extract(r'^[^/]+(/[^?]*)',expand=False).fillna('').str.len()
D['length_bucket']=pd.cut(D.url_canonical.str.len(),[-1,30,60,100,200,2048],labels=['0-30','31-60','61-100','101-200','201+']).astype(str)
D['path_bucket']=pd.cut(D.path_chars,[-1,0,10,30,80,2048],labels=['none','1-10','11-30','31-80','81+']).astype(str)
cols=['source','has_path','path_bucket','length_bucket','has_scheme_raw','has_www_raw','has_trailing_slash_raw','has_query']
train=D[D.split_role.isin(['train_dev','validation','calibration'])].copy()
# stable grouped train/eval split for the artifact-only diagnostic
h=train.registrable_domain.map(lambda x:int(__import__('hashlib').sha256(x.encode()).hexdigest()[:8],16)%5)
a=train[h<4]; b=train[h==4]
def design(frame): return pd.get_dummies(frame[cols].astype(str),dtype=np.float32)
def auc_fit(train_df,test_df,weights=None):
 X=design(train_df); Z=design(test_df).reindex(columns=X.columns,fill_value=0)
 m=LogisticRegression(max_iter=300,class_weight=None,n_jobs=1)
 m.fit(X,train_df.y,sample_weight=weights)
 return roc_auc_score(test_df.y,m.predict_proba(Z)[:,1])
auc_before=auc_fit(a,b)
# Reweight only training roles to match the pooled conditional distribution of surface strata across classes.
train['stratum']=train[cols].astype(str).agg('|'.join,axis=1)
ct=pd.crosstab(train.stratum,train.y)
common=ct.index[(ct.get(0,0)>0)&(ct.get(1,0)>0)]
ct=ct.loc[common]
if len(common):
 probs=ct.div(ct.sum(axis=0),axis=1)
 target=probs.mean(axis=1)
 weights=np.ones(len(train),dtype=np.float32)
 for i,(s,y) in enumerate(zip(train.stratum,train.y)):
  if s not in target.index: weights[i]=0.0
  else: weights[i]=float(target[s]/probs.loc[s,y])
 weights/=max(1e-9,float(weights[weights>0].mean()))
else: weights=np.ones(len(train),dtype=np.float32)
# Store weights by stable canonical URL key. Eval-only rows retain weight 1.
lookup=dict(zip(train.url_canonical,weights))
D['sample_weight']=D.url_canonical.map(lookup).fillna(1.0).astype('float32')
D.to_parquet('data/processed/urls_unified.parquet',index=False)
train=D[D.split_role.isin(['train_dev','validation','calibration'])].copy(); h=train.registrable_domain.map(lambda x:int(__import__('hashlib').sha256(x.encode()).hexdigest()[:8],16)%5); a=train[h<4]; b=train[h==4]
auc_after=auc_fit(a,b,weights=a.sample_weight.to_numpy()) if len(b) else None
# per-source/class cue report
summary=[]
for (src,y),g in D.groupby(['source','y']):
 summary.append({'source':src,'label':'phishing' if y else 'benign','rows':len(g),'scheme_share':float(g.has_scheme_raw.mean()),'www_share':float(g.has_www_raw.mean()),'trailing_slash_share':float(g.has_trailing_slash_raw.mean()),'path_share':float(g.has_path.mean()),'query_share':float(g.has_query.mean()),'mean_path_chars':float(g.path_chars.mean()),'mean_sample_weight':float(g.sample_weight.mean())})
# Within-source grouped surface AUC; ignore sources without both labels.
per_source={}
for src,g in train.groupby('source'):
 if g.y.nunique()<2: per_source[src]=None; continue
 hh=g.registrable_domain.map(lambda x:int(__import__('hashlib').sha256(x.encode()).hexdigest()[:8],16)%5); tr=g[hh<4]; te=g[hh==4]
 try: per_source[src]={'before':auc_fit(tr,te),'after':auc_fit(tr,te,weights=tr.sample_weight.to_numpy())}
 except Exception: per_source[src]=None
Path('data/ARTIFACT_AUDIT.md').write_text('# Artifact audit\n\nThe classifier below uses only source identity and URL formatting/path length cues, not the phishing model features. Holdout rows were selected by a stable registrable-domain hash.\n\nPooled grouped surface-only AUC before reweighting: **'+f'{auc_before:.4f}'+'**. After stratum reweighting: **'+f'{auc_after:.4f}'+'**. Pooled target: <= 0.60. Weights are stored in `sample_weight` in the unified parquet; data rows are not duplicated.\n\nPer-source grouped AUC: `'+json.dumps(per_source,sort_keys=True)+'`\n\nPer-source/class cue rates (CSV):\n\n```csv\n'+pd.DataFrame(summary).to_csv(index=False)+'```\n')
Path('data/spot_check.csv').write_text(D.sample(min(300,len(D)),random_state=42)[['source','label','url_raw']].to_csv(index=False))
Path('results/artifact_audit.json').write_text(json.dumps({'pooled_auc_before':auc_before,'pooled_auc_after':auc_after,'per_source_auc':per_source,'common_strata':len(common),'weight_min':float(D.sample_weight.min()),'weight_max':float(D.sample_weight.max())},indent=2))
print(json.dumps({'auc_before':auc_before,'auc_after':auc_after,'per_source_auc':per_source,'common_strata':len(common),'weights':[float(x) for x in np.quantile(D.sample_weight,[0,.5,.95,1])]},indent=2))

# ---------- machine-readable summary for gates.py ----------
Path('data/artifact_audit.json').write_text(json.dumps({
    'pooled_surface_auc_before': float(auc_before),
    'pooled_surface_auc_after': (float(auc_after) if auc_after is not None else None),
    'surface_band_target': [0.45, 0.60],
    'in_band': bool(auc_after is not None and 0.45 <= float(auc_after) <= 0.60),
    'per_source': per_source,
}, indent=2))
