from pathlib import Path
import json, sys, hashlib
import numpy as np, pandas as pd, joblib
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedGroupKFold
from sklearn.metrics import roc_auc_score, average_precision_score
sys.path.insert(0,'src')
from phishing_url_detection.features import featurize
from phishing_url_detection.canonical import canonicalize
D=pd.read_parquet('data/processed/urls_unified.parquet')
D=D[D.split_role=='train_pool'].reset_index(drop=True)
# deterministic domain split within development pool
h=D.registrable_domain.map(lambda x:int(hashlib.sha256(x.encode()).hexdigest()[:8],16)%10)
D['fold']=h
train=D[D.fold<7]; val=D[(D.fold>=7)&(D.fold<9)]; cal=D[D.fold==9]
X=featurize(train.url_canonical.tolist()); y=(train.label=='phishing').astype(int).to_numpy()
model=LogisticRegression(max_iter=250,C=0.7,class_weight='balanced',solver='lbfgs',random_state=42)
model.fit(X,y)
vp=model.predict_proba(featurize(val.url_canonical.tolist()))[:,1]; vy=(val.label=='phishing').astype(int).to_numpy()
# thresholds are selected on validation only; exact empirical FPR targets
order=np.argsort(vp)[::-1]; pos=vy.sum(); neg=max(1,(vy==0).sum())
def threshold_at(fpr):
 for t in np.unique(vp[order]):
  pred=vp>=t; rate=((pred==1)&(vy==0)).sum()/neg
  if rate<=fpr: return float(t)
 return 1.0
thresholds={'strict':threshold_at(.001),'balanced':threshold_at(.01),'sensitive':threshold_at(.05)}
# calibration slice is held out and reported; Platt is intentionally omitted for tiny lexical model
cp=model.predict_proba(featurize(cal.url_canonical.tolist()))[:,1]; cy=(cal.label=='phishing').astype(int).to_numpy()
bundle={'model':model,'thresholds':thresholds,'version':'2.0.0','feature_names':__import__('phishing_url_detection.features',fromlist=['feature_names']).feature_names(),'canonicalize':canonicalize}
Path('results').mkdir(exist_ok=True); joblib.dump(bundle,'results/model_bundle.joblib',compress=3)
metrics={'train_rows':len(train),'validation_rows':len(val),'calibration_rows':len(cal),'features':len(X[0]),'roc_auc_validation':float(roc_auc_score(vy,vp)),'average_precision_validation':float(average_precision_score(vy,vp)),'thresholds':thresholds,'protocol':'domain-hash development split; final holdout untouched'}
Path('results/model_metrics.json').write_text(json.dumps(metrics,indent=2))
print(json.dumps(metrics,indent=2))
