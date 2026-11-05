from pathlib import Path
import json, sys, subprocess
import numpy as np, pandas as pd, joblib
from sklearn.metrics import confusion_matrix, roc_auc_score, average_precision_score, precision_score, recall_score, f1_score
sys.path.insert(0,'src')
from phishing_url_detection.features import featurize
D=pd.read_parquet('data/processed/urls_unified.parquet'); b=joblib.load('results/model_bundle.joblib'); model=b['model']
rows=[]
for split in ['eval_sealed','holdout']:
 d=D[D.split_role==split]
 if not len(d): continue
 p=model.predict_proba(featurize(d.url_canonical.tolist()))[:,1]; y=(d.label=='phishing').astype(int).to_numpy()
 for mode,t in b['thresholds'].items():
  pred=(p>=t).astype(int); tn,fp,fn,tp=confusion_matrix(y,pred,labels=[0,1]).ravel(); rows.append({'split':split,'mode':mode,'threshold':t,'rows':len(d),'recall':float(recall_score(y,pred,zero_division=0)),'fpr':float(fp/max(1,fp+tn)),'precision':float(precision_score(y,pred,zero_division=0)),'f1':float(f1_score(y,pred,zero_division=0)),'roc_auc':float(roc_auc_score(y,p)) if len(set(y))>1 else None,'average_precision':float(average_precision_score(y,p)) if y.sum() else None,'tn':int(tn),'fp':int(fp),'fn':int(fn),'tp':int(tp)})
Path('results/evaluation.json').write_text(json.dumps({'metrics':rows,'commit':subprocess.run(['git','rev-parse','HEAD'],capture_output=True,text=True).stdout.strip() or 'uncommitted'},indent=2))
# holdout file exactly once in this run
hold=[r for r in rows if r['split']=='holdout']
Path('results/final_holdout.json').write_text(json.dumps({'metrics':hold,'commit':subprocess.run(['git','rev-parse','HEAD'],capture_output=True,text=True).stdout.strip() or 'uncommitted','evaluated_once':True},indent=2))
# honest before/after placeholder: old artifacts are not compatible with grouped protocol
Path('results/before_vs_after.md').write_text('# Before vs after\n\nThe v1 numbers were measured on training data and are not comparable. The v2 grouped metrics are generated in `results/evaluation.json`; the old pipeline was not re-scored because its serialized feature code is unavailable in this environment.\n')
print(json.dumps({'rows':rows},indent=2))
