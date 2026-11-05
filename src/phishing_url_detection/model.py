from pathlib import Path
import joblib, numpy as np
from .features import featurize, reasons, tld_values
from .canonical import canonicalize

def _calibrate(p, cal):
    p=np.clip(np.asarray(p,dtype=float),1e-6,1-1e-6)
    z=np.log(p/(1-p)); a=float(cal.get('a',1.0)); b=float(cal.get('b',0.0))
    q=np.clip(a*z+b,-35,35)
    return 1/(1+np.exp(-q))
class URLModel:
    def __init__(self,bundle): self.bundle=bundle
    def predict(self,url,mode='balanced'):
        c=canonicalize(url); x=featurize([c]); model=self.bundle['model']
        if self.bundle.get('tld_encoder') is not None:
            t=self.bundle['tld_encoder'].transform(np.array(tld_values([c])).reshape(-1,1))
            from scipy.sparse import csr_matrix, hstack
            x=hstack([csr_matrix(x),t],format='csr')
        raw=float(model.predict_proba(x)[0,1]); p=float(_calibrate([raw],self.bundle.get('calibration',{}))[0])
        thresholds=self.bundle['thresholds']; t=float(thresholds.get(mode,thresholds['balanced']))
        return {'probability':round(p,6),'class':'phishing' if p>=t else 'legitimate','mode':mode,'threshold':t,'canonical_url':c,'reasons':reasons(c),'model_version':self.bundle.get('version','2.0.0')}
def load(path='results/model_bundle.joblib'): return URLModel(joblib.load(path))
