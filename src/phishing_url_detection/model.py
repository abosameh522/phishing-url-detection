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
    def _raw(self,c,x):
        b=self.bundle
        if b.get('kind')=='stack':
            p_lgbm=float(b['lgbm'].predict_proba(x)[0,1])
            p_lin=float(b['lr'].predict_proba(b['tfidf'].transform([c.lower()]))[0,1])
            w=float(b.get('w_text',0.5))
            return w*p_lin+(1.0-w)*p_lgbm
        model=b['model']
        if b.get('tld_encoder') is not None:
            t=b['tld_encoder'].transform(np.array(tld_values([c])).reshape(-1,1))
            from scipy.sparse import csr_matrix, hstack
            x=hstack([csr_matrix(x),t],format='csr')
        return float(model.predict_proba(x)[0,1])
    def predict(self,url,mode='balanced'):
        c=canonicalize(url); x=featurize([c])
        raw=float(self._raw(c,x))
        p=float(_calibrate([raw],self.bundle.get('calibration',{}))[0])
        thresholds=self.bundle['thresholds']; t=float(thresholds.get(mode,thresholds['balanced']))
        rs=reasons(c,self.bundle)
        if p>=t:
            rs=[r for r in rs if 'no strong lexical warning signal' not in r]
            if not rs:
                rs=[f"stacked model probability {p:.3f} exceeds the {mode} threshold {t:.3f}"]
        return {'probability':round(p,6),'class':'phishing' if p>=t else 'legitimate','mode':mode,'threshold':t,'canonical_url':c,'reasons':rs,'model_version':self.bundle.get('version','2.0.0')}

def load(path='results/model_bundle.joblib'): return URLModel(joblib.load(path))
