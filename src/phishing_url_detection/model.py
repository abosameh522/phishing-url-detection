from pathlib import Path
import joblib, numpy as np
from .features import featurize, reasons
from .features import BRANDS, SUSPICIOUS, _parts
import ipaddress
class URLModel:
    def __init__(self,bundle): self.bundle=bundle
    def predict(self,url,mode='balanced'):
        c=self.bundle['canonicalize'](url); x=featurize([c]); p=float(self.bundle['model'].predict_proba(x)[0,1]);
        # Conservative, explainable guardrails for high-confidence lexical attacks.
        _, parts, host, ex, reg = _parts(c); low=c.lower(); strong=False
        try: ipaddress.ip_address(host); strong=True
        except ValueError: pass
        if 'xn--' in host or (any(b in low for b in BRANDS) and not any(b == ex.domain.lower() for b in BRANDS)): strong=True
        if any(k in low for k in SUSPICIOUS) and ex.domain.lower() not in BRANDS and (host.count('.')>=2 or len(c)>90): strong=True
        if strong: p=max(p,0.995)
        thresholds=self.bundle['thresholds']; t=float(thresholds.get(mode,thresholds['balanced'])); return {'probability':round(p,6),'class':'phishing' if p>=t else 'legitimate','mode':mode,'threshold':t,'canonical_url':c,'reasons':reasons(c),'model_version':self.bundle.get('version','2.0.0')}
def load(path='results/model_bundle.joblib'): return URLModel(joblib.load(path))
