from __future__ import annotations
import math, re, ipaddress
from urllib.parse import urlsplit
import tldextract
import numpy as np
from .canonical import canonicalize
_TLD = tldextract.TLDExtract(suffix_list_urls=(), include_psl_private_domains=True)

BRANDS = ("paypal","apple","microsoft","google","amazon","facebook","instagram","linkedin","netflix","coinbase","bank","docusign","dropbox","office365","outlook","icloud","steam","github","binance")
SUSPICIOUS = ("login","verify","secure","account","update","signin","confirm","wallet","password","credential","billing","unlock","recover","authenticate","webscr")

def _parts(u):
    c=canonicalize(u); p=urlsplit(c if '://' in c else '//'+c); host=p.hostname or ''; ex=_TLD(host); reg='.'.join(x for x in (ex.domain,ex.suffix) if x); return c,p,host,ex,reg

def registrable_domain(u): return _parts(u)[4]
def tld_values(urls): return [(_parts(u)[3].suffix or 'unknown').lower() for u in urls]

def feature_names(): return ["url_length","host_length","path_length","query_length","num_dots","num_hyphens","num_digits","digit_ratio","special_ratio","entropy","subdomain_count","path_depth","param_count","has_ip","has_punycode","host_keyword_count","path_keyword_count","brand_host_count","brand_path_count","typo_brand_distance","host_digit_ratio","host_hyphen_density","has_at","percent_ratio","longest_alpha_run","vowel_consonant_ratio","class_transitions","is_shortener"]

def featurize_one(u):
    c,p,host,ex,reg=_parts(u); path=p.path or ''; query=p.query or ''; low=c.lower(); hostlow=host.lower();
    try: ipaddress.ip_address(host); has_ip=1
    except ValueError: has_ip=0
    chars=max(1,len(c)); letters=sum(ch.isalpha() for ch in c); digits=sum(ch.isdigit() for ch in c)
    counts={ch:c.count(ch) for ch in set(c)}; ent=-sum((n/chars)*math.log2(n/chars) for n in counts.values())
    alpha_host=sum(ch.isalpha() for ch in host); vowels=sum(ch in 'aeiou' for ch in hostlow); consonants=sum(ch.isalpha() and ch not in 'aeiou' for ch in hostlow)
    runs=[len(x) for x in re.findall(r'[A-Za-z]+',c)] or [0]
    transitions=sum(a.isalpha()!=b.isalpha() and a.isalnum() and b.isalnum() for a,b in zip(c,c[1:]))
    brand_host=sum(b in hostlow for b in BRANDS); brand_path=sum(b in (path+'?'+query).lower() for b in BRANDS)
    typo=min([min((sum(a!=b for a,b in zip(ex.domain.lower(),b2))+abs(len(ex.domain)-len(b2))), 20) for b2 in BRANDS if b2!=ex.domain.lower()] or [20])
    return np.array([len(c),len(host),len(path),len(query),c.count('.'),c.count('-'),digits,digits/chars,sum(not ch.isalnum() for ch in c)/chars,ent,max(0,len(ex.subdomain.split('.')) if ex.subdomain else 0),len([x for x in path.split('/') if x]),len([x for x in query.split('&') if x]),has_ip,int('xn--' in hostlow),sum(k in hostlow for k in SUSPICIOUS),sum(k in (path+' '+query).lower() for k in SUSPICIOUS),brand_host,brand_path,typo, sum(ch.isdigit() for ch in host)/max(1,len(host)),host.count('-')/max(1,len(host)),int('@' in p.netloc),sum(1 for ch in c if ch=='%')/chars,max(runs),vowels/max(1,consonants),transitions,int(ex.domain in ('bit.ly','tinyurl.com','t.co','goo.gl'))],dtype=np.float32)

def featurize(urls): return np.vstack([featurize_one(x) for x in urls]).astype(np.float32)

def reasons(u, model=None):
    """Deduce human-readable drivers of the score.

    Without a model: keyword/surface heuristics (legacy). With the stack bundle: include
    the top POSITIVE char-3/5 n-grams from the linear half (coef * tf-idf value) and note
    the inter-model agreement, so a phishing verdict always names what pushed it.
    """
    c, p, h, ex, r = _parts(u); text = (c).lower(); out = []
    if any(k in text for k in SUSPICIOUS): out.append("contains a credential or urgency keyword")
    if any(b in text and b != ex.domain.lower() for b in BRANDS): out.append("brand name appears outside its registrable domain")
    try:
        ipaddress.ip_address(h); out.append("uses a numeric IP host")
    except ValueError: pass
    if 'xn--' in h: out.append("uses punycode in the host")
    if h.count('-') >= 2: out.append("host has unusually many hyphens")
    if len(c) > 120: out.append("unusually long URL")
    if model is not None:
        try:
            X = model["tfidf"].transform([c.lower()])
            names = model["tfidf"].get_feature_names_out()
            coeff = model["lr"].coef_[0]
            contributions = coeff * X.toarray()[0]
            order = np.argsort(contributions)[::-1]
            top = [(str(names[i]), float(contributions[i])) for i in order
                   if contributions[i] > 0][:3]
            for gram, val in top:
                out.append(f"character pattern {gram!r} resembles known phishing URLs (contribution {val:.2f})")
        except Exception:
            pass
    return out[:5]
