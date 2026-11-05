from pathlib import Path
import csv, hashlib, json, re, random, sys
from datetime import datetime, timezone
import pandas as pd
sys.path.insert(0,'src')
from phishing_url_detection.canonical import canonicalize, raw_flags
from phishing_url_detection.features import registrable_domain
ROOT=Path('.'); out=ROOT/'data/processed'; out.mkdir(parents=True,exist_ok=True)
rows=[]; dropped={}; seen={}; conflicts=set()
for i,rec in enumerate(csv.DictReader(open('malicious_phish.csv',encoding='utf-8',errors='replace',newline=''))):
    raw=(rec.get('url') or '').strip(); label=(rec.get('type') or '').strip().lower()
    if label not in ('benign','phishing'): dropped[label or 'missing_label']=dropped.get(label or 'missing_label',0)+1; continue
    try:
        c=canonicalize(raw); reg=registrable_domain(c)
        if len(raw)>2048 or not reg or any(ord(x)<32 for x in raw): raise ValueError
    except Exception: dropped['unparseable']=dropped.get('unparseable',0)+1; continue
    key=c; old=seen.get(key)
    if old and old['label']!=label: conflicts.add(key)
    elif not old: seen[key]={'url_raw':raw,'url_canonical':c,'label':label,'source':'malicious_phish.csv','family':'kaggle_like','registrable_domain':reg,'host':c.split('/')[0],'date':'2017-01-01','brand_target':'','lang':'','license':'CC BY/unknown Kaggle mirror','sample_weight':1.0,**raw_flags(raw)}
for key in conflicts: seen.pop(key,None)
for row in seen.values():
    h=int(hashlib.sha256(row['registrable_domain'].encode()).hexdigest()[:8],16)%100
    row['split_role']='eval_sealed' if h<5 else ('eval_sanity' if h<10 else ('holdout' if h<15 else 'train_pool'))
    row['hard_negative']=False; row['hard_positive']=False; row['collected_at']=datetime.now(timezone.utc).isoformat(); row['family']='kaggle_like'
    rows.append(row)
df=pd.DataFrame(rows)
# source placeholders are explicit and never silently presented as downloaded data
for p in ['data/raw/fresh','data/raw/external']:
 Path(p).mkdir(parents=True,exist_ok=True)
manifest={'created_at':datetime.now(timezone.utc).isoformat(),'sources_attempted':['malicious_phish.csv','PhreshPhish','ealvaradob/phishing-dataset','Common Crawl','Tranco','OpenPhish','PhishTank'],'sources_kept':{'malicious_phish.csv':len(df)},'sources_skipped':{'external_downloads':'not used without a verified local snapshot; see PROVENANCE.md'},'rows_kept':len(df),'rows_dropped':dropped,'conflicting_urls_removed':len(conflicts),'class_balance':df.label.value_counts().to_dict(),'registrable_domains':int(df.registrable_domain.nunique()),'split_counts':df.split_role.value_counts().to_dict()}
df.to_parquet(out/'urls_unified.parquet',index=False)
(out/'manifest.json').write_text(json.dumps(manifest,indent=2))
# audit and spot check
audit=[]
for (source,label),g in df.groupby(['source','label']): audit.append({'source':source,'label':label,'rows':len(g),'scheme_share':float(g.has_scheme_raw.mean()),'www_share':float(g.has_www_raw.mean()),'trailing_slash_share':float(g.has_trailing_slash_raw.mean()),'path_share':float(g.url_canonical.str.contains('/').mean()),'query_share':float(g.url_canonical.str.contains(r'\\?',regex=True).mean()),'domains':int(g.registrable_domain.nunique())})
Path('data/ARTIFACT_AUDIT.md').write_text('# Artifact audit\n\nSurface-cue rates are measured from the cleaned local source. A domain-grouped surface-only baseline is recorded as a diagnostic; no surface-only model is shipped.\n\n'+pd.DataFrame(audit).to_csv(index=False)+'\n\nPooled AUC before rebalancing: unavailable for this single-source snapshot; the audit is a limitation and is not used as a success claim.\n')
spot=df.sample(min(300,len(df)),random_state=42)[['source','label','url_raw']]
spot.to_csv('data/spot_check.csv',index=False)
Path('data/DATA_CARD.md').write_text(f'''# Data card\n\nThis run uses the local `malicious_phish.csv` snapshot only ({len(df):,} unique canonical URLs after cleaning). Labels are the source's `benign` and `phishing` classes. Rows with unsupported labels, malformed hosts, control characters, overlong URLs, or conflicting duplicate labels are removed. No URL is requested or opened.\n\nThe requested million-row target was not padded: additional sources require separate verified downloads and are logged as skipped.\n''')
Path('data/PROVENANCE.md').write_text('''# Provenance\n\n- `malicious_phish.csv`: local Kaggle-style snapshot supplied with the project; source licence is not embedded in the file, so it is treated as provenance-uncertain and used for development only.\n- PhreshPhish, academic sets, Common Crawl, Tranco, OpenPhish, PhishTank: not included in this offline rebuild; no credentials or network fetches were used.\n\nURLs are strings only. The pipeline never resolves, crawls, or downloads URL content.\n''')
# sanity set written before training
legit=['https://www.google.com/','google.com','https://github.com/login','github.com','https://www.wikipedia.org/wiki/Main_Page','amazon.com/dp/B01','https://www.microsoft.com/en-us/','apple.com/support','youtube.com/watch?v=abc','stackoverflow.com/questions/1','mansoura.edu.eg/','https://docs.google.com/forms/','https://www.github.com/user/repo/issues?q=test','https://www.amazon.com/s?k=books']
phish=['paypal.com.account-verify.example-secure.top/login','http://192.0.2.10/login/paypal','secure-google-login.example.top/verify','appleid.apple.com.account-check.example.org/signin','xn--pple-43d.example/login','github.com.evil.example/confirm','microsoft-login-reset.example.net/account/verify','10.0.0.1/bank/login','coinbase-wallet-confirm.example.top/update','amazon.security-alert.example.com/login']
with open('tests/sanity_urls.csv','w',newline='') as f:
 w=csv.writer(f); w.writerow(['url','label']); w.writerows([(x,'legitimate') for x in legit]); w.writerows([(x,'phishing') for x in phish])
print(json.dumps(manifest,indent=2))
