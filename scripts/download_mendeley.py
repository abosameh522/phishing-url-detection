from pathlib import Path
import json,time,urllib.request
sources=[('MURL','5fk24y4xmg',1),('PhishBD_2026','8d6zsfwc7z',2),('LegitPhish','hx4m73v2sf',1)]
root=Path('data/external/mendeley'); root.mkdir(parents=True,exist_ok=True)
log=Path('logs/mendeley_download.log')
def get(url,headers=None):
 req=urllib.request.Request(url,headers={'User-Agent':'PhishingURLResearch/2.0 (+public research data; no URL requests)',**(headers or {})})
 return urllib.request.urlopen(req,timeout=30)
for name,dsid,version in sources:
 try:
  u=f'https://data.mendeley.com/public-api/datasets/{dsid}/files?folder_id=root&version={version}&$start=0&$limit=1000'
  with get(u,{'Accept':'application/vnd.mendeley-public-dataset.1+json'}) as r: items=json.load(r)
  time.sleep(1)
  entry=next(x for x in items if x.get('status')=='COMPLETED')
  target=root/f"{name}_{version}_{entry['filename']}"
  if not target.exists() or target.stat().st_size!=entry.get('size'):
   with get(entry['content_details']['download_url']) as r, target.open('wb') as f:
    while True:
     b=r.read(1<<20)
     if not b: break
     f.write(b)
  with log.open('a') as f:f.write(f'{name} dataset={dsid} version={version} file={target} bytes={target.stat().st_size} license metadata fetched on public page\n')
  time.sleep(1)
 except Exception as e:
  with log.open('a') as f:f.write(f'ERROR {name} {type(e).__name__}: {e}\n')
print('Mendeley downloads completed; see',log)
