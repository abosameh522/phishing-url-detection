"""Resumable PhreshPhish downloader; selects only safe metadata columns."""
from pathlib import Path
from datetime import datetime, timezone
import time
from huggingface_hub import HfFileSystem
import pyarrow.parquet as pq
ROOT=Path('data/external/phreshphish'); fs=HfFileSystem(); cols=['url','label','target','date','lang']
ROOT.mkdir(parents=True,exist_ok=True)
log=Path('logs/phresh_download.log')
def record(x):
 with log.open('a') as f: f.write(f"{datetime.now(timezone.utc).isoformat()} {x}\n")
for split in ['train','test']:
 paths=sorted(fs.glob(f'datasets/phreshphish/phreshphish/data/{split}-*.parquet'))
 (ROOT/split).mkdir(parents=True,exist_ok=True)
 for n,remote in enumerate(paths):
  dest=ROOT/split/(remote.rsplit('/',1)[1])
  if dest.exists() and dest.stat().st_size>0: continue
  for attempt in range(3):
   try:
    with fs.open(remote,'rb') as f: table=pq.read_table(f,columns=cols)
    pq.write_table(table,dest,compression='zstd')
    record(f'{split} {n+1}/{len(paths)} {dest.name} rows={table.num_rows} cols={table.column_names} bytes={dest.stat().st_size}')
    del table
    time.sleep(1)
    break
   except Exception as e:
    record(f'ERROR {split} {remote} attempt={attempt+1} {type(e).__name__}: {e}')
    time.sleep(2*(attempt+1))
  else: raise RuntimeError(f'Failed shard {remote}; see {log}')
# Benchmark text lists contain hashes, never live URLs. Keep each source file as returned.
bench=ROOT/'benchmark'; bench.mkdir(exist_ok=True)
files=sorted(fs.glob('datasets/phreshphish/phreshphish/benchmark/benchmark-*/*.txt'))
for n,remote in enumerate(files):
 dest=bench/remote.split('/benchmark/',1)[1]
 dest.parent.mkdir(parents=True,exist_ok=True)
 if dest.exists() and dest.stat().st_size>0: continue
 try:
  with fs.open(remote,'rb') as src, dest.open('wb') as out: out.write(src.read())
  record(f'benchmark {n+1}/{len(files)} {dest.relative_to(ROOT)} bytes={dest.stat().st_size}')
  time.sleep(1)
 except Exception as e:
  record(f'ERROR benchmark {remote} {type(e).__name__}: {e}')
print('download complete; details in',log)
