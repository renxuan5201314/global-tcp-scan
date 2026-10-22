#!/usr/bin/env python3
"""Scan one region per run, then update public/<region>.txt and public/data/<region>.json."""
import concurrent.futures, datetime as dt, ipaddress, json, os, socket, sys, time, urllib.request
from pathlib import Path
REGIONS=[x.strip().upper() for x in os.getenv('REGIONS','JP,HK,KR,CN,US,SG,DE').split(',') if x.strip()]
SOURCE_URL=os.getenv('SOURCE_URL','https://proxy.seeck.cn/api/nodes?region=')
BATCH_SIZE=max(1,min(int(os.getenv('BATCH_SIZE','25')),100))
TIMEOUT=max(1.0,min(float(os.getenv('CONNECT_TIMEOUT_SECONDS','5')),10.0))
CONCURRENCY=max(1,min(int(os.getenv('MAX_CONCURRENCY','5')),10))
OUT=Path('public'); DATA=OUT/'data'
def now(): return dt.datetime.now(dt.timezone.utc)
def slot_number(): return int(now().timestamp()//300)
def fetch_json(url):
 req=urllib.request.Request(url,headers={'User-Agent':'github-actions-global-tcp-scan/1.0'})
 with urllib.request.urlopen(req,timeout=20) as r:
  raw=r.read(); return json.loads(raw.decode('utf-8',errors='replace')),len(raw)
def parse_endpoint(item):
 ip=port=None
 if isinstance(item,str):
  x=item.strip().split('#',1)[0]
  if x.startswith('[') and ']:' in x: ip,port=x[1:].split(']:',1)
  elif x.count(':')==1: ip,port=x.rsplit(':',1)
 elif isinstance(item,dict):
  ip=item.get('ip') or item.get('host') or item.get('address'); port=item.get('port')
  if ip and port is None and isinstance(ip,str) and ip.count(':')==1: ip,port=ip.rsplit(':',1)
 if not ip or port is None:return None
 try:
  ip=str(ipaddress.ip_address(str(ip).strip())); port=int(port)
  if not 1<=port<=65535:return None
  return {'ip':ip,'port':port,'address':f'{ip}:{port}'}
 except (ValueError,TypeError):return None
def candidates_from(payload):
 if isinstance(payload,list): raw=payload
 elif isinstance(payload,dict):
  raw=next((payload[k] for k in ('nodes','data','list','results','items','proxies') if isinstance(payload.get(k),list)),None)
  if raw is None: raw=next((v for v in payload.values() if isinstance(v,list)),None)
  if raw is None: raise ValueError('API JSON does not contain a recognizable node list')
 else: raise ValueError('API JSON is not a list/object')
 out=[]; seen=set()
 for item in raw:
  n=parse_endpoint(item)
  if n and n['address'] not in seen: seen.add(n['address']); out.append(n)
 if not out: raise ValueError('No valid IP:port candidates parsed; inspect source API JSON format')
 return out
def test_tcp(n):
 started=time.perf_counter(); result={**n,'ok':False,'latencyMs':None,'testedAt':now().isoformat().replace('+00:00','Z'),'error':None}
 try:
  with socket.create_connection((n['ip'],n['port']),timeout=TIMEOUT):
   result['ok']=True; result['latencyMs']=round((time.perf_counter()-started)*1000,2)
 except socket.timeout: result['error']=f'TCP timeout after {TIMEOUT:g}s'
 except OSError as e: result['error']=f'{type(e).__name__}: {str(e)[:160]}'
 return result
def read_previous(region):
 p=DATA/f'{region.lower()}.json'
 if not p.exists(): return []
 try:
  x=json.loads(p.read_text(encoding='utf-8')); return x.get('nodes',[]) if isinstance(x,dict) and isinstance(x.get('nodes'),list) else []
 except Exception: return []
def main():
 if not REGIONS: raise RuntimeError('REGIONS is empty')
 OUT.mkdir(exist_ok=True); DATA.mkdir(parents=True,exist_ok=True)
 slot=slot_number(); region=REGIONS[slot%len(REGIONS)]; round_no=slot//len(REGIONS)
 payload,source_bytes=fetch_json(SOURCE_URL+region); candidates=candidates_from(payload)
 start=(round_no*BATCH_SIZE)%len(candidates); batch=[candidates[(start+i)%len(candidates)] for i in range(min(BATCH_SIZE,len(candidates)))]
 print(f'region={region}; candidates={len(candidates)}; sourceBytes={source_bytes}; start={start}; testing={len(batch)}')
 with concurrent.futures.ThreadPoolExecutor(max_workers=CONCURRENCY) as pool: results=list(pool.map(test_tcp,batch))
 success=[r for r in results if r['ok']]; print(f'tested={len(results)}; success={len(success)}; failed={len(results)-len(success)}')
 # Keep previous successful measurements for nodes not in this batch; failed retests never erase good records.
 merged={f"{n.get('ip')}:{n.get('port')}":n for n in read_previous(region) if n.get('ip') and n.get('port') and isinstance(n.get('latencyMs'),(int,float))}
 for r in success: merged[r['address']]={'ip':r['ip'],'port':r['port'],'latencyMs':r['latencyMs'],'testedAt':r['testedAt']}
 nodes=sorted(merged.values(),key=lambda n:(float(n['latencyMs']),n['ip'],int(n['port'])))[:500]
 # Output format kept compatible with the existing style: IP:PORT#REGION-NN-Nms
 lines=[]
 for i,n in enumerate(nodes,1):
  ms=max(0,round(float(n['latencyMs'])))
  lines.append(f"{n['ip']}:{n['port']}#{region}-{i:02d}-{ms}ms")
 (OUT/f'{region.lower()}.txt').write_text(('\n'.join(lines)+'\n') if lines else '',encoding='utf-8')
 record={'region':region,'source':'github-actions','updatedAt':now().isoformat().replace('+00:00','Z'),'candidateCount':len(candidates),'batchStartIndex':start,'testedCount':len(results),'successCount':len(success),'failedCount':len(results)-len(success),'nodes':nodes,'lastBatch':results}
 (DATA/f'{region.lower()}.json').write_text(json.dumps(record,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
 # landing page links to the seven plain-text files
 names={'JP':'Japan','HK':'Hong Kong','KR':'South Korea','CN':'China','US':'United States','SG':'Singapore','DE':'Germany'}
 links='\n'.join(f'<li><a href="{r.lower()}.txt">{r} — {names[r]} TXT</a> <small>(<a href="data/{r.lower()}.json">JSON details</a>)</small></li>' for r in REGIONS)
 (OUT/'index.html').write_text('<!doctype html><html lang="en"><meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1"><title>Global TCP latency TXT</title><h1>Global TCP latency results</h1><p>Generated by GitHub Actions. TCP connect latency only; this does not verify proxy protocol usability.</p><ul>'+links+'</ul><p>Each scheduled run scans one region, up to 25 candidates. Results are cumulative successful TCP measurements; failed retests do not remove previous successes.</p></html>\n',encoding='utf-8')
 print(f'Wrote public/{region.lower()}.txt with {len(lines)} successful cached nodes')
if __name__=='__main__':
 try: main()
 except Exception as e: print(f'ERROR: {type(e).__name__}: {e}',file=sys.stderr); sys.exit(1)
