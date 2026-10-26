#!/usr/bin/env python3
"""Simple regional CloudflareSpeedTest runner; failed regions keep their last output."""
import csv, ipaddress, json, re, subprocess, urllib.request
from collections import defaultdict
from pathlib import Path

ROOT=Path(__file__).resolve().parent
PUBLIC=ROOT/"public"
REGIONS=("JP","HK","KR","CN","US","SG","DE")
API="https://proxy.seeck.cn/api/nodes?region="
CFST=ROOT/"cfst"
TOP_N=30

def fetch(region):
    req=urllib.request.Request(API+region,headers={"User-Agent":"global-tcp-scan/1.0"})
    with urllib.request.urlopen(req,timeout=20) as r:
        raw=r.read().decode("utf-8","replace")
    try: data=json.loads(raw); text=json.dumps(data,ensure_ascii=False)
    except json.JSONDecodeError: text=raw
    found=set()
    for m in re.finditer(r'(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})\s*:\s*(\d{1,5})',text):
        ip,ps=m.group(1),m.group(2)
        try:
            ipaddress.IPv4Address(ip); port=int(ps)
            if 1<=port<=65535: found.add((ip,port))
        except ValueError: pass
    return sorted(found,key=lambda x:(x[1],tuple(map(int,x[0].split(".")))))

def scan(region,endpoints):
    grouped=defaultdict(set)
    for ip,port in endpoints: grouped[port].add(ip)
    results={}
    for port,ips in sorted(grouped.items()):
        ipfile=ROOT/f".ips-{region.lower()}-{port}.txt"
        csvfile=ROOT/f".result-{region.lower()}-{port}.csv"
        try:
            sorted_ips = sorted(ips, key=lambda s: tuple(map(int, s.split("."))))
            ipfile.write_text("\n".join(sorted_ips) + "\n", encoding="utf-8")
            csvfile.unlink(missing_ok=True)
            cmd=[str(CFST),"-f",str(ipfile),"-tp",str(port),"-n","100","-t","3","-tl","9999","-tlr","1","-p","0","-o",str(csvfile),"-dd"]
            print(f"[{region}] port {port}: {len(ips)} IPs")
            p=subprocess.run(cmd,cwd=ROOT,text=True,stdout=subprocess.PIPE,stderr=subprocess.STDOUT,timeout=600)
            print(p.stdout[-3000:])
            if p.returncode or not csvfile.exists(): continue
            with csvfile.open(encoding="utf-8-sig",newline="") as f:
                reader=csv.reader(f); header=next(reader,[])
                h=[x.strip().lower() for x in header]
                ii=next((i for i,x in enumerate(h) if x in ("ip address","ip地址","ip")),None)
                li=next((i for i,x in enumerate(h) if "average latency" in x or "平均延迟" in x),None)
                if ii is None or li is None:
                    print(f"[{region}] CSV header not recognized: {header}"); continue
                for row in reader:
                    try:
                        ip=row[ii].strip(); ms=float(row[li])
                        if ip in ips and ms>=0: results[(ip,port)]=ms
                    except (ValueError,IndexError): pass
        except Exception as e: print(f"[{region}] port {port} failed: {e}")
        finally:
            ipfile.unlink(missing_ok=True); csvfile.unlink(missing_ok=True)
    return results

def main():
    if not CFST.exists(): raise SystemExit("cfst executable missing")
    PUBLIC.mkdir(parents=True,exist_ok=True)
    updated=0
    for region in REGIONS:
        target=PUBLIC/(region.lower()+".txt")
        try:
            endpoints=fetch(region)
            if not endpoints:
                print(f"[{region}] API returned no IPv4:port; keeping old file"); continue
            print(f"[{region}] got {len(endpoints)} unique IP:port endpoints")
            results=scan(region,endpoints)
            if not results:
                print(f"[{region}] no successful latency results; keeping old file"); continue
            best=sorted(results.items(),key=lambda x:(x[1],x[0][0],x[0][1]))[:30]
            lines=[f"{ip}:{port}#{region}-{i:02d}-{ms:.0f}ms" for i,((ip,port),ms) in enumerate(best,1)]
            target.write_text("\n".join(lines)+"\n",encoding="utf-8")
            print(f"[{region}] updated {target.name}: {len(lines)} entries")
            updated+=1
        except Exception as e: print(f"[{region}] failed; keeping old file: {e}")
    print(f"Done: updated {updated}/{len(REGIONS)} regions")

if __name__=="__main__": main()
