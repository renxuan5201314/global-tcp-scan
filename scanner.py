#!/usr/bin/env python3
"""Regional CloudflareSpeedTest runner; failed regions keep their last output."""
import csv
import ipaddress
import json
import math
import re
import subprocess
import urllib.request
from collections import defaultdict
from pathlib import Path

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
REGIONS = ("JP", "HK", "KR", "CN", "US", "SG", "DE")
API = "https://proxy.seeck.cn/api/nodes?region="
CFST = ROOT / "cfst"
TOP_N = 30


def fetch(region):
    request = urllib.request.Request(
        API + region, headers={"User-Agent": "global-tcp-scan/1.0"}
    )
    with urllib.request.urlopen(request, timeout=30) as response:
        raw = response.read().decode("utf-8", "replace")

    try:
        payload = json.loads(raw)
        text = json.dumps(payload, ensure_ascii=False)
    except json.JSONDecodeError:
        text = raw

    found = set()
    pattern = r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})\s*:\s*(\d{1,5})"
    for match in re.finditer(pattern, text):
        ip, port_text = match.groups()
        try:
            ipaddress.IPv4Address(ip)
            port = int(port_text)
            if 1 <= port <= 65535:
                found.add((ip, port))
        except ValueError:
            continue

    return sorted(found, key=lambda item: (item[1], tuple(map(int, item[0].split(".")))))


def parse_latency(value):
    value = str(value).strip().lower().replace("ms", "").strip()
    latency = float(value)
    if not math.isfinite(latency) or latency < 0:
        raise ValueError("invalid latency")
    return latency


def scan(region, endpoints):
    grouped = defaultdict(set)
    for ip, port in endpoints:
        grouped[port].add(ip)

    results = {}
    for port, ips in sorted(grouped.items()):
        ipfile = ROOT / f".ips-{region.lower()}-{port}.txt"
        csvfile = ROOT / f".result-{region.lower()}-{port}.csv"
        try:
            sorted_ips = sorted(ips, key=lambda value: tuple(map(int, value.split("."))))
            ipfile.write_text("\n".join(sorted_ips) + "\n", encoding="utf-8")
            csvfile.unlink(missing_ok=True)

            command = [
                str(CFST), "-f", str(ipfile), "-tp", str(port),
                "-n", "100", "-t", "3", "-tl", "9999", "-tlr", "1",
                "-p", "0", "-o", str(csvfile), "-dd",
            ]
            print(f"[{region}] port {port}: testing {len(ips)} IPs", flush=True)
            process = subprocess.run(
                command, cwd=ROOT, text=True, stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT, timeout=600,
            )
            if process.stdout:
                print(process.stdout[-5000:], flush=True)

            if process.returncode != 0:
                print(f"[{region}] port {port}: CFST exit {process.returncode}", flush=True)
                continue
            if not csvfile.is_file() or csvfile.stat().st_size == 0:
                print(f"[{region}] port {port}: CSV missing or empty", flush=True)
                continue

            with csvfile.open(encoding="utf-8-sig", newline="") as handle:
                reader = csv.reader(handle)
                header = next(reader, [])
                columns = [column.strip().lower() for column in header]
                ip_index = next(
                    (i for i, column in enumerate(columns)
                     if column in ("ip address", "ip地址", "ip")), None
                )
                latency_index = next(
                    (i for i, column in enumerate(columns)
                     if "average latency" in column or "平均延迟" in column
                     or "平均时延" in column), None
                )
                if ip_index is None or latency_index is None:
                    print(f"[{region}] CSV header not recognized: {header}", flush=True)
                    continue

                parsed = 0
                for row in reader:
                    try:
                        ip = row[ip_index].strip()
                        latency = parse_latency(row[latency_index])
                        if ip in ips:
                            results[(ip, port)] = latency
                            parsed += 1
                    except (ValueError, IndexError):
                        continue
                print(f"[{region}] port {port}: parsed {parsed} valid results", flush=True)

        except subprocess.TimeoutExpired:
            print(f"[{region}] port {port}: CFST timed out", flush=True)
        except Exception as error:
            print(f"[{region}] port {port} failed: {error}", flush=True)
        finally:
            ipfile.unlink(missing_ok=True)
            csvfile.unlink(missing_ok=True)

    return results


def main():
    if not CFST.is_file():
        raise SystemExit(f"CFST executable missing: {CFST}")

    PUBLIC.mkdir(parents=True, exist_ok=True)
    updated = 0

    for region in REGIONS:
        target = PUBLIC / f"{region.lower()}.txt"
        print(f"\n========== {region} ==========", flush=True)
        try:
            endpoints = fetch(region)
            if not endpoints:
                print(f"[{region}] API returned no IPv4:port endpoints; keeping old file", flush=True)
                continue

            print(f"[{region}] got {len(endpoints)} unique IP:port endpoints", flush=True)
            results = scan(region, endpoints)
            if not results:
                print(f"[{region}] no successful latency results; keeping old file", flush=True)
                continue

            best = sorted(
                results.items(),
                key=lambda item: (
                    item[1], tuple(map(int, item[0][0].split("."))), item[0][1]
                ),
            )[:TOP_N]
            lines = [
                f"{ip}:{port}#{region}-{rank:02d}-{latency:.0f}ms"
                for rank, ((ip, port), latency) in enumerate(best, 1)
            ]
            content = "\n".join(lines) + "\n"
            old_content = target.read_text(encoding="utf-8") if target.is_file() else None
            if old_content == content:
                print(f"[{region}] valid results found, file content unchanged", flush=True)
            else:
                target.write_text(content, encoding="utf-8")
                print(f"[{region}] updated {target.name}: {len(lines)} entries", flush=True)
            updated += 1

        except Exception as error:
            print(f"[{region}] failed; keeping old file: {error}", flush=True)

    print(f"\nDone: {updated}/{len(REGIONS)} regions produced valid results", flush=True)
    if updated == 0:
        raise SystemExit(
            "ERROR: 0 regions produced valid results. Review API, CFST, and CSV logs above."
        )


if __name__ == "__main__":
    main()
