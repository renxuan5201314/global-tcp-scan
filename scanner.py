
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Regional HTTPS latency scanner using official CloudflareSpeedTest."""

import concurrent.futures
import csv
import datetime as dt
import ipaddress
import json
import os
import shutil
import subprocess
import sys
import tempfile
import urllib.error
import urllib.request
from pathlib import Path

REGIONS = [
    x.strip().upper()
    for x in os.getenv("REGIONS", "JP,HK,KR,CN,US,SG,DE").split(",")
    if x.strip()
]
SOURCE_URL = os.getenv(
    "SOURCE_URL", "https://proxy.seeck.cn/api/nodes?region="
)
TOP_N = max(1, min(int(os.getenv("TOP_N", "20")), 500))
PUBLISH_STANDARD_VARIANTS = os.getenv(
    "PUBLISH_STANDARD_VARIANTS", "true"
).lower() in ("1", "true", "yes", "on")
CFST_BIN = os.getenv("CFST_BIN", "./cfst")
CFST_THREADS = max(1, min(int(os.getenv("CFST_THREADS", "20")), 1000))
CFST_ROUNDS = max(1, min(int(os.getenv("CFST_ROUNDS", "4")), 20))
CFST_TIMEOUT_SECONDS = max(
    1, min(int(os.getenv("CFST_TIMEOUT_SECONDS", "3")), 30)
)
CFST_URL = os.getenv(
    "CFST_URL", "https://www.youtube.com/generate_204"
)
CFST_HTTPING_CODE = os.getenv("CFST_HTTPING_CODE", "204")
OUT = Path("public")
DATA = OUT / "data"
STATE_FILE = Path(".scan-state.json")
INTERVAL_SECONDS = 30 * 60


def now():
    return dt.datetime.now(dt.timezone.utc)


def iso_now():
    return now().isoformat().replace("+00:00", "Z")


def load_state():
    try:
        value = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return value if isinstance(value, dict) else {}
    except FileNotFoundError:
        return {}
    except (OSError, json.JSONDecodeError) as exc:
        print(f"WARNING: cannot read {STATE_FILE}: {exc}", file=sys.stderr)
        return {}


def should_scan(state):
    last = state.get("lastCompletedAt")
    if not last:
        return True
    try:
        previous = dt.datetime.fromisoformat(last.replace("Z", "+00:00"))
        elapsed = (now() - previous).total_seconds()
    except (ValueError, TypeError):
        return True
    if elapsed < INTERVAL_SECONDS:
        print(
            f"Skipping scan: {INTERVAL_SECONDS - elapsed:.0f}s remain "
            "before next round."
        )
        return False
    return True


def fetch_payload(url):
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": "global-tcp-scan/3.0",
            "Accept": "application/json, text/plain, */*",
        },
    )
    try:
        with urllib.request.urlopen(request, timeout=25) as response:
            raw = response.read()
            final_url = response.geturl()
            status = response.status
    except urllib.error.HTTPError as exc:
        body = exc.read(300).decode("utf-8", errors="replace")
        raise RuntimeError(f"source HTTP {exc.code}: {body}") from exc

    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise ValueError(f"empty source response: {final_url}")
    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.lstrip().startswith("#")
        ]
    print(f"Source HTTP {status}, {len(raw)} bytes: {final_url}")
    return payload, len(raw)


def parse_endpoint(item):
    ip = port = None
    if isinstance(item, str):
        value = item.strip().split("#", 1)[0].strip()
        if value.startswith("[") and "]:" in value:
            ip, port = value[1:].split("]:", 1)
        elif value.count(":") == 1:
            ip, port = value.rsplit(":", 1)
    elif isinstance(item, dict):
        ip = (
            item.get("ip")
            or item.get("host")
            or item.get("address")
            or item.get("server")
        )
        port = item.get("port")
        if ip and port is None and isinstance(ip, str) and ip.count(":") == 1:
            ip, port = ip.rsplit(":", 1)

    if not ip or port is None:
        return None
    try:
        parsed_ip = ipaddress.ip_address(str(ip).strip())
        if parsed_ip.version != 4:
            return None
        port = int(port)
        if not 1 <= port <= 65535:
            return None
        ip = str(parsed_ip)
        return {"ip": ip, "port": port, "address": f"{ip}:{port}"}
    except (ValueError, TypeError):
        return None


def candidates_from(payload):
    if isinstance(payload, list):
        raw = payload
    elif isinstance(payload, dict):
        keys = (
            "nodes", "data", "list", "results", "items",
            "proxies", "servers", "ips",
        )
        raw = next(
            (payload.get(k) for k in keys if isinstance(payload.get(k), list)),
            None,
        )
        if raw is None:
            for parent_key in ("data", "result", "response"):
                parent = payload.get(parent_key)
                if isinstance(parent, dict):
                    raw = next(
                        (
                            parent.get(k)
                            for k in keys
                            if isinstance(parent.get(k), list)
                        ),
                        None,
                    )
                    if raw is not None:
                        break
        if raw is None:
            raw = next(
                (v for v in payload.values() if isinstance(v, list)), None
            )
        if raw is None:
            raise ValueError(
                f"JSON has no recognizable node list; keys={list(payload)[:25]}"
            )
    else:
        raise ValueError(f"unsupported source payload: {type(payload).__name__}")

    found, seen = [], set()
    for item in raw:
        parts = (
            item.split()
            if isinstance(item, str) and any(c.isspace() for c in item.strip())
            else [item]
        )
        for part in parts:
            node = parse_endpoint(part)
            if node and node["address"] not in seen:
                seen.add(node["address"])
                found.append(node)

    if not found:
        raise ValueError(
            "source yielded no valid IPv4:port candidates "
            "(CFST adapter requires IPv4)"
        )
    return found


def find_csv_value(row, needles):
    for key, value in row.items():
        if key and any(needle in key.strip().lower() for needle in needles):
            return value
    return None


def run_cfst_group(port, nodes, workdir):
    """Run HTTPing against the target URL for one candidate port."""
    ip_file = workdir / f"ips-{port}.txt"
    csv_file = workdir / f"result-{port}.csv"
    ip_file.write_text(
        "\n".join(node["ip"] for node in nodes) + "\n",
        encoding="ascii",
    )

    command = [
        CFST_BIN,
        "-f", str(ip_file),
        "-tp", str(port),
        "-t", str(CFST_ROUNDS),
        "-n", str(min(CFST_THREADS, max(1, len(nodes)))),
        "-tl", "9999",
        "-tlr", "1",
        "-httping",
        "-url", CFST_URL,
        "-httping-code", CFST_HTTPING_CODE,
        "-p", "0",
        "-o", str(csv_file),
        "-dd",
    ]
    print(
        f"CFST HTTPS HTTPing port={port}, candidates={len(nodes)}: "
        f"{' '.join(command)}"
    )

    timeout = max(
        60, len(nodes) * CFST_TIMEOUT_SECONDS + 90
    )
    try:
        proc = subprocess.run(
            command,
            cwd=Path.cwd(),
            capture_output=True,
            text=True,
            timeout=timeout,
        )
    except subprocess.TimeoutExpired as exc:
        raise RuntimeError(f"CFST timed out on port {port}") from exc

    if proc.stdout:
        print(proc.stdout[-4000:])
    if proc.stderr:
        print(proc.stderr[-2000:], file=sys.stderr)

    if not csv_file.exists() or csv_file.stat().st_size == 0:
        if proc.returncode != 0:
            raise RuntimeError(
                f"CFST exit={proc.returncode}, no CSV for port {port}"
            )
        print(f"CFST produced no results for port {port}")
        return {}

    results = {}
    with csv_file.open("r", encoding="utf-8-sig", newline="") as stream:
        reader = csv.DictReader(stream)
        for row in reader:
            ip = find_csv_value(row, ("ip 地址", "ip address", "ip"))
            latency = find_csv_value(
                row, ("平均延迟", "average latency", "latency")
            )
            if not ip or not latency:
                continue
            try:
                ip = str(ip).strip()
                ms = float(
                    str(latency).strip().lower().replace("ms", "")
                )
                ipaddress.IPv4Address(ip)
                if 0 <= ms < 9999:
                    results[f"{ip}:{port}"] = round(ms, 2)
            except (ValueError, TypeError):
                continue

    if proc.returncode != 0 and not results:
        raise RuntimeError(
            f"CFST failed on port {port}, exit={proc.returncode}"
        )
    print(
        f"CFST port={port}: parsed {len(results)} successful HTTPing results"
    )
    return results


def scan_region(candidates):
    grouped = {}
    for node in candidates:
        grouped.setdefault(node["port"], []).append(node)

    results = {}
    with tempfile.TemporaryDirectory(prefix="cfst-") as temp:
        workdir = Path(temp)
        for port, nodes in sorted(grouped.items()):
            try:
                results.update(run_cfst_group(port, nodes, workdir))
            except Exception as exc:
                print(
                    f"WARNING: port group {port} failed: "
                    f"{type(exc).__name__}: {exc}",
                    file=sys.stderr,
                )
    return results


def write_region(region, candidates, latencies, source_bytes):
    if not latencies:
        print(
            f"{region}: no successful HTTPS results; "
            "keeping old TXT/JSON unchanged."
        )
        return False

    by_address = {node["address"]: node for node in candidates}
    all_nodes = []
    for address, latency in latencies.items():
        node = by_address.get(address)
        if node:
            all_nodes.append(
                {
                    "ip": node["ip"],
                    "port": node["port"],
                    "latencyMs": latency,
                    "testedAt": iso_now(),
                }
            )

    all_nodes.sort(
        key=lambda node: (
            float(node["latencyMs"]),
            node["ip"],
            int(node["port"]),
        )
    )
    if not all_nodes:
        print(
            f"{region}: CFST results did not match source candidates; "
            "keeping old files."
        )
        return False

    OUT.mkdir(parents=True, exist_ok=True)
    DATA.mkdir(parents=True, exist_ok=True)
    region_l = region.lower()

    def make_lines(items, limit=None):
        selected = items if limit is None else items[:limit]
        return (
            "\n".join(
                f'{node["ip"]}:{node["port"]}#{region}-{i:02d}-'
                f'{max(0, round(float(node["latencyMs"])))}ms'
                for i, node in enumerate(selected, 1)
            ) + "\n"
        ).encode("utf-8") if selected else b""

    outputs = {f"{region_l}.txt": make_lines(all_nodes, TOP_N)}
    if PUBLISH_STANDARD_VARIANTS:
        outputs[f"{region_l}-.txt"] = make_lines(all_nodes, 30)
        outputs[f"{region_l}-top100.txt"] = make_lines(all_nodes, 100)
        outputs[f"{region_l}-all.txt"] = make_lines(all_nodes)

    record = {
        "region": region,
        "source": "official-XIU2-CloudflareSpeedTest",
        "protocol": "HTTPS-HTTPing",
        "testUrl": CFST_URL,
        "acceptedHttpStatus": CFST_HTTPING_CODE,
        "updatedAt": iso_now(),
        "candidateCount": len(candidates),
        "sourceBytes": source_bytes,
        "testedCount": len(candidates),
        "successCount": len(all_nodes),
        "failedCount": max(0, len(candidates) - len(all_nodes)),
        "cfstRounds": CFST_ROUNDS,
        "defaultTopN": TOP_N,
        "nodes": all_nodes,
    }

    pending = []
    try:
        for name, content in outputs.items():
            tmp = OUT / (name + ".tmp")
            tmp.write_bytes(content)
            pending.append((tmp, OUT / name))
        json_tmp = DATA / f"{region_l}.json.tmp"
        json_tmp.write_text(
            json.dumps(record, ensure_ascii=False, indent=2) + "\n",
            encoding="utf-8",
        )
        pending.append((json_tmp, DATA / f"{region_l}.json"))
        for tmp, target in pending:
            tmp.replace(target)
    except Exception:
        for tmp, _ in pending:
            try:
                tmp.unlink(missing_ok=True)
            except OSError:
                pass
        raise

    print(
        f"{region}: candidates={len(candidates)}, successes={len(all_nodes)}, "
        f"default_published={min(TOP_N, len(all_nodes))}, "
        f"top30={min(30, len(all_nodes))}, "
        f"top100={min(100, len(all_nodes))}, all={len(all_nodes)}"
    )
    return True


def build_index():
    names = {
        "JP": "Japan",
        "HK": "Hong Kong",
        "KR": "South Korea",
        "CN": "China",
        "US": "United States",
        "SG": "Singapore",
        "DE": "Germany",
    }
    links = "\n".join(
        f'<li><strong>{region} — {names.get(region, region)}:</strong> '
        f'<a href="{region.lower()}.txt">default top {TOP_N}</a> | '
        f'<a href="{region.lower()}-.txt">top 30</a> | '
        f'<a href="{region.lower()}-top100.txt">top 100</a> | '
        f'<a href="{region.lower()}-all.txt">all</a> | '
        f'<a href="data/{region.lower()}.json">JSON</a></li>'
        for region in REGIONS
    )
    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Global YouTube HTTPS latency results</title>
</head>
<body>
<h1>Global YouTube HTTPS latency results</h1>
<p>Target: {CFST_URL}; accepted HTTP status: {CFST_HTTPING_CODE}.
Latency is measured from GitHub Actions and may differ from your own network.</p>
<ul>{links}</ul>
<p>Each candidate IP is tested with official CloudflareSpeedTest HTTPing.
This is not a test through a V2RayN proxy. If a region has no successful
results, its previous TXT/JSON files are retained.</p>
</body>
</html>"""
    (OUT / "index.html").write_text(html + "\n", encoding="utf-8")


def set_output(name, value):
    path = os.getenv("GITHUB_OUTPUT")
    if path:
        with open(path, "a", encoding="utf-8") as stream:
            stream.write(f"{name}={str(value).lower()}\n")


def main():
    if not REGIONS:
        raise RuntimeError("REGIONS is empty")

    binary = Path(CFST_BIN)
    if not binary.exists() and shutil.which(CFST_BIN) is None:
        raise FileNotFoundError(
            f"CloudflareSpeedTest binary not found: {CFST_BIN}"
        )

    OUT.mkdir(parents=True, exist_ok=True)
    DATA.mkdir(parents=True, exist_ok=True)
    state = load_state()
    if not should_scan(state):
        set_output("publish", False)
        return

    round_no = int(state.get("roundNo", 0))
    errors = []
    any_updated = False
    print(
        f"Official CloudflareSpeedTest HTTPS scan round {round_no + 1}: "
        f"{', '.join(REGIONS)}"
    )

    for region in REGIONS:
        url = SOURCE_URL + region
        print(f"\n===== {region} =====\nSource: {url}")
        try:
            payload, source_bytes = fetch_payload(url)
            candidates = candidates_from(payload)
            print(
                f"{region}: parsed {len(candidates)} unique IPv4:port "
                "candidates; scanning every candidate."
            )
            latencies = scan_region(candidates)
            updated = write_region(
                region, candidates, latencies, source_bytes
            )
            any_updated = any_updated or updated
            if not updated:
                errors.append(
                    f"{region}: no successful HTTPS result; old files retained"
                )
        except Exception as exc:
            message = f"{region}: {type(exc).__name__}: {exc}"
            errors.append(message)
            print(
                f"ERROR: {message}; keeping previous region files.",
                file=sys.stderr,
            )

    build_index()
    completed = iso_now()
    STATE_FILE.write_text(
        json.dumps(
            {
                "lastCompletedAt": completed,
                "roundNo": round_no + 1,
                "regions": REGIONS,
                "lastErrors": errors,
            },
            ensure_ascii=False,
            indent=2,
        ) + "\n",
        encoding="utf-8",
    )
    set_output("publish", True)
    print(f"Round completed at {completed}; any_region_updated={any_updated}")
    if errors:
        print(
            "Regions needing attention:\n"
            + "\n".join(f" - {error}" for error in errors)
        )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(f"FATAL: {type(exc).__name__}: {exc}", file=sys.stderr)
        sys.exit(1)
