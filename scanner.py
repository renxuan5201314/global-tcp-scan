
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Scan regional TCP endpoints, retain previous results and publish TXT/JSON."""

import concurrent.futures
import datetime as dt
import ipaddress
import json
import os
import socket
import sys
import time
import urllib.error
import urllib.request
from pathlib import Path

REGIONS = [
    x.strip().upper()
    for x in os.getenv("REGIONS", "JP,HK,KR,CN,US,SG,DE").split(",")
    if x.strip()
]

SOURCE_URL = os.getenv(
    "SOURCE_URL",
    "https://proxy.seeck.cn/api/nodes?region=",
)
BATCH_SIZE = max(1, min(int(os.getenv("BATCH_SIZE", "25")), 100))
TIMEOUT = max(
    1.0, min(float(os.getenv("CONNECT_TIMEOUT_SECONDS", "5")), 10.0)
)
CONCURRENCY = max(1, min(int(os.getenv("MAX_CONCURRENCY", "5")), 10))

OUT = Path("public")
DATA = OUT / "data"
STATE_FILE = Path(".scan-state.json")
INTERVAL_SECONDS = 30 * 60


def now():
    return dt.datetime.now(dt.timezone.utc)


def iso_now():
    return now().isoformat().replace("+00:00", "Z")


def load_state():
    if not STATE_FILE.exists():
        return {}
    try:
        data = json.loads(STATE_FILE.read_text(encoding="utf-8"))
        return data if isinstance(data, dict) else {}
    except (OSError, json.JSONDecodeError) as exc:
        print(f"WARNING: Cannot read {STATE_FILE}: {exc}", file=sys.stderr)
        return {}


def should_scan(state):
    last = state.get("lastCompletedAt")
    if not last:
        print("No previous completed round; starting initial scan.")
        return True

    try:
        last_time = dt.datetime.fromisoformat(last.replace("Z", "+00:00"))
        elapsed = (now() - last_time).total_seconds()
    except (ValueError, TypeError):
        print("Invalid previous completion time; starting a new scan.")
        return True

    remaining = INTERVAL_SECONDS - elapsed
    if remaining > 0:
        print(
            f"Skipping scan: {remaining:.0f}s remain before the next round."
        )
        return False

    print("30-minute interval elapsed; starting the next round.")
    return True


def fetch_json(url):
    """Accept either JSON or a plain-text list of IP:port endpoints."""
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "github-actions-global-tcp-scan/1.3",
            "Accept": "application/json, text/plain, */*",
        },
    )

    try:
        with urllib.request.urlopen(req, timeout=20) as response:
            raw = response.read()
            status = response.status
            content_type = response.headers.get("Content-Type", "unknown")
            final_url = response.geturl()
    except urllib.error.HTTPError as exc:
        sample = exc.read(500).decode("utf-8", errors="replace")
        raise RuntimeError(
            f"HTTP {exc.code} for {url}; body={sample!r}"
        ) from exc

    text = raw.decode("utf-8-sig", errors="replace").strip()
    if not text:
        raise ValueError(f"Empty response from {final_url}")

    try:
        payload = json.loads(text)
        response_format = "JSON"
    except json.JSONDecodeError:
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]
        endpoints = [line for line in lines if parse_endpoint(line)]
        if not endpoints:
            raise ValueError(
                f"Unrecognized response; HTTP {status}; "
                f"Content-Type={content_type}; bytes={len(raw)}; "
                f"URL={final_url}; sample={text[:300]!r}"
            )
        payload = endpoints
        response_format = "plain text"

    print(
        f"Source: HTTP {status}; format={response_format}; "
        f"bytes={len(raw)}; URL={final_url}"
    )
    return payload, len(raw)


def parse_endpoint(item):
    ip = None
    port = None

    if isinstance(item, str):
        value = item.strip()
        if not value:
            return None

        # Strip source labels such as #JP or #JP-01-25ms.
        value = value.split("#", 1)[0].strip()

        # Also accept multiple whitespace-separated endpoints.
        if any(ch.isspace() for ch in value):
            return None

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

        if (
            ip
            and port is None
            and isinstance(ip, str)
            and ip.count(":") == 1
        ):
            ip, port = ip.rsplit(":", 1)

    if not ip or port is None:
        return None

    try:
        ip = str(ipaddress.ip_address(str(ip).strip()))
        port = int(port)
        if not 1 <= port <= 65535:
            return None
        return {
            "ip": ip,
            "port": port,
            "address": f"{ip}:{port}",
        }
    except (ValueError, TypeError):
        return None


def candidates_from(payload):
    if isinstance(payload, list):
        raw = payload
    elif isinstance(payload, dict):
        raw = None
        keys = (
            "nodes", "data", "list", "results", "items",
            "proxies", "servers", "ips",
        )

        for key in keys:
            if isinstance(payload.get(key), list):
                raw = payload[key]
                break

        if raw is None:
            for parent_key in ("data", "result", "response"):
                parent = payload.get(parent_key)
                if isinstance(parent, dict):
                    for key in keys:
                        if isinstance(parent.get(key), list):
                            raw = parent[key]
                            break
                if raw is not None:
                    break

        if raw is None:
            raw = next(
                (value for value in payload.values()
                 if isinstance(value, list)),
                None,
            )

        if raw is None:
            raise ValueError(
                "JSON has no recognizable node list; "
                f"keys={list(payload.keys())[:30]}"
            )
    else:
        raise ValueError(
            f"Expected JSON list/object, got {type(payload).__name__}"
        )

    nodes = []
    seen = set()

    for item in raw:
        # Some plain-text APIs put multiple endpoints on one line.
        if isinstance(item, str) and any(ch.isspace() for ch in item.strip()):
            items = item.split()
        else:
            items = [item]

        for part in items:
            node = parse_endpoint(part)
            if node and node["address"] not in seen:
                seen.add(node["address"])
                nodes.append(node)

    if not nodes:
        raise ValueError("No valid IP:port candidates parsed.")
    return nodes


def test_tcp(node):
    started = time.perf_counter()
    result = {
        **node,
        "ok": False,
        "latencyMs": None,
        "testedAt": iso_now(),
        "error": None,
    }

    try:
        with socket.create_connection(
            (node["ip"], node["port"]), timeout=TIMEOUT
        ):
            result["ok"] = True
            result["latencyMs"] = round(
                (time.perf_counter() - started) * 1000, 2
            )
    except socket.timeout:
        result["error"] = f"TCP timeout after {TIMEOUT:g}s"
    except OSError as exc:
        result["error"] = f"{type(exc).__name__}: {str(exc)[:160]}"

    return result


def read_previous(region):
    path = DATA / f"{region.lower()}.json"
    if not path.exists():
        return []

    try:
        data = json.loads(path.read_text(encoding="utf-8"))
        if isinstance(data, dict) and isinstance(data.get("nodes"), list):
            return data["nodes"]
    except (OSError, json.JSONDecodeError) as exc:
        print(f"WARNING: Cannot read {path}: {exc}", file=sys.stderr)

    return []


def merge_results(region, successful):
    """Keep previous successful records; replace entries that test successfully."""
    merged = {}

    for node in read_previous(region):
        if not isinstance(node, dict):
            continue
        try:
            ip = str(ipaddress.ip_address(str(node.get("ip"))))
            port = int(node.get("port"))
            latency = node.get("latencyMs")
            if (
                1 <= port <= 65535
                and isinstance(latency, (int, float))
                and latency >= 0
            ):
                address = f"{ip}:{port}"
                merged[address] = {
                    "ip": ip,
                    "port": port,
                    "latencyMs": latency,
                    "testedAt": node.get("testedAt"),
                }
        except (ValueError, TypeError):
            continue

    for result in successful:
        merged[result["address"]] = {
            "ip": result["ip"],
            "port": result["port"],
            "latencyMs": result["latencyMs"],
            "testedAt": result["testedAt"],
        }

    return sorted(
        merged.values(),
        key=lambda n: (
            float(n["latencyMs"]), n["ip"], int(n["port"])
        ),
    )[:500]


def write_region(region, candidates, results, batch_start, source_bytes):
    successful = [r for r in results if r["ok"]]
    failed_count = len(results) - len(successful)
    nodes = merge_results(region, successful)

    lines = [
        f'{node["ip"]}:{node["port"]}#{region}-{index:02d}-'
        f'{max(0, round(float(node["latencyMs"])))}ms'
        for index, node in enumerate(nodes, 1)
    ]

    txt_path = OUT / f"{region.lower()}.txt"
    txt_path.write_text(
        ("\n".join(lines) + "\n") if lines else "",
        encoding="utf-8",
    )

    record = {
        "region": region,
        "source": "github-actions",
        "updatedAt": iso_now(),
        "candidateCount": len(candidates),
        "sourceBytes": source_bytes,
        "batchStartIndex": batch_start,
        "testedCount": len(results),
        "successCount": len(successful),
        "failedCount": failed_count,
        "nodes": nodes,
        "lastBatch": results,
    }

    json_path = DATA / f"{region.lower()}.json"
    json_path.write_text(
        json.dumps(record, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    print(
        f"{region}: tested={len(results)}, "
        f"success={len(successful)}, failed={failed_count}, "
        f"cached={len(nodes)}; wrote {txt_path} and {json_path}"
    )


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
        f'<li><a href="{r.lower()}.txt">{r} — '
        f'{names.get(r, r)} TXT</a> '
        f'(<a href="data/{r.lower()}.json">JSON details</a>)</li>'
        for r in REGIONS
    )

    html = f"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1">
<title>Global TCP latency results</title>
</head>
<body>
<h1>Global TCP latency results</h1>
<p>TCP connection latency only. This does not verify proxy protocol
usability or whether an IP is residential.</p>
<ul>
{links}
</ul>
<p>All configured regions are processed sequentially. Previous successful
measurements are retained when retests fail. A new round starts at least
30 minutes after the previous round completes.</p>
</body>
</html>
"""
    (OUT / "index.html").write_text(html, encoding="utf-8")


def main():
    if not REGIONS:
        raise RuntimeError("REGIONS is empty")

    OUT.mkdir(parents=True, exist_ok=True)
    DATA.mkdir(parents=True, exist_ok=True)

    state = load_state()

    # The workflow wakes periodically; only scan after 30 minutes have elapsed.
    if not should_scan(state):
        with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
            f.write("publish=false\n")
        return

    round_no = int(state.get("roundNo", 0))
    errors = []

    print(f"Starting round {round_no + 1}: {', '.join(REGIONS)}")

    for region in REGIONS:
        source_url = SOURCE_URL + region
        print(f"\n===== Starting region={region} =====")
        print(f"Source URL={source_url}")

        try:
            payload, source_bytes = fetch_json(source_url)
            candidates = candidates_from(payload)

            start = (round_no * BATCH_SIZE) % len(candidates)
            count = min(BATCH_SIZE, len(candidates))
            batch = [
                candidates[(start + i) % len(candidates)]
                for i in range(count)
            ]

            print(
                f"{region}: candidates={len(candidates)}, "
                f"start={start}, testing={len(batch)}"
            )

            with concurrent.futures.ThreadPoolExecutor(
                max_workers=CONCURRENCY
            ) as pool:
                results = list(pool.map(test_tcp, batch))

            write_region(region, candidates, results, start, source_bytes)

        except Exception as exc:
            # Do not replace the old region files when its source or scan fails.
            message = f"{region}: {type(exc).__name__}: {exc}"
            errors.append(message)
            print(f"ERROR: {message}", file=sys.stderr)
            print(f"Keeping previous files for {region}.")

    # Only mark completion after every region has been attempted.
    # Even if one region fails, its old results remain and the next cycle
    # can retry it after the interval.
    build_index()
    completed_at = iso_now()
    new_state = {
        "lastCompletedAt": completed_at,
        "roundNo": round_no + 1,
        "regions": REGIONS,
        "lastErrors": errors,
    }
    STATE_FILE.write_text(
        json.dumps(new_state, ensure_ascii=False, indent=2) + "\n",
        encoding="utf-8",
    )

    with open(os.environ["GITHUB_OUTPUT"], "a", encoding="utf-8") as f:
        f.write("publish=true\n")

    print(f"\nRound completed at {completed_at}")
    print(f"Next round eligible after {INTERVAL_SECONDS} seconds.")
    if errors:
        print(f"Regions with errors ({len(errors)}):")
        for error in errors:
            print(f" - {error}")
    else:
        print("All regions completed without source-level errors.")


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            f"FATAL: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
