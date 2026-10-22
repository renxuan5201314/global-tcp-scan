
#!/usr/bin/env python3
# -*- coding: utf-8 -*-

"""Scan regional IP:port candidates and publish TCP latency results."""

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


def now():
    return dt.datetime.now(dt.timezone.utc)


def slot_number():
    return int(now().timestamp() // 300)


def fetch_json(url):
    """
    Fetch either JSON or plain-text node lists.
    The function name is retained to avoid changing the rest of the program.
    """
    req = urllib.request.Request(
        url,
        headers={
            "User-Agent": "github-actions-global-tcp-scan/1.2",
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
        try:
            body = exc.read(1000).decode("utf-8-sig", errors="replace")
            sample = " ".join(body.split())[:500]
        except Exception:
            sample = "(unable to read response)"
        raise RuntimeError(
            f"Source HTTP error: status={exc.code}; "
            f"reason={str(exc.reason)[:200]}; bodySample={sample!r}"
        ) from exc
    except Exception as exc:
        raise RuntimeError(
            f"Source request failed: {type(exc).__name__}: {str(exc)[:300]}"
        ) from exc

    text = raw.decode("utf-8-sig", errors="replace").strip()

    if not text:
        raise ValueError(
            f"Source returned an empty response: HTTP {status}; "
            f"Content-Type={content_type}; bytes={len(raw)}"
        )

    # Prefer JSON when the entire response is valid JSON.
    try:
        payload = json.loads(text)
        response_format = "JSON"
    except json.JSONDecodeError:
        # The configured API currently returns lines such as:
        # 172.105.121.230:443#SG
        # 146.190.87.188:443#SG
        #
        # Accept plain text only when it contains endpoint-like lines.
        lines = [
            line.strip()
            for line in text.splitlines()
            if line.strip() and not line.strip().startswith("#")
        ]

        endpoint_lines = [
            line for line in lines
            if parse_endpoint(line) is not None
        ]

        if not endpoint_lines:
            sample = " ".join(text[:500].split())
            raise ValueError(
                f"Source is neither valid JSON nor a recognized IP:port list. "
                f"HTTP {status}; Content-Type={content_type}; "
                f"bytes={len(raw)}; URL={final_url}; "
                f"bodySample={sample!r}"
            )

        payload = endpoint_lines
        response_format = "plain text"

    print(
        f"Source response: HTTP {status}; "
        f"Content-Type={content_type}; bytes={len(raw)}; "
        f"format={response_format}; URL={final_url}"
    )
    return payload, len(raw)


def parse_endpoint(item):
    ip = None
    port = None

    if isinstance(item, str):
        # Remove comments such as #SG or #JP-01-25ms.
        value = item.strip()
        if not value:
            return None

        # Accept whitespace-delimited lines containing multiple endpoints.
        # Normal single-endpoint lines are handled below.
        value = value.split("#", 1)[0].strip()

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
                "API JSON has no recognizable node list. "
                f"Top-level keys: {list(payload.keys())[:30]}"
            )

    else:
        raise ValueError(
            f"API response must be a list or object, "
            f"not {type(payload).__name__}"
        )

    nodes = []
    seen = set()

    for item in raw:
        node = parse_endpoint(item)

        if node and node["address"] not in seen:
            seen.add(node["address"])
            nodes.append(node)

    if not nodes:
        sample = repr(raw[:3])[:600] if isinstance(raw, list) else repr(raw)[:600]
        raise ValueError(
            "No valid IP:port candidates parsed. "
            f"Sample={sample}. Check the source format."
        )

    return nodes


def test_tcp(node):
    started = time.perf_counter()

    result = {
        **node,
        "ok": False,
        "latencyMs": None,
        "testedAt": now().isoformat().replace("+00:00", "Z"),
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
        print(
            f"WARNING: Cannot read previous cache {path}: {exc}",
            file=sys.stderr,
        )

    return []


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
<p>Each scheduled run scans one region and up to the configured batch size.
Previous successful measurements are retained when retests fail.</p>
</body>
</html>
"""
    (OUT / "index.html").write_text(html, encoding="utf-8")


def main():
    if not REGIONS:
        raise RuntimeError("REGIONS is empty")

    OUT.mkdir(parents=True, exist_ok=True)
    DATA.mkdir(parents=True, exist_ok=True)

    slot = slot_number()
    region = REGIONS[slot % len(REGIONS)]
    round_no = slot // len(REGIONS)

    source_url = SOURCE_URL + region
    print(f"Starting region={region}")
    print(f"Source URL={source_url}")

    payload, source_bytes = fetch_json(source_url)
    candidates = candidates_from(payload)

    start = (round_no * BATCH_SIZE) % len(candidates)
    count = min(BATCH_SIZE, len(candidates))
    batch = [
        candidates[(start + i) % len(candidates)]
        for i in range(count)
    ]

    print(
        f"region={region}; candidates={len(candidates)}; "
        f"sourceBytes={source_bytes}; start={start}; testing={len(batch)}"
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=CONCURRENCY
    ) as pool:
        results = list(pool.map(test_tcp, batch))

    successful = [result for result in results if result["ok"]]
    failed_count = len(results) - len(successful)

    print(
        f"tested={len(results)}; success={len(successful)}; "
        f"failed={failed_count}"
    )

    # Retain previous successful records. Failed retests do not erase them.
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

    nodes = sorted(
        merged.values(),
        key=lambda n: (
            float(n["latencyMs"]),
            n["ip"],
            int(n["port"]),
        ),
    )[:500]

    lines = []
    for index, node in enumerate(nodes, 1):
        ms = max(0, round(float(node["latencyMs"])))
        lines.append(
            f'{node["ip"]}:{node["port"]}#{region}-{index:02d}-{ms}ms'
        )

    txt_path = OUT / f"{region.lower()}.txt"
    txt_path.write_text(
        ("\n".join(lines) + "\n") if lines else "",
        encoding="utf-8",
    )

    record = {
        "region": region,
        "source": "github-actions",
        "updatedAt": now().isoformat().replace("+00:00", "Z"),
        "candidateCount": len(candidates),
        "batchStartIndex": start,
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

    build_index()

    print(
        f"Wrote {txt_path} with {len(lines)} successful cached nodes; "
        f"JSON={json_path}"
    )


if __name__ == "__main__":
    try:
        main()
    except Exception as exc:
        print(
            f"ERROR: {type(exc).__name__}: {exc}",
            file=sys.stderr,
        )
        sys.exit(1)
