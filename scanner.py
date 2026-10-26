#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regional proxy latency scanner.

Features:
- Fetch nodes from proxy.seeck.cn regional APIs.
- Measure latency using the site's responseTime API.
- Require success=True and probe_results.ipv4.ok=True.
- Test each endpoint 3 times and use the median latency.
- Keep the best 30 endpoints for each source region.
- Preserve old TXT files when a scan fails or looks incomplete.
- Atomic file replacement.
- Detailed logging and JSON diagnostics.

Latency source:
    https://api.090227.xyz/check?proxyip=IP:PORT

Important:
- Does not fall back to local TCP-connect timing.
- responseTime is the ranking latency.
- The API's own success and IPv4 probe status must both be successful.
"""

import concurrent.futures
import ipaddress
import json
import logging
import math
import os
import re
import statistics
import time
import urllib.parse
import urllib.request

from datetime import datetime, timezone
from pathlib import Path


# -------------------- Configuration --------------------

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
LOG_DIR = ROOT / "logs"
DATA_DIR = PUBLIC / "data"

REGIONS = ("JP", "HK", "KR", "CN", "US", "SG", "DE")

NODE_API = "https://proxy.seeck.cn/api/nodes?region="
SPEED_API = "https://api.090227.xyz/check?proxyip="

TOP_N = 30
REPEAT_COUNT = 3

# Avoid overloading the remote service.
MAX_WORKERS = 4

NODE_API_TIMEOUT = 30
SPEED_API_TIMEOUT = 30

# Protect old files against suspiciously incomplete scans.
MIN_SUCCESS_RESULTS = 3
MIN_SUCCESS_RATIO = 0.10

USER_AGENT = "regional-proxy-latency-scanner/2.1"

MAX_ACCEPTABLE_LATENCY_MS = 120000

WRITE_DIAGNOSTICS = True

# Delay between repeated requests to the same endpoint.
REPEAT_DELAY_SECONDS = 0.15


# -------------------- Directory setup --------------------

PUBLIC.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)


# -------------------- Logging --------------------

log_file = LOG_DIR / "scanner.log"

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(log_file, encoding="utf-8"),
    ],
)

log = logging.getLogger("regional-scanner")


# -------------------- HTTP helpers --------------------

def http_get_text(url, timeout):
    """GET a URL and return decoded response text."""
    request = urllib.request.Request(
        url,
        headers={
            "User-Agent": USER_AGENT,
            "Accept": "application/json, text/plain, */*",
        },
        method="GET",
    )

    with urllib.request.urlopen(request, timeout=timeout) as response:
        status = getattr(response, "status", 200)

        if status < 200 or status >= 300:
            raise RuntimeError(f"HTTP status {status}")

        raw = response.read()
        charset = response.headers.get_content_charset() or "utf-8"

        return raw.decode(charset, errors="replace")


def atomic_write_text(path, content):
    """
    Write a temporary file in the same directory and atomically replace
    the destination only after the write completes successfully.
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)

    temp_path = path.with_name(
        path.name + f".tmp-{os.getpid()}-{time.time_ns()}"
    )

    try:
        with temp_path.open(
            "w",
            encoding="utf-8",
            newline="\n",
        ) as handle:
            handle.write(content)
            handle.flush()
            os.fsync(handle.fileno())

        os.replace(temp_path, path)

    finally:
        try:
            temp_path.unlink(missing_ok=True)
        except OSError:
            pass


def atomic_write_json(path, data):
    content = json.dumps(
        data,
        ensure_ascii=False,
        indent=2,
    ) + "\n"

    atomic_write_text(path, content)


# -------------------- Node discovery --------------------

ENDPOINT_PATTERN = re.compile(
    r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})\s*:\s*(\d{1,5})(?!\d)"
)


def extract_endpoints(text):
    """
    Extract unique IPv4:port endpoints from a JSON or plain-text response.

    Note:
    This uses endpoint-pattern extraction because the precise node JSON
    schema has not been supplied here. If the source contains unrelated
    IPv4:port strings, those could also be extracted.
    """
    found = set()

    for match in ENDPOINT_PATTERN.finditer(text):
        ip_text, port_text = match.groups()

        try:
            ip = str(ipaddress.IPv4Address(ip_text))
            port = int(port_text)

            if not 1 <= port <= 65535:
                continue

            found.add((ip, port))

        except ValueError:
            continue

    return sorted(
        found,
        key=lambda item: (
            tuple(int(part) for part in item[0].split(".")),
            item[1],
        ),
    )


def fetch_region(region):
    """Fetch candidates for one source region."""
    url = NODE_API + urllib.parse.quote(region, safe="")

    log.info("[%s] Fetching candidates: %s", region, url)

    text = http_get_text(url, NODE_API_TIMEOUT)

    try:
        payload = json.loads(text)
        searchable_text = json.dumps(
            payload,
            ensure_ascii=False,
        )
    except json.JSONDecodeError:
        searchable_text = text

    endpoints = extract_endpoints(searchable_text)

    if not endpoints:
        raise RuntimeError(
            "API returned no valid IPv4:port endpoints; "
            "existing output retained"
        )

    log.info(
        "[%s] Found %d unique endpoints",
        region,
        len(endpoints),
    )

    return endpoints


# -------------------- Site latency API --------------------

def parse_latency_value(value):
    """
    Parse responseTime into milliseconds.

    Numeric values are interpreted as milliseconds.
    Strings such as '123ms' are also accepted.
    """
    if isinstance(value, bool) or value is None:
        raise ValueError("responseTime is missing or invalid")

    if isinstance(value, (int, float)):
        latency = float(value)

    elif isinstance(value, str):
        cleaned = value.strip().lower()
        cleaned = re.sub(r"\s*ms\s*$", "", cleaned)
        latency = float(cleaned)

    else:
        raise ValueError(
            "Unsupported responseTime type: "
            f"{type(value).__name__}"
        )

    if not math.isfinite(latency):
        raise ValueError("responseTime is not finite")

    if latency < 0 or latency > MAX_ACCEPTABLE_LATENCY_MS:
        raise ValueError(
            f"responseTime out of range: {latency}"
        )

    return latency


def find_response_time(payload):
    """
    Validate the known API response structure.

    A response is accepted only if:
    - payload is a JSON object;
    - success is exactly True;
    - probe_results.ipv4 exists;
    - probe_results.ipv4.ok is exactly True;
    - responseTime is present and valid.

    The ranking latency comes from responseTime, not local HTTP elapsed time.
    """
    if not isinstance(payload, dict):
        raise ValueError("Latency API response is not a JSON object")

    if payload.get("success") is not True:
        raise ValueError(
            "Latency API did not report success=True; "
            f"received {payload.get('success')!r}"
        )

    probe_results = payload.get("probe_results")

    if not isinstance(probe_results, dict):
        raise ValueError("Missing or invalid probe_results")

    ipv4_result = probe_results.get("ipv4")

    if not isinstance(ipv4_result, dict):
        raise ValueError("Missing or invalid probe_results.ipv4")

    if ipv4_result.get("ok") is not True:
        raise ValueError(
            "IPv4 probe failed; "
            f"error={ipv4_result.get('error')!r}"
        )

    if "responseTime" not in payload:
        raise ValueError("Missing responseTime")

    return parse_latency_value(payload["responseTime"])


def probe_once(ip, port):
    """
    Ask the site's latency API to measure one endpoint.

    Local API request duration is recorded for diagnostics only.
    It is never used as the endpoint ranking latency.
    """
    endpoint = f"{ip}:{port}"

    query = urllib.parse.urlencode({
        "proxyip": endpoint,
    })

    url = f"{SPEED_API}{query}"
    started = time.perf_counter()

    try:
        text = http_get_text(url, SPEED_API_TIMEOUT)

        elapsed_ms = (
            time.perf_counter() - started
        ) * 1000

        try:
            payload = json.loads(text)

        except json.JSONDecodeError as error:
            raise ValueError(
                "Latency API returned non-JSON content: "
                f"{text[:200]!r}"
            ) from error

        latency_ms = find_response_time(payload)

        return {
            "ok": True,
            "latency_ms": latency_ms,
            "api_elapsed_ms": round(elapsed_ms, 2),
            "api_success": payload.get("success"),
            "ipv4_probe_ok": (
                payload.get("probe_results", {})
                .get("ipv4", {})
                .get("ok")
            ),
            "colo": payload.get("colo"),
            "error": None,
        }

    except Exception as error:
        elapsed_ms = (
            time.perf_counter() - started
        ) * 1000

        return {
            "ok": False,
            "latency_ms": None,
            "api_elapsed_ms": round(elapsed_ms, 2),
            "api_success": None,
            "ipv4_probe_ok": None,
            "colo": None,
            "error": f"{type(error).__name__}: {error}",
        }


def probe_endpoint(ip, port):
    """
    Test an endpoint REPEAT_COUNT times.

    All attempts must succeed. The median responseTime is used for ranking.
    """
    measurements = []
    attempts = []
    errors = []

    for attempt in range(1, REPEAT_COUNT + 1):
        result = probe_once(ip, port)

        attempts.append({
            "attempt": attempt,
            "ok": result["ok"],
            "latency_ms": result["latency_ms"],
            "api_elapsed_ms": result["api_elapsed_ms"],
            "api_success": result["api_success"],
            "ipv4_probe_ok": result["ipv4_probe_ok"],
            "colo": result["colo"],
            "error": result["error"],
        })

        if result["ok"]:
            measurements.append(result["latency_ms"])
        else:
            errors.append({
                "attempt": attempt,
                "error": result["error"],
            })

        if attempt < REPEAT_COUNT:
            time.sleep(REPEAT_DELAY_SECONDS)

    complete = len(measurements) == REPEAT_COUNT

    record = {
        "ip": ip,
        "port": port,
        "endpoint": f"{ip}:{port}",
        "attempts_requested": REPEAT_COUNT,
        "attempts_succeeded": len(measurements),
        "attempts": attempts,
        "measurements_ms": measurements,
        "errors": errors,
        "complete": complete,
        "latency_ms": (
            round(statistics.median(measurements), 2)
            if complete
            else None
        ),
        "minimum_ms": (
            round(min(measurements), 2)
            if complete
            else None
        ),
        "maximum_ms": (
            round(max(measurements), 2)
            if complete
            else None
        ),
        "spread_ms": (
            round(max(measurements) - min(measurements), 2)
            if complete
            else None
        ),
    }

    return record


# -------------------- Region scanning --------------------

def scan_region(region, endpoints):
    """Measure all endpoints in a region concurrently."""
    started = time.monotonic()
    records = []

    log.info(
        "[%s] Starting measurements: endpoints=%d, repeats=%d, workers=%d",
        region,
        len(endpoints),
        REPEAT_COUNT,
        MAX_WORKERS,
    )

    with concurrent.futures.ThreadPoolExecutor(
        max_workers=MAX_WORKERS
    ) as executor:

        future_to_endpoint = {
            executor.submit(probe_endpoint, ip, port): (ip, port)
            for ip, port in endpoints
        }

        completed = 0
        total = len(future_to_endpoint)

        for future in concurrent.futures.as_completed(
            future_to_endpoint
        ):
            ip, port = future_to_endpoint[future]
            completed += 1

            try:
                record = future.result()

            except Exception as error:
                record = {
                    "ip": ip,
                    "port": port,
                    "endpoint": f"{ip}:{port}",
                    "attempts_requested": REPEAT_COUNT,
                    "attempts_succeeded": 0,
                    "attempts": [],
                    "measurements_ms": [],
                    "errors": [{
                        "error": f"Unhandled exception: {error}",
                    }],
                    "complete": False,
                    "latency_ms": None,
                    "minimum_ms": None,
                    "maximum_ms": None,
                    "spread_ms": None,
                }

            record["region"] = region
            records.append(record)

            if record["complete"]:
                log.info(
                    "[%s] [%d/%d] %s latency=%.2fms spread=%.2fms",
                    region,
                    completed,
                    total,
                    record["endpoint"],
                    record["latency_ms"],
                    record["spread_ms"],
                )
            else:
                log.warning(
                    "[%s] [%d/%d] %s incomplete: %d/%d successful attempts",
                    region,
                    completed,
                    total,
                    record["endpoint"],
                    record["attempts_succeeded"],
                    REPEAT_COUNT,
                )

    successful = [
        record for record in records
        if record["complete"]
    ]

    elapsed = round(time.monotonic() - started, 2)

    log.info(
        "[%s] Scan finished: candidates=%d complete=%d "
        "incomplete=%d elapsed=%.2fs",
        region,
        len(endpoints),
        len(successful),
        len(records) - len(successful),
        elapsed,
    )

    return records


# -------------------- Output validation --------------------

def validate_results(region, endpoints, records, target):
    """
    Refuse to replace an existing output when results appear incomplete.
    """
    candidate_count = len(endpoints)

    success_records = [
        record for record in records
        if record.get("complete")
    ]

    success_count = len(success_records)

    if candidate_count == 0:
        raise RuntimeError("No candidates were discovered")

    if success_count < MIN_SUCCESS_RESULTS:
        raise RuntimeError(
            f"Only {success_count} complete results; "
            f"minimum required is {MIN_SUCCESS_RESULTS}"
        )

    success_ratio = success_count / candidate_count

    if target.is_file() and target.stat().st_size > 0:
        old_lines = [
            line
            for line in target.read_text(
                encoding="utf-8",
                errors="replace",
            ).splitlines()
            if line.strip()
        ]

        if (
            len(old_lines) >= TOP_N
            and success_ratio < MIN_SUCCESS_RATIO
        ):
            raise RuntimeError(
                f"Suspiciously low success ratio "
                f"{success_ratio:.1%}; existing output retained"
            )

    if not success_records:
        raise RuntimeError("No complete latency records")

    candidate_set = set(endpoints)

    for record in success_records:
        key = (record["ip"], record["port"])

        if key not in candidate_set:
            raise RuntimeError(
                f"Unexpected endpoint in results: {record['endpoint']}"
            )

    return success_records, success_ratio


# -------------------- TXT generation --------------------

def build_txt(region, best):
    """
    Build subscription-compatible TXT lines.

    Example:
        129.154.212.204:443#JP-01-133ms
    """
    lines = []

    for rank, record in enumerate(best, start=1):
        latency = record["latency_ms"]

        lines.append(
            f"{record['ip']}:{record['port']}"
            f"#{region}-{rank:02d}-{latency:.0f}ms"
        )

    return "\n".join(lines) + "\n"


# -------------------- Region processing --------------------

def process_region(region):
    target = PUBLIC / f"{region.lower()}.txt"
    diagnostic_path = DATA_DIR / f"{region.lower()}.json"

    started_at = datetime.now(timezone.utc).isoformat()

    diagnostic = {
        "region": region,
        "started_at": started_at,
        "node_api": NODE_API + region,
        "speed_api": SPEED_API,
        "repeat_count": REPEAT_COUNT,
        "top_n": TOP_N,
        "status": "failed",
        "candidate_count": 0,
        "complete_count": 0,
        "incomplete_count": 0,
        "success_ratio": 0,
        "results": [],
        "error": None,
    }

    log.info("========== %s ==========", region)

    try:
        endpoints = fetch_region(region)

        diagnostic["candidate_count"] = len(endpoints)

        records = scan_region(region, endpoints)

        diagnostic["complete_count"] = sum(
            1 for record in records
            if record["complete"]
        )

        diagnostic["incomplete_count"] = (
            len(records) - diagnostic["complete_count"]
        )

        diagnostic["results"] = records

        successful, success_ratio = validate_results(
            region,
            endpoints,
            records,
            target,
        )

        diagnostic["success_ratio"] = round(
            success_ratio,
            4,
        )

        best = sorted(
            successful,
            key=lambda record: (
                record["latency_ms"],
                record["spread_ms"],
                tuple(
                    int(part)
                    for part in record["ip"].split(".")
                ),
                record["port"],
            ),
        )[:TOP_N]

        if not best:
            raise RuntimeError(
                "No ranked results after validation"
            )

        content = build_txt(region, best)

        # Validate generated TXT content before replacing the old file.
        lines = [
            line for line in content.splitlines()
            if line.strip()
        ]

        if not lines:
            raise RuntimeError("Generated TXT content is empty")

        for line in lines:
            if "#" not in line or ":" not in line:
                raise RuntimeError(
                    f"Malformed output line: {line!r}"
                )

        # Existing TXT is replaced only after all checks pass.
        atomic_write_text(target, content)

        diagnostic["status"] = "success"
        diagnostic["output_count"] = len(lines)
        diagnostic["output_file"] = str(
            target.relative_to(ROOT)
        )
        diagnostic["finished_at"] = (
            datetime.now(timezone.utc).isoformat()
        )

        log.info(
            "[%s] Updated %s with %d entries "
            "(success ratio %.1f%%)",
            region,
            target.name,
            len(lines),
            success_ratio * 100,
        )

    except Exception as error:
        diagnostic["status"] = "failed"
        diagnostic["error"] = (
            f"{type(error).__name__}: {error}"
        )
        diagnostic["finished_at"] = (
            datetime.now(timezone.utc).isoformat()
        )

        log.exception(
            "[%s] Failed; existing output retained: %s",
            region,
            error,
        )

    finally:
        if WRITE_DIAGNOSTICS:
            try:
                atomic_write_json(
                    diagnostic_path,
                    diagnostic,
                )
            except Exception:
                log.exception(
                    "[%s] Failed to write diagnostics JSON",
                    region,
                )

    return diagnostic["status"] == "success"


# -------------------- Main --------------------

def main():
    log.info("Regional latency scan started")

    log.info(
        "Regions=%s top_n=%d repeats=%d workers=%d",
        ",".join(REGIONS),
        TOP_N,
        REPEAT_COUNT,
        MAX_WORKERS,
    )

    successful_regions = 0

    for region in REGIONS:
        if process_region(region):
            successful_regions += 1

    log.info(
        "Finished: %d/%d regions updated",
        successful_regions,
        len(REGIONS),
    )

    if successful_regions == 0:
        raise SystemExit(
            "ERROR: no region produced a valid new output. "
            "Previous TXT files were retained. Check "
            "logs/scanner.log and public/data/*.json."
        )


if __name__ == "__main__":
    main()
