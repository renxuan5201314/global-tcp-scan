
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regional proxy latency scanner.

Features:
- Fetch nodes from proxy.seeck.cn regional APIs.
- Use the site's reported responseTime API as the latency source.
- Test each endpoint 3 times and use the median latency.
- Keep the best 30 endpoints for each source region.
- Preserve old TXT files when a scan fails or looks incomplete.
- Atomic file replacement.
- Detailed logging and JSON diagnostics.

Important:
The exact request/response schema of the site's JavaScript API must be
verified against the original source. This script deliberately does not
fall back to TCP-connect timing when the API request fails.
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
import urllib.error
import urllib.parse
import urllib.request

from collections import Counter
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
# A region must have at least this many successful endpoints before
# replacing its existing output. Set to 1 if small result sets are valid.
MIN_SUCCESS_RESULTS = 3

# If an existing list has many entries, require a reasonable number
# of successful results before replacing it.
MIN_SUCCESS_RATIO = 0.10

USER_AGENT = "regional-proxy-latency-scanner/2.0"

# Optional API response keys that may contain the latency result.
# "responseTime" is the expected key mentioned in the site's JS.
LATENCY_KEYS = ("responseTime",)

# Only accept plausible, finite, non-negative latency values.
MAX_ACCEPTABLE_LATENCY_MS = 120000

# If True, save per-endpoint measurements and error diagnostics.
WRITE_DIAGNOSTICS = True


# -------------------- Logging --------------------

PUBLIC.mkdir(parents=True, exist_ok=True)
LOG_DIR.mkdir(parents=True, exist_ok=True)
DATA_DIR.mkdir(parents=True, exist_ok=True)

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
    Write to a temporary file in the same directory, then atomically replace.
    The previous file remains untouched if writing fails before os.replace().
    """
    path = Path(path)
    path.parent.mkdir(parents=True, exist_ok=True)
    temp_path = path.with_name(path.name + f".tmp-{os.getpid()}")

    try:
        with temp_path.open("w", encoding="utf-8", newline="\n") as handle:
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
        sort_keys=False,
    ) + "\n"
    atomic_write_text(path, content)


# -------------------- Node discovery --------------------

ENDPOINT_PATTERN = re.compile(
    r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})\s*:\s*(\d{1,5})(?!\d)"
)


def extract_endpoints(text):
    """
    Extract unique IPv4:port endpoints from JSON or plain-text API responses.
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
    url = NODE_API + urllib.parse.quote(region, safe="")
    log.info("[%s] Fetching candidates: %s", region, url)

    text = http_get_text(url, NODE_API_TIMEOUT)

    # JSON responses are serialized again to make nested endpoint fields
    # searchable. If the response is not JSON, scan the original text.
    try:
        payload = json.loads(text)
        searchable_text = json.dumps(payload, ensure_ascii=False)
    except json.JSONDecodeError:
        searchable_text = text

    endpoints = extract_endpoints(searchable_text)

    if not endpoints:
        raise RuntimeError(
            "API returned no valid IPv4:port endpoints; old output retained"
        )

    log.info("[%s] Found %d unique endpoints", region, len(endpoints))
    return endpoints


# -------------------- Site latency API --------------------

def parse_latency_value(value):
    """
    Parse the site's responseTime value into milliseconds.

    Numeric values are interpreted as milliseconds.
    Strings such as '123ms' are accepted.
    Seconds are NOT inferred from a numeric value; that must be established
    from the site's source/API contract.
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
            f"Unsupported responseTime type: {type(value).__name__}"
        )

    if not math.isfinite(latency):
        raise ValueError("responseTime is not finite")

    if latency < 0 or latency > MAX_ACCEPTABLE_LATENCY_MS:
        raise ValueError(f"responseTime out of range: {latency}")

    return latency


def find_response_time(payload):
    """
    Locate responseTime in common JSON response layouts.

    This does not invent a latency value. If responseTime is not present,
    the measurement is considered failed.
    """
    if isinstance(payload, dict):
        for key in LATENCY_KEYS:
            if key in payload:
                return parse_latency_value(payload[key])

        # Common wrappers sometimes put the actual response inside data/result.
        # Search only these explicit wrapper objects.
        for wrapper_key in ("data", "result"):
            nested = payload.get(wrapper_key)
            if isinstance(nested, dict):
                for key in LATENCY_KEYS:
                    if key in nested:
                        return parse_latency_value(nested[key])

    raise ValueError(
        "Could not find responseTime in API JSON; "
        "verify the exact response structure against the site's JavaScript"
    )


def probe_once(ip, port):
    """
    Make one request to the site's latency API for an endpoint.

    The endpoint is passed as the proxyip query parameter.
    The API URL and query format must be checked against the original JS.
    """
    endpoint = f"{ip}:{port}"
    query = urllib.parse.urlencode({"proxyip": endpoint})
    url = f"{SPEED_API}{query}"

    started = time.perf_counter()

    try:
        text = http_get_text(url, SPEED_API_TIMEOUT)
        elapsed_ms = (time.perf_counter() - started) * 1000

        try:
            payload = json.loads(text)
        except json.JSONDecodeError as error:
            raise ValueError(
                f"Latency API returned non-JSON content: {text[:200]!r}"
            ) from error

        latency_ms = find_response_time(payload)

        return {
            "ok": True,
            "latency_ms": latency_ms,
            "api_elapsed_ms": round(elapsed_ms, 2),
            "error": None,
        }

    except Exception as error:
        elapsed_ms = (time.perf_counter() - started) * 1000
        return {
            "ok": False,
            "latency_ms": None,
            "api_elapsed_ms": round(elapsed_ms, 2),
            "error": f"{type(error).__name__}: {error}",
        }


def probe_endpoint(ip, port):
    """
    Test an endpoint REPEAT_COUNT times.

    The ranking latency is the median of successful responseTime readings.
    An endpoint is accepted only if all three measurements succeed, to avoid
    ranking unstable or partially measured endpoints as if fully verified.
    """
    measurements = []
    errors = []

    for attempt in range(1, REPEAT_COUNT + 1):
        result = probe_once(ip, port)

        if result["ok"]:
            measurements.append(result["latency_ms"])
        else:
            errors.append({
                "attempt": attempt,
                "error": result["error"],
            })

        # Small pause between requests to reduce accidental burst pressure.
        if attempt < REPEAT_COUNT:
            time.sleep(0.15)

    complete = len(measurements) == REPEAT_COUNT

    record = {
        "ip": ip,
        "port": port,
        "endpoint": f"{ip}:{port}",
        "attempts_requested": REPEAT_COUNT,
        "attempts_succeeded": len(measurements),
        "measurements_ms": measurements,
        "errors": errors,
        "complete": complete,
        "latency_ms": (
            round(statistics.median(measurements), 2)
            if complete
            else None
        ),
        "minimum_ms": (
            round(min(measurements), 2) if complete else None
        ),
        "maximum_ms": (
            round(max(measurements), 2) if complete else None
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

        for future in concurrent.futures.as_completed(future_to_endpoint):
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
                    "measurements_ms": [],
                    "errors": [
                        {"error": f"Unhandled exception: {error}"}
                    ],
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

    successful = [r for r in records if r["complete"]]
    elapsed = round(time.monotonic() - started, 2)

    log.info(
        "[%s] Scan finished: candidates=%d complete=%d incomplete=%d elapsed=%.2fs",
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
    Refuse to replace an existing file when results appear incomplete.

    This is a safety threshold, not proof that the remote service measured
    every endpoint correctly.
    """
    candidate_count = len(endpoints)
    success_records = [r for r in records if r.get("complete")]
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
            line for line in target.read_text(
                encoding="utf-8", errors="replace"
            ).splitlines()
            if line.strip()
        ]

        # If a previous list had many entries, reject a dramatically smaller
        # scan unless the current scan has a reasonable success ratio.
        if len(old_lines) >= TOP_N and success_ratio < MIN_SUCCESS_RATIO:
            raise RuntimeError(
                f"Suspiciously low success ratio {success_ratio:.1%}; "
                "existing output retained"
            )

    if not success_records:
        raise RuntimeError("No complete latency records")

    # Ensure all output endpoints were among the discovered candidates.
    candidate_set = set(endpoints)
    for record in success_records:
        key = (record["ip"], record["port"])
        if key not in candidate_set:
            raise RuntimeError(
                f"Unexpected endpoint in results: {record['endpoint']}"
            )

    return success_records, success_ratio


def build_txt(region, best):
    lines = []

    for rank, record in enumerate(best, start=1):
        latency = record["latency_ms"]
        ip = record["ip"]
        port = record["port"]

        # Preserve the original subscription-compatible line format.
        lines.append(
            f"{ip}:{port}#{region}-{rank:02d}-{latency:.0f}ms"
        )

    return "\n".join(lines) + "\n"


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
            1 for record in records if record["complete"]
        )
        diagnostic["incomplete_count"] = (
            len(records) - diagnostic["complete_count"]
        )
        diagnostic["results"] = records

        successful, success_ratio = validate_results(
            region, endpoints, records, target
        )
        diagnostic["success_ratio"] = round(success_ratio, 4)

        best = sorted(
            successful,
            key=lambda record: (
                record["latency_ms"],
                record["spread_ms"],
                tuple(int(part) for part in record["ip"].split(".")),
                record["port"],
            ),
        )[:TOP_N]

        if not best:
            raise RuntimeError("No ranked results after validation")

        content = build_txt(region, best)

        # Validate the complete content before replacing the previous file.
        lines = [line for line in content.splitlines() if line.strip()]
        if not lines:
            raise RuntimeError("Generated TXT content is empty")

        for line in lines:
            if "#" not in line or ":" not in line:
                raise RuntimeError(f"Malformed output line: {line!r}")

        # Atomic replacement: old file remains intact if writing fails.
        atomic_write_text(target, content)

        diagnostic["status"] = "success"
        diagnostic["output_count"] = len(lines)
        diagnostic["output_file"] = str(target.relative_to(ROOT))
        diagnostic["finished_at"] = datetime.now(timezone.utc).isoformat()

        log.info(
            "[%s] Updated %s with %d entries (success ratio %.1f%%)",
            region,
            target.name,
            len(lines),
            success_ratio * 100,
        )

    except Exception as error:
        diagnostic["status"] = "failed"
        diagnostic["error"] = f"{type(error).__name__}: {error}"
        diagnostic["finished_at"] = datetime.now(timezone.utc).isoformat()

        log.exception(
            "[%s] Failed; existing output retained: %s",
            region,
            error,
        )

    finally:
        if WRITE_DIAGNOSTICS:
            try:
                atomic_write_json(diagnostic_path, diagnostic)
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
            "Previous TXT files were retained. Check logs/scanner.log "
            "and public/data/*.json."
        )


if __name__ == "__main__":
    main()
