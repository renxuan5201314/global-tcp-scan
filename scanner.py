```python
#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""
Regional Cloudflare IP scanner using official XIU2/CloudflareSpeedTest HTTPing.

Requirements:
- Put CloudflareST.exe or cfst.exe beside this script on Windows.
- Fetch candidates from proxy.seeck.cn for seven regions.
- Test every candidate IP using official CFST HTTPing.
- Keep the 30 lowest average-latency IPs per region.
- Preserve TXT format, atomic writes, detailed logs and JSON diagnostics.
- Never replace an existing TXT when a scan fails validation.
"""

import csv
import ipaddress
import json
import logging
import os
import re
import shutil
import subprocess
import time
import urllib.parse
import urllib.request

from datetime import datetime, timezone
from pathlib import Path


# ==================== Configuration ====================

ROOT = Path(__file__).resolve().parent
PUBLIC = ROOT / "public"
LOG_DIR = ROOT / "logs"
DATA_DIR = PUBLIC / "data"
WORK_DIR = ROOT / "work_cfst"

REGIONS = ("JP", "HK", "KR", "CN", "US", "SG", "DE")

NODE_API = "https://proxy.seeck.cn/api/nodes?region="
USER_AGENT = "regional-cfst-httping-scanner/3.0"

TOP_N = 30
REPEAT_COUNT = 3
MAX_WORKERS = 10

NODE_API_TIMEOUT = 30
CFST_TIMEOUT_SECONDS = 3600

HTTPING_URL = "https://cf.xiu2.xyz/url"
HTTPING_PORT = 443

# Reject a scan if too few IPs were measured successfully.
MIN_SUCCESS_RESULTS = 3
MIN_SUCCESS_RATIO = 0.10

# If an old TXT exists, do not replace it with fewer than this many entries.
MIN_OUTPUT_COUNT = 3

WRITE_DIAGNOSTICS = True

# Usually leave empty. Auto-detection checks the script directory and PATH.
# Example: r"D:\Tools\CloudflareST.exe"
CFST_EXECUTABLE = ""

IP_PATTERN = re.compile(
    r"(?<![\d.])(?:\d{1,3}\.){3}\d{1,3}(?![\d.])"
)
ENDPOINT_PATTERN = re.compile(
    r"(?<![\d.])((?:\d{1,3}\.){3}\d{1,3})\s*:\s*(\d{1,5})(?!\d)"
)


# ==================== Directories and logging ====================

for directory in (PUBLIC, LOG_DIR, DATA_DIR, WORK_DIR):
    directory.mkdir(parents=True, exist_ok=True)

logging.basicConfig(
    level=logging.INFO,
    format="%(asctime)s %(levelname)s %(message)s",
    handlers=[
        logging.StreamHandler(),
        logging.FileHandler(
            LOG_DIR / "scanner.log",
            encoding="utf-8",
        ),
    ],
)
log = logging.getLogger("regional-cfst-scanner")


# ==================== Atomic file writes ====================

def atomic_write_text(path, content):
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
    atomic_write_text(
        path,
        json.dumps(data, ensure_ascii=False, indent=2) + "\n",
    )


# ==================== HTTP helpers ====================

def http_get_text(url, timeout):
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

        if not 200 <= status < 300:
            raise RuntimeError(f"HTTP status {status}: {url}")

        raw = response.read()
        charset = response.headers.get_content_charset() or "utf-8"

        return raw.decode(charset, errors="replace")


# ==================== Candidate discovery ====================

def valid_ip(value):
    try:
        return str(ipaddress.IPv4Address(str(value).strip()))
    except (ValueError, TypeError):
        return None


def valid_port(value, default=443):
    try:
        port = int(value)
        return port if 1 <= port <= 65535 else default
    except (ValueError, TypeError):
        return default


def extract_endpoint_string(value, results):
    if not isinstance(value, str):
        return

    for match in ENDPOINT_PATTERN.finditer(value):
        ip = valid_ip(match.group(1))
        port = valid_port(match.group(2), default=0)

        if ip and port:
            results.add((ip, port))


def walk_node_json(value, results):
    """
    Parse structured node records instead of regex-scanning serialized JSON.
    Recognizes common IP, host, address, endpoint and port fields.
    """
    if isinstance(value, list):
        for item in value:
            walk_node_json(item, results)
        return

    if not isinstance(value, dict):
        if isinstance(value, str):
            extract_endpoint_string(value, results)
        return

    lowered = {str(k).lower(): v for k, v in value.items()}

    # Find an address-like field in this object.
    address = None
    for key in (
        "endpoint", "proxyip", "proxy_ip", "ip_port",
        "ipport", "address", "addr", "ip", "ipv4",
        "host", "server",
    ):
        candidate = lowered.get(key)
        if isinstance(candidate, str) and candidate.strip():
            address = candidate.strip()
            break

    # Find a port field if the address did not already include one.
    port_value = 443
    for key in ("port", "portremote", "port_remote", "remoteport"):
        if key in lowered:
            port_value = lowered[key]
            break

    if address:
        if ENDPOINT_PATTERN.fullmatch(address):
            extract_endpoint_string(address, results)
        else:
            ip = valid_ip(address)
            if ip:
                results.add((ip, valid_port(port_value)))

    # Recurse into nested node collections.
    for key, child in value.items():
        if isinstance(child, (dict, list)):
            walk_node_json(child, results)
        elif isinstance(child, str):
            # Only accept explicit endpoint strings, not arbitrary IPs
            # appearing in unrelated metadata.
            if ENDPOINT_PATTERN.fullmatch(child.strip()):
                extract_endpoint_string(child.strip(), results)


def extract_endpoints(text):
    results = set()

    try:
        payload = json.loads(text)
    except json.JSONDecodeError:
        payload = None

    if payload is not None:
        walk_node_json(payload, results)
    else:
        # Plain-text fallback.
        for match in ENDPOINT_PATTERN.finditer(text):
            ip = valid_ip(match.group(1))
            port = valid_port(match.group(2), default=0)
            if ip and port:
                results.add((ip, port))

        # If the plain-text source consists of bare IPs, assume port 443.
        if not results:
            for match in IP_PATTERN.finditer(text):
                ip = valid_ip(match.group(0))
                if ip:
                    results.add((ip, 443))

    return sorted(
        results,
        key=lambda item: (
            tuple(int(part) for part in item[0].split(".")),
            item[1],
        ),
    )


def fetch_region(region):
    url = NODE_API + urllib.parse.quote(region, safe="")

    log.info("[%s] Fetching candidates: %s", region, url)

    text = http_get_text(url, NODE_API_TIMEOUT)
    endpoints = extract_endpoints(text)

    if not endpoints:
        raise RuntimeError(
            "No valid IPv4:port candidates found; existing TXT retained"
        )

    log.info(
        "[%s] Found %d candidate endpoints, %d unique IPs",
        region,
        len(endpoints),
        len({ip for ip, _ in endpoints}),
    )

    return endpoints


# ==================== Official CFST executable ====================

def resolve_cfst_executable():
    if CFST_EXECUTABLE:
        path = Path(CFST_EXECUTABLE)
        if path.is_file():
            return str(path.resolve())
        raise FileNotFoundError(
            f"CFST_EXECUTABLE does not exist: {path}"
        )

    names = (
        "CloudflareST.exe",
        "cfst.exe",
        "CloudflareSpeedTest.exe",
        "CloudflareST",
        "cfst",
        "CloudflareSpeedTest",
    )

    for name in names:
        path = ROOT / name
        if path.is_file():
            return str(path.resolve())

    for name in names:
        found = shutil.which(name)
        if found:
            return found

    raise FileNotFoundError(
        "Official CloudflareSpeedTest executable not found. "
        "Put CloudflareST.exe or cfst.exe beside scanner.py, "
        "or configure CFST_EXECUTABLE at the top of this file."
    )


def run_cfst(region, endpoints, executable):
    """
    Test every unique candidate IPv4 address using official CFST HTTPing.
    -allip is important: it prevents the default random-per-/24 behavior.
    """
    ips = sorted(
        {ip for ip, _port in endpoints},
        key=lambda value: tuple(int(p) for p in value.split(".")),
    )

    if not ips:
        raise RuntimeError("No IPv4 addresses to test")

    region_dir = WORK_DIR / region.lower()
    region_dir.mkdir(parents=True, exist_ok=True)

    input_path = region_dir / "candidates.txt"
    output_path = region_dir / "result.csv"
    stdout_path = region_dir / "cfst.stdout.log"
    stderr_path = region_dir / "cfst.stderr.log"

    atomic_write_text(input_path, "\n".join(ips) + "\n")

    try:
        output_path.unlink(missing_ok=True)
    except OSError as error:
        raise RuntimeError(
            f"Cannot clear previous CFST result file: {error}"
        ) from error

    command = [
        executable,
        "-f", str(input_path),
        "-allip",
        "-o", str(output_path),
        "-p", "0",
        "-n", str(MAX_WORKERS),
        "-t", str(REPEAT_COUNT),
        "-tp", str(HTTPING_PORT),
        "-httping",
        "-url", HTTPING_URL,
        "-dd",
        "-debug",
    ]

    log.info(
        "[%s] Starting official CFST HTTPing: IPs=%d, repeats=%d, "
        "workers=%d, port=%d, URL=%s",
        region,
        len(ips),
        REPEAT_COUNT,
        MAX_WORKERS,
        HTTPING_PORT,
        HTTPING_URL,
    )
    log.info(
        "[%s] Command: %s",
        region,
        subprocess.list2cmdline(command),
    )

    try:
        completed = subprocess.run(
            command,
            cwd=str(ROOT),
            capture_output=True,
            text=True,
            encoding="utf-8",
            errors="replace",
            timeout=CFST_TIMEOUT_SECONDS,
            check=False,
        )
    except subprocess.TimeoutExpired as error:
        raise RuntimeError(
            f"CFST timed out after {CFST_TIMEOUT_SECONDS} seconds"
        ) from error

    atomic_write_text(stdout_path, completed.stdout or "")
    atomic_write_text(stderr_path, completed.stderr or "")

    if completed.returncode != 0:
        raise RuntimeError(
            f"CFST exited with code {completed.returncode}; "
            f"inspect {stdout_path.relative_to(ROOT)} and "
            f"{stderr_path.relative_to(ROOT)}"
        )

    if not output_path.is_file() or output_path.stat().st_size == 0:
        raise RuntimeError(
            "CFST produced no CSV output; old TXT retained. "
            "Check the HTTPing URL, port and CFST logs."
        )

    ranked = parse_cfst_csv(output_path, ips)

    log.info(
        "[%s] CFST returned %d valid IP results out of %d candidates",
        region,
        len(ranked),
        len(ips),
    )

    return ranked


# ==================== Parse official CFST CSV ====================

def normalize_header(value):
    return re.sub(
        r"[\s_\-()（）]+",
        "",
        str(value).strip().lower(),
    )


def parse_latency_ms(value):
    text = str(value).strip().lower()
    text = text.replace("毫秒", "").replace("ms", "").strip()
    text = text.replace(",", "")

    latency = float(text)

    if latency < 0 or latency > 120000:
        raise ValueError(f"Latency out of range: {value!r}")

    return latency


def parse_cfst_csv(csv_path, candidate_ips):
    """
    Official CFST CSV commonly contains:
    IP 地址,已发送,已接收,丢包率,平均延迟,下载速度(MB/s),地区码

    Ranking uses the official average-latency column.
    """
    allowed_ips = set(candidate_ips)
    by_ip = {}

    with open(
        csv_path,
        "r",
        encoding="utf-8-sig",
        newline="",
    ) as handle:
        sample = handle.read(8192)
        handle.seek(0)

        try:
            dialect = csv.Sniffer().sniff(
                sample,
                delimiters=",;\t",
            )
        except csv.Error:
            dialect = csv.excel

        reader = csv.DictReader(handle)

        if not reader.fieldnames:
            raise RuntimeError("CFST CSV has no header")

        headers = {
            normalize_header(header): header
            for header in reader.fieldnames
        }

        ip_header = None
        latency_header = None
        loss_header = None

        for normalized, original in headers.items():
            if normalized in ("ip地址", "ip", "ipaddress", "address"):
                ip_header = original
                break

        for normalized, original in headers.items():
            if (
                normalized == "平均延迟"
                or normalized in ("averagelatency", "averagedelay")
            ):
                latency_header = original
                break

        for normalized, original in headers.items():
            if normalized in ("丢包率", "lossrate", "packetloss"):
                loss_header = original
                break

        if ip_header is None:
            ip_header = reader.fieldnames[0]

        if latency_header is None:
            raise RuntimeError(
                "Cannot find CFST average-latency column. "
                f"CSV headers: {reader.fieldnames!r}"
            )

        for row in reader:
            if not row:
                continue

            ip_cell = (row.get(ip_header) or "").strip()
            match = IP_PATTERN.search(ip_cell)

            if not match:
                continue

            ip = valid_ip(match.group(0))

            if not ip or ip not in allowed_ips:
                continue

            latency_cell = row.get(latency_header)

            try:
                latency = parse_latency_ms(latency_cell)
            except (ValueError, TypeError):
                continue

            loss_value = 0.0

            if loss_header and row.get(loss_header):
                raw_loss = str(row[loss_header]).strip()
                raw_loss = raw_loss.replace("%", "")

                try:
                    loss_value = float(raw_loss)
                    if "%" in str(row[loss_header]):
                        loss_value /= 100.0
                except ValueError:
                    continue

            # Reject rows that report packet loss. This avoids ranking
            # a low average latency when the IP is not consistently usable.
            if loss_value > 0:
                continue

            result = {
                "ip": ip,
                "latency_ms": round(latency, 2),
                "loss_rate": loss_value,
                "raw_csv": row,
            }

            previous = by_ip.get(ip)

            if previous is None or latency < previous["latency_ms"]:
                by_ip[ip] = result

    return sorted(
        by_ip.values(),
        key=lambda row: (
            row["latency_ms"],
            tuple(int(part) for part in row["ip"].split(".")),
        ),
    )


# ==================== Validation and TXT generation ====================

def validate_results(region, endpoints, ranked, target):
    candidate_ips = {ip for ip, _port in endpoints}

    valid = [
        row for row in ranked
        if row.get("ip") in candidate_ips
        and isinstance(row.get("latency_ms"), (int, float))
        and 0 <= row["latency_ms"] <= 120000
        and row.get("loss_rate", 0) == 0
    ]

    if len(valid) < MIN_SUCCESS_RESULTS:
        raise RuntimeError(
            f"Only {len(valid)} valid zero-loss results; "
            f"minimum required is {MIN_SUCCESS_RESULTS}. "
            "Old TXT retained."
        )

    success_ratio = len(valid) / max(1, len(candidate_ips))

    if target.is_file() and target.stat().st_size > 0:
        old_lines = [
            line for line in target.read_text(
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
                f"Suspicious success ratio {success_ratio:.1%}; "
                "old TXT retained."
            )

    if len(valid) < MIN_OUTPUT_COUNT:
        raise RuntimeError(
            f"Only {len(valid)} results available; "
            "old TXT retained."
        )

    return valid, success_ratio


def build_txt(region, ranked, endpoint_ports):
    lines = []

    for rank, row in enumerate(ranked[:TOP_N], start=1):
        ip = row["ip"]
        ports = endpoint_ports.get(ip, [443])

        # The confirmed use case is Cloudflare CDN on port 443.
        # If the source contains another port for the same IP, prefer 443.
        port = 443 if 443 in ports else ports[0]

        lines.append(
            f"{ip}:{port}"
            f"#{region}-{rank:02d}-{row['latency_ms']:.0f}ms"
        )

    return "\n".join(lines) + "\n"


# ==================== Process one region ====================

def process_region(region, executable):
    target = PUBLIC / f"{region.lower()}.txt"
    diagnostic_path = DATA_DIR / f"{region.lower()}.json"

    diagnostic = {
        "region": region,
        "started_at": datetime.now(timezone.utc).isoformat(),
        "node_api": NODE_API + region,
        "cfst_executable": executable,
        "mode": "official CloudflareSpeedTest HTTPing",
        "httping_url": HTTPING_URL,
        "httping_port": HTTPING_PORT,
        "repeat_count": REPEAT_COUNT,
        "workers": MAX_WORKERS,
        "top_n": TOP_N,
        "status": "failed",
        "candidate_count": 0,
        "unique_ip_count": 0,
        "result_count": 0,
        "success_ratio": 0,
        "results": [],
        "error": None,
    }

    log.info("========== %s ==========", region)

    try:
        endpoints = fetch_region(region)
        diagnostic["candidate_count"] = len(endpoints)

        endpoint_ports = {}

        for ip, port in endpoints:
            endpoint_ports.setdefault(ip, []).append(port)

        diagnostic["unique_ip_count"] = len(endpoint_ports)

        ranked = run_cfst(region, endpoints, executable)
        diagnostic["results"] = ranked
        diagnostic["result_count"] = len(ranked)

        valid, success_ratio = validate_results(
            region,
            endpoints,
            ranked,
            target,
        )

        best = valid[:TOP_N]
        content = build_txt(region, best, endpoint_ports)
        lines = [
            line for line in content.splitlines()
            if line.strip()
        ]

        if len(lines) < MIN_OUTPUT_COUNT:
            raise RuntimeError(
                f"Generated only {len(lines)} lines; old TXT retained."
            )

        for line in lines:
            if not re.fullmatch(
                r"\d{1,3}(?:\.\d{1,3}){3}:\d{1,5}"
                r"#[A-Z]{2}-\d{2}-\d+ms",
                line,
            ):
                raise RuntimeError(f"Malformed output line: {line!r}")

        # Only replace the previous TXT after all checks have passed.
        atomic_write_text(target, content)

        diagnostic.update({
            "status": "success",
            "success_count": len(valid),
            "success_ratio": round(success_ratio, 4),
            "output_count": len(lines),
            "output_file": str(target.relative_to(ROOT)),
            "finished_at": datetime.now(timezone.utc).isoformat(),
        })

        log.info(
            "[%s] Updated %s: %d entries, %d candidate IPs, "
            "%d valid results, success ratio %.1f%%",
            region,
            target.name,
            len(lines),
            len(endpoint_ports),
            len(valid),
            success_ratio * 100,
        )

        for row in best[:5]:
            log.info(
                "[%s] TOP %s latency=%.2fms",
                region,
                row["ip"],
                row["latency_ms"],
            )

    except Exception as error:
        diagnostic["status"] = "failed"
        diagnostic["error"] = f"{type(error).__name__}: {error}"
        diagnostic["finished_at"] = datetime.now(timezone.utc).isoformat()

        log.exception(
            "[%s] Failed; previous TXT retained: %s",
            region,
            error,
        )

    finally:
        if WRITE_DIAGNOSTICS:
            try:
                atomic_write_json(diagnostic_path, diagnostic)
            except Exception:
                log.exception(
                    "[%s] Could not write diagnostic JSON",
                    region,
                )

    return diagnostic["status"] == "success"


# ==================== Main ====================

def main():
    log.info("Regional official CFST HTTPing scan started")
    log.info(
        "Regions=%s top_n=%d repeats=%d workers=%d port=%d URL=%s",
        ",".join(REGIONS),
        TOP_N,
        REPEAT_COUNT,
        MAX_WORKERS,
        HTTPING_PORT,
        HTTPING_URL,
    )

    executable = resolve_cfst_executable()

    # Confirm the executable can be launched.
    version_check = subprocess.run(
        [executable, "-v"],
        cwd=str(ROOT),
        capture_output=True,
        text=True,
        encoding="utf-8",
        errors="replace",
        timeout=30,
        check=False,
    )

    log.info(
        "CFST version check: exit=%s stdout=%s stderr=%s",
        version_check.returncode,
        (version_check.stdout or "").strip()[:500],
        (version_check.stderr or "").strip()[:500],
    )

    successes = 0

    for region in REGIONS:
        if process_region(region, executable):
            successes += 1

    log.info(
        "Finished: %d/%d regions updated",
        successes,
        len(REGIONS),
    )

    if successes == 0:
        raise SystemExit(
            "ERROR: no region produced a valid output. "
            "Previous TXT files were retained. Check "
            "logs/scanner.log, work_cfst/ and public/data/*.json."
        )


if __name__ == "__main__":
    main()
```
