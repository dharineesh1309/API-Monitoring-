"""Deep-test exposed APIs with OWASP ASTF, using the real routes from the API inventory.

ASTF sends attack traffic: bursts of requests, state-changing calls and injection
payloads. Only public APIs whose name matches API_SCAN_ALLOWLIST (comma-separated
glob patterns, default "cw-lab-*") can be tested, and one deep test runs at a time.
"""

import hashlib
import json
import re
import subprocess
import tempfile
import threading
import time
import urllib.parse
import urllib.request
from concurrent.futures import ThreadPoolExecutor
from datetime import datetime, timezone
from fnmatch import fnmatch
from pathlib import Path
from typing import Any

from .api_inventory import SEVERITY_ORDER, crawl

ASTF_JAR = Path("/app/astf-v2.0.1.jar")  # same pinned build scripts/security_scan.sh uses
ASTF_URL = "https://github.com/OWASP/www-project-api-security-testing-framework/releases/download/v2.0.1/astf-v2.0.1.jar"
ASTF_SHA256 = "ea9defba5bf0a83550cf1072a39649b0a0f5507f66a49578d557a28185cc5954"
ASTF_MINUTES = 10  # per run
ASTF_THREADS = "2"  # keep the load on the target low
MAX_URLS_PER_API = 3  # e.g. REST stages
OWASP = {
    "API1": "Broken Object Level Authorization",
    "API2": "Broken Authentication",
    "API3": "Broken Object Property Level Authorization",
    "API4": "Unrestricted Resource Consumption",
    "API5": "Broken Function Level Authorization",
    "API6": "Unrestricted Access to Sensitive Business Flows",
    "API7": "Server Side Request Forgery",
    "API8": "Security Misconfiguration",
    "API9": "Improper Inventory Management",
    "API10": "Unsafe Consumption of APIs",
}

_running = threading.Lock()


class DeepTestBusy(RuntimeError):
    pass


def deep_test(session, settings, api_ids: list[str] | None = None) -> dict[str, Any]:
    if not _running.acquire(blocking=False):
        raise DeepTestBusy("A deep test is already running. Wait for it to finish.")
    try:
        return _deep_test(session, settings, api_ids)
    finally:
        _running.release()


def _deep_test(session, settings, api_ids):
    patterns = [p.strip() for p in settings.api_scan_allowlist.split(",") if p.strip()]

    def allowed(api):
        return any(fnmatch(api["name"], pattern) for pattern in patterns)

    public = [api for api in crawl(session, settings)["apis"] if api["public"]]
    if api_ids is None:
        targets = [api for api in public if allowed(api)]
    else:
        by_id = {api["id"]: api for api in public}
        unknown = [api_id for api_id in api_ids if api_id not in by_id]
        if unknown:
            raise LookupError(f"Not a public API in the current inventory: {', '.join(unknown)}")
        targets = [by_id[api_id] for api_id in dict.fromkeys(api_ids)]
        blocked = [api["name"] for api in targets if not allowed(api)]
        if blocked:
            raise PermissionError(
                f"Not in API_SCAN_ALLOWLIST ({settings.api_scan_allowlist}): {', '.join(blocked)}. "
                "ASTF sends attack traffic; add a name only for APIs you are authorized to test."
            )

    runs = [(api, url, endpoints) for api in targets for url, endpoints in _runs(api)]
    if runs:
        _ensure_jar()
    with ThreadPoolExecutor(max_workers=3) as pool:
        scans = list(pool.map(lambda run: _scan(*run), runs))

    findings = sorted(
        {f["id"]: f for scan in scans for f in scan.pop("findings")}.values(),
        key=lambda f: (SEVERITY_ORDER[f["severity"]], f["api"], f["target"]),
    )
    return {
        "generated_at": datetime.now(timezone.utc).isoformat(timespec="seconds"),
        "allowlist": settings.api_scan_allowlist,
        "tested": [api["name"] for api in targets],
        "skipped": sorted(api["name"] for api in public if api not in targets),
        "scans": scans,
        "findings": findings,
        "summary": {
            "apis": len(targets),
            "runs": len(scans),
            "failed_runs": sum(bool(scan.get("error")) for scan in scans),
            "findings": {level: sum(f["severity"] == level for f in findings) for level in SEVERITY_ORDER},
        },
    }


def _runs(api) -> list[tuple[str, list[str] | None]]:
    """(base URL, endpoint lines) per ASTF run; None lets ASTF discover the endpoints itself."""
    urls = [url for url in api["urls"] if url.startswith("http")][:MAX_URLS_PER_API]  # ASTF cannot test wss://
    if api["source"].startswith("API Gateway"):
        return [(url, _endpoint_lines(api["routes"])) for url in urls]
    if api["source"] == "Lambda function URL":  # one function answers every path, so discovery would be noise
        return [(url, ["GET /", "POST /"]) for url in urls]
    if api["source"] == "AppSync GraphQL":
        parts = [urllib.parse.urlsplit(url) for url in urls]
        return [(f"{p.scheme}://{p.netloc}", [f"POST {p.path}"]) for p in parts]
    return [(url, None) for url in urls]


def _endpoint_lines(routes) -> list[str]:
    """Inventory route keys as ASTF "METHOD /path" lines: ANY -> GET+POST, {param} -> 1, no preflights."""
    lines = set()
    for route in routes:
        method, _, path = route["route"].partition(" ")
        if method == "OPTIONS":
            continue
        if not path:  # $default / $connect catch-alls
            method, path = "ANY", "/"
        path = re.sub(r"\{[^}]+\}", "1", path)
        lines.update(f"{m} {path}" for m in (("GET", "POST") if method == "ANY" else (method,)))
    return sorted(lines)


def _scan(api, base, endpoints) -> dict[str, Any]:
    result = {"api": api["name"], "api_id": api["id"], "url": base, "endpoints": endpoints or "discovered by ASTF", "findings": []}
    with tempfile.TemporaryDirectory() as tmp:
        report = Path(tmp, "astf.json")
        command = ["java", "-jar", str(ASTF_JAR), "-u", base, "-f", "JSON", "-o", str(report),
                   "-t", ASTF_THREADS, "--timeout", str(ASTF_MINUTES)]
        if endpoints:
            Path(tmp, "endpoints.txt").write_text("\n".join(endpoints) + "\n")
            command += ["--endpoints-file", str(Path(tmp, "endpoints.txt"))]
        started = time.monotonic()
        try:
            done = subprocess.run(command, cwd=tmp, capture_output=True, text=True, timeout=ASTF_MINUTES * 60 + 60)
        except subprocess.TimeoutExpired:
            return {**result, "error": f"ASTF did not finish within {ASTF_MINUTES} minutes."}
        result.update(exit_code=done.returncode, seconds=round(time.monotonic() - started, 1))
        if done.returncode > 1 or not report.exists():  # 0 = clean, 1 = findings, 2 = scan error
            return {**result, "error": (done.stderr or done.stdout or "ASTF wrote no report.")[-500:]}
        items = json.loads(report.read_text())["findings"]
        if endpoints:
            # ASTF also guesses paths (/admin, /.env, ...) beyond the list. Every real route is in the list,
            # so a hit elsewhere is a catch-all handler (e.g. a Lambda URL) answering 200 to any path: noise.
            kept = [item for item in items if item.get("endpoint") in endpoints]
            result["ignored_guessed_paths"] = len(items) - len(kept)
            items = kept
        result["findings"] = [_finding(api, base, item) for item in items]
        return result


def _finding(api, base, item) -> dict[str, Any]:
    test = item.get("testCaseId", "ASTF")
    category = re.match(r"ASTF-(API\d+)-(\d{4})", test)
    severity = item.get("severity", "LOW").lower()
    title = item.get("title", test)
    return {
        "id": f"{api['id']}:{test}:{item.get('endpoint')}:{title}",
        "source": api["source"],
        "region": api["region"],
        "api": api["name"],
        "check": test,
        "severity": severity if severity in SEVERITY_ORDER else "low",  # ASTF INFO -> low
        "owasp": f"{category[1]}:{category[2]} {OWASP[category[1]]}" if category else test,
        "target": item.get("endpoint") or base,
        "evidence": f"{title}. {item.get('evidence') or item.get('description', '')}",
        "fix": item.get("remediation", ""),
        "command": "",
        "tool": "ASTF",
    }


def _ensure_jar() -> None:
    if ASTF_JAR.exists():
        return
    partial = ASTF_JAR.with_suffix(".tmp")
    urllib.request.urlretrieve(ASTF_URL, partial)
    if hashlib.sha256(partial.read_bytes()).hexdigest() != ASTF_SHA256:
        partial.unlink()
        raise RuntimeError("Downloaded ASTF jar failed its SHA-256 check; refusing to run it.")
    partial.rename(ASTF_JAR)
