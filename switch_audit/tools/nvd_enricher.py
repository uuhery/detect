"""
NIST NVD CVE enricher — live CPE-based vulnerability lookup.

Queries https://services.nvd.nist.gov/rest/json/cves/2.0 by CPE string to find
CVEs matching the audited device's OS + version. Results are cached in SQLite
(~/.detect/nvd_cache.db) for 6 hours to respect the 5 req/30s rate limit.

Public API: enrich_with_nvd(device_os, version) -> Markdown str or ""
Never raises — enrichment failure must not block the audit.
"""

from __future__ import annotations

import json
import sqlite3
import time
import urllib.error
import urllib.parse
import urllib.request
from datetime import datetime, timedelta, timezone
from pathlib import Path

from switch_audit.core.logging import logger

# ---------------------------------------------------------------------------
# CPE vendor/product map for known device_os tokens
# ---------------------------------------------------------------------------

_CPE_MAP: dict[str, tuple[str, str]] = {
    "cisco_iosxe":    ("cisco",       "ios_xe"),
    "cisco_ios":      ("cisco",       "ios"),
    "cisco_nxos":     ("cisco",       "nx-os"),
    "arista_eos":     ("arista",      "eos"),
    "juniper_junos":  ("juniper",     "junos"),
    "frr":            ("frrouting",   "frrouting"),
    "huawei_vrpv8":   ("huawei",      "vrp"),
}

# ---------------------------------------------------------------------------
# SQLite cache
# ---------------------------------------------------------------------------

_DB_PATH = Path.home() / ".detect" / "nvd_cache.db"
_CACHE_TTL_HOURS = 6
_NVD_API = "https://services.nvd.nist.gov/rest/json/cves/2.0"


def _get_db() -> sqlite3.Connection:
    _DB_PATH.parent.mkdir(parents=True, exist_ok=True)
    conn = sqlite3.connect(str(_DB_PATH))
    conn.execute(
        "CREATE TABLE IF NOT EXISTS cpe_cache "
        "(cpe_key TEXT PRIMARY KEY, result_json TEXT, fetched_at TEXT)"
    )
    conn.commit()
    return conn


def _cache_get(cpe_key: str) -> str | None:
    try:
        conn = _get_db()
        row = conn.execute(
            "SELECT result_json, fetched_at FROM cpe_cache WHERE cpe_key = ?",
            (cpe_key,),
        ).fetchone()
        conn.close()
        if not row:
            return None
        fetched_at = datetime.fromisoformat(row[1])
        if datetime.now(timezone.utc) - fetched_at > timedelta(hours=_CACHE_TTL_HOURS):
            return None  # expired
        return row[0]
    except Exception:
        return None


def _cache_set(cpe_key: str, result_json: str) -> None:
    try:
        conn = _get_db()
        conn.execute(
            "INSERT OR REPLACE INTO cpe_cache (cpe_key, result_json, fetched_at) VALUES (?,?,?)",
            (cpe_key, result_json, datetime.now(timezone.utc).isoformat()),
        )
        conn.commit()
        conn.close()
    except Exception:
        pass


# ---------------------------------------------------------------------------
# NVD API query
# ---------------------------------------------------------------------------

def _build_cpe_string(vendor: str, product: str, version: str) -> str:
    # Strip build suffix: "4.32.10M-46429116.43210M" → "4.32.10M"
    v = version.split("-")[0]
    # Remove trailing release letters: "4.28.3F" → "4.28.3", lowercase
    v = v.lower().rstrip("abcdefghijklmnopqrstuvwxyz").strip(".")
    return f"cpe:2.3:o:{vendor}:{product}:{v}:*:*:*:*:*:*:*"


def _query_nvd(cpe_string: str) -> list[dict]:
    params = urllib.parse.urlencode({
        "cpeName": cpe_string,
        "resultsPerPage": 10,
    })
    url = f"{_NVD_API}?{params}"
    req = urllib.request.Request(url, headers={"User-Agent": "switch-audit/1.0"})

    try:
        with urllib.request.urlopen(req, timeout=10) as resp:
            body = json.loads(resp.read().decode("utf-8"))
            return body.get("vulnerabilities", [])
    except urllib.error.HTTPError as exc:
        if exc.code == 429:
            logger.warning("nvd.rate_limited", sleeping=6)
            time.sleep(6)
            with urllib.request.urlopen(req, timeout=10) as resp:
                body = json.loads(resp.read().decode("utf-8"))
                return body.get("vulnerabilities", [])
        raise


def _format_cve_table(vulns: list[dict], queried_at: str) -> str:
    rows: list[str] = []
    for item in vulns:
        cve = item.get("cve", {})
        cve_id = cve.get("id", "")
        desc = next(
            (d["value"] for d in cve.get("descriptions", []) if d.get("lang") == "en"),
            "",
        )
        # CVSS v3 score preferred, fall back to v2
        metrics = cve.get("metrics", {})
        score_str = "N/A"
        for key in ("cvssMetricV31", "cvssMetricV30", "cvssMetricV2"):
            entries = metrics.get(key, [])
            if entries:
                cvss = entries[0].get("cvssData", {})
                score_str = f"{cvss.get('baseScore', '?')} {cvss.get('baseSeverity', '')}"
                break
        rows.append(f"| {cve_id} | {score_str} | {desc[:120]} |")

    if not rows:
        return ""

    table = (
        "| CVE | CVSS | Summary |\n"
        "|-----|------|---------|\n"
        + "\n".join(rows)
    )
    return (
        f"## CVE Intelligence (NIST NVD — live query)\n\n"
        f"{table}\n\n"
        f"_Queried: {queried_at} · Source: https://nvd.nist.gov_"
    )


# ---------------------------------------------------------------------------
# Public API
# ---------------------------------------------------------------------------

def enrich_with_nvd(device_os: str, version: str) -> str:
    """Return a Markdown CVE table for device_os + version, or "" if unavailable.

    Uses SQLite cache to avoid re-querying within 6 hours. Rate-limit safe.
    Never raises.
    """
    if not device_os or not version:
        return ""

    vendor_product = _CPE_MAP.get(device_os)
    if not vendor_product:
        logger.info("nvd.unsupported_os", device_os=device_os)
        return ""

    vendor, product = vendor_product
    cpe_string = _build_cpe_string(vendor, product, version)
    queried_at = datetime.now(timezone.utc).strftime("%Y-%m-%dT%H:%M:%SZ")

    cached = _cache_get(cpe_string)
    if cached is not None:
        logger.info("nvd.cache_hit", cpe=cpe_string)
        vulns = json.loads(cached)
    else:
        try:
            logger.info("nvd.querying", cpe=cpe_string)
            vulns = _query_nvd(cpe_string)
            _cache_set(cpe_string, json.dumps(vulns))
            logger.info("nvd.query_ok", cpe=cpe_string, count=len(vulns))
        except Exception as exc:
            logger.warning("nvd.query_failed", cpe=cpe_string, error=str(exc))
            return ""

    return _format_cve_table(vulns, queried_at)
