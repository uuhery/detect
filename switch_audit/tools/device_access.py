"""
DeviceAccessLayer: three-path abstraction over network device interfaces.

Every path returns a CheckResult with data: dict — the rest of the system
never receives raw CLI text. Paths tried in order until one succeeds:

  1. NAPALM getter    — vendor SDK, structured objects, high confidence
  2. ntc-templates    — TextFSM-parsed CLI output, medium confidence
  3. ssh-raw          — raw CLI wrapped in {"raw": ...}, low confidence

The caller only needs execute_check(). Path selection is automatic.
"""

from __future__ import annotations

import logging
from datetime import datetime, timezone
from functools import lru_cache
from pathlib import Path

import yaml
from ntc_templates.parse import parse_output

from switch_audit.core.config import settings
from switch_audit.core.langgraph.state import AuditState, CheckResult
from switch_audit.core.logging import logger
from switch_audit.tools import ssh_exec

logging.getLogger("napalm").setLevel(logging.WARNING)
logging.getLogger("netmiko").setLevel(logging.WARNING)
logging.getLogger("paramiko").setLevel(logging.WARNING)

_METHODOLOGY_PATH = Path(__file__).parent.parent / "knowledge" / "audit_methodology.yaml"

# Canonical device_os → NAPALM driver name
_NAPALM_DRIVERS: dict[str, str] = {
    "cisco_iosxe": "ios",
    "cisco_ios":   "ios",
    "cisco_nxos":  "nxos",
    "arista_eos":  "eos",
    "juniper_junos": "junos",
}

# Canonical device_os → ntc-templates platform name
_NTC_PLATFORMS: dict[str, str] = {
    "cisco_iosxe":    "cisco_xe",
    "cisco_ios":      "cisco_ios",
    "cisco_nxos":     "cisco_nxos",
    "arista_eos":     "arista_eos",
    "juniper_junos":  "juniper_junos",
}


@lru_cache(maxsize=1)
def load_methodology() -> list[dict]:
    raw = yaml.safe_load(_METHODOLOGY_PATH.read_text(encoding="utf-8"))
    return raw.get("checks", [])


def get_check_spec(check_id: str) -> dict | None:
    return next((c for c in load_methodology() if c["id"] == check_id), None)


def _now() -> str:
    return datetime.now(timezone.utc).isoformat()


# ---------------------------------------------------------------------------
# Default credential testing
# ---------------------------------------------------------------------------

_DEFAULT_CREDS: list[tuple[str, str]] = [
    ("cisco",    "cisco"),
    ("admin",    "admin"),
    ("admin",    "password"),
    ("admin",    ""),
    ("admin",    "1234"),
    ("enable",   "cisco"),
    ("netadmin", "netadmin"),
    ("manager",  "manager"),
    ("root",     "root"),
    ("guest",    "guest"),
]


def _test_default_credentials(state: AuditState) -> CheckResult:
    """Try known weak/default SSH credentials; report which ones work.

    Skips the current working credential (already known good).
    Uses 5s timeout per attempt to keep total time bounded (~45s worst case).
    """
    current = (settings.SSH_USERNAME, settings.SSH_PASSWORD)
    working: list[dict] = []
    tested = 0

    for user, pwd in _DEFAULT_CREDS:
        if (user, pwd) == current:
            continue
        raw = ssh_exec(
            host=state["target"],
            port=settings.SSH_PORT,
            username=user,
            password=pwd,
            command="show version",
            timeout=5,
            device_type=settings.SSH_DEVICE_TYPE,
        )
        tested += 1
        if not raw.startswith("[ssh_error]"):
            working.append({"username": user, "password": pwd})
            logger.info(
                "device_access.default_cred_match",
                target=state["target"],
                username=user,
            )

    return CheckResult(
        check_id="default_credentials",
        data={"working_credentials": working, "tested_count": tested},
        access_method="ssh-raw",
        confidence="high",
        timestamp=_now(),
    )


# ---------------------------------------------------------------------------
# Public entry point
# ---------------------------------------------------------------------------

def _resolve_cli(check: dict, device_os: str) -> str | None:
    """Return the CLI command for this check on this device OS.

    Priority (deterministic, no ambiguity):
      cli_by_os[device_os]  >  cli_by_os["default"]  >  cli_fallback  >  None

    None means the check is not applicable on this OS → caller returns unavailable.
    Backward-compatible: checks without cli_by_os fall through to cli_fallback.
    """
    by_os = check.get("cli_by_os", {})
    if by_os:
        if device_os in by_os:
            return by_os[device_os]        # None is a valid explicit "not supported"
        return by_os.get("default")        # generic fallback within cli_by_os
    return check.get("cli_fallback")       # legacy single-command format


def execute_check(check_id: str, state: AuditState) -> CheckResult:
    """Execute one audit check, returning structured CheckResult on every path."""
    # Algorithmic checks bypass the CLI access layers entirely
    if check_id == "default_credentials":
        return _test_default_credentials(state)

    check = get_check_spec(check_id)
    if not check:
        return CheckResult(
            check_id=check_id,
            data={},
            access_method="unavailable",
            confidence="low",
            timestamp=_now(),
        )

    device_os = state.get("device_os", "")
    access_method = state.get("access_method", "ssh-raw")
    cli_cmd = _resolve_cli(check, device_os)

    # Layer 1: NAPALM — only when profiler confirmed it works for this device
    if check.get("napalm_getter") and access_method == "napalm":
        result = _try_napalm(check, state, device_os)
        if result:
            return result

    # Layer 2: ntc-templates — structured CLI parsing for known platforms
    if check.get("parse_with") == "ntc-templates" and cli_cmd:
        result = _try_ntc_templates(check, state, device_os, cli_cmd)
        if result:
            return result

    # Layer 3: ssh-raw — always possible, data is low-confidence
    if cli_cmd:
        return _ssh_raw(check, state, cli_cmd)

    return CheckResult(
        check_id=check_id,
        data={},
        access_method="unavailable",
        confidence="low",
        timestamp=_now(),
    )


# ---------------------------------------------------------------------------
# Layer implementations
# ---------------------------------------------------------------------------

def _try_napalm(check: dict, state: AuditState, device_os: str) -> CheckResult | None:
    driver_name = _NAPALM_DRIVERS.get(device_os)
    if not driver_name:
        return None

    try:
        from napalm import get_network_driver  # lazy import — not required if NAPALM unavailable

        driver_cls = get_network_driver(driver_name)
        device = driver_cls(
            hostname=state["target"],
            username=settings.SSH_USERNAME,
            password=settings.SSH_PASSWORD,
            optional_args={
                "port": settings.EAPI_PORT,
                "transport": settings.EAPI_TRANSPORT,
                "timeout": settings.SSH_TIMEOUT,
            },
        )
        device.open()
        try:
            getter = getattr(device, check["napalm_getter"])
            raw_data = getter()
        finally:
            device.close()

        # NAPALM returns dict or list; list → {"rows": [...]} for uniform dict interface
        data = raw_data if isinstance(raw_data, dict) else {"rows": raw_data}

        logger.info("device_access.napalm_ok", check_id=check["id"])
        return CheckResult(
            check_id=check["id"],
            data=data,
            access_method="napalm",
            confidence="high",
            timestamp=_now(),
        )

    except Exception as exc:
        logger.warning("device_access.napalm_failed", check_id=check["id"], error=str(exc))
        return None


def _try_ntc_templates(check: dict, state: AuditState, device_os: str, cli_cmd: str) -> CheckResult | None:
    platform = _NTC_PLATFORMS.get(device_os)
    if not platform:
        return None  # no template for this OS → fall through to ssh-raw

    command = cli_cmd
    raw = _ssh(state, command)
    if raw.startswith("[ssh_error]"):
        return None

    try:
        rows = parse_output(platform=platform, command=command, data=raw)
        logger.info("device_access.ntc_ok", check_id=check["id"], rows=len(rows))
        return CheckResult(
            check_id=check["id"],
            data={"rows": rows},
            access_method="ntc-templates",
            confidence="medium",
            timestamp=_now(),
        )
    except Exception as exc:
        logger.warning("device_access.ntc_failed", check_id=check["id"], error=str(exc))
        return None


def _ssh_raw(check: dict, state: AuditState, cli_cmd: str) -> CheckResult:
    command = cli_cmd
    raw = _ssh(state, command)
    status = "ssh_error" if raw.startswith("[ssh_error]") else "ok"
    logger.info("device_access.ssh_raw", check_id=check["id"], status=status)
    return CheckResult(
        check_id=check["id"],
        data={"raw": raw, "status": status},
        access_method="ssh-raw",
        confidence="low",
        timestamp=_now(),
    )


def _ssh(state: AuditState, command: str) -> str:
    return ssh_exec(
        host=state["target"],
        port=settings.SSH_PORT,
        username=settings.SSH_USERNAME,
        password=settings.SSH_PASSWORD,
        command=command,
        timeout=settings.SSH_TIMEOUT,
        device_type=settings.SSH_DEVICE_TYPE,
    )


# ---------------------------------------------------------------------------
# Helpers used by profiler
# ---------------------------------------------------------------------------

def classify_device_os(raw_show_version: str) -> tuple[str, str]:
    """Return (canonical_device_os, vendor) from raw 'show version' output."""
    s = raw_show_version.lower()

    if "ios xe" in s or "ios-xe" in s:
        return "cisco_iosxe", "Cisco"
    if "cisco ios" in s:
        return "cisco_ios", "Cisco"
    if "nx-os" in s or "nxos" in s:
        return "cisco_nxos", "Cisco"
    if "arista" in s or ("eos" in s and "arista" not in s and "junos" not in s):
        return "arista_eos", "Arista"
    if "junos" in s or "juniper" in s:
        return "juniper_junos", "Juniper"
    if "frr" in s or "free range routing" in s or "frrouting" in s:
        return "frr", "FRR"
    if "open vswitch" in s or "ovs" in s:
        return "ovs", "OVS"
    return "unknown", "Unknown"


def extract_version_string(raw_show_version: str, device_os: str) -> str:
    """Extract a clean version string from 'show version' output for NVD CPE lookup.

    Returns the version token (e.g. "4.28.3F", "17.03.01a") or "" if not found.
    """
    import re
    patterns: dict[str, list[str]] = {
        "arista_eos":    [
            r"[Ss]oftware\s+image\s+version:\s+(\S+)",          # cEOS: "Software image version: 4.32.10M-..."
            r"[Ee][Oo][Ss]\s+(?:version\s+)?(\d[\d.]+\w*)",     # physical: "EOS version 4.28.3F"
        ],
        "cisco_iosxe":   [r"[Cc]isco IOS.XE Software.*?[Vv]ersion\s+(\S+)", r"[Vv]ersion\s+(\d+\.\d+\.\S+)"],
        "cisco_ios":     [r"[Cc]isco IOS Software.*?[Vv]ersion\s+(\S+,?)", r"[Vv]ersion\s+(\d+\.\d+[\(\)\w]+)"],
        "cisco_nxos":    [r"[Nn][Xx]-[Oo][Ss].*?[Vv]ersion\s+(\S+)", r"[Vv]ersion\s+(\d+\.\d+\S*)"],
        "juniper_junos": [r"[Jj]unos:\s+(\S+)", r"[Jj][Uu][Nn][Oo][Ss]\s+[Rr]elease\s+(\S+)"],
        "frr":           [r"[Ff][Rr][Rr]outing\s+(\d[\d.]+)", r"[Ff][Rr][Rr]\s+(\d[\d.]+)"],
    }
    for pattern in patterns.get(device_os, []):
        m = re.search(pattern, raw_show_version)
        if m:
            # Strip trailing comma/semicolon
            return m.group(1).rstrip(",;")
    return ""


def probe_napalm(target: str, device_os: str) -> tuple[bool, str]:
    """Return (napalm_ok, os_version) from a minimal NAPALM connection.

    Calls get_facts() to retrieve the structured os_version string, which is
    more reliable than regex on raw show version output (especially for cEOS
    where the version string has build suffixes).
    Returns (False, "") if NAPALM is unavailable or connection fails.
    """
    driver_name = _NAPALM_DRIVERS.get(device_os)
    if not driver_name:
        return False, ""
    try:
        from napalm import get_network_driver
        device = get_network_driver(driver_name)(
            hostname=target,
            username=settings.SSH_USERNAME,
            password=settings.SSH_PASSWORD,
            optional_args={
                "port": settings.EAPI_PORT,
                "transport": settings.EAPI_TRANSPORT,
                "timeout": 10,
            },
        )
        device.open()
        try:
            facts = device.get_facts()
            napalm_version = facts.get("os_version", "")
        finally:
            device.close()
        return True, napalm_version
    except Exception:
        return False, ""
