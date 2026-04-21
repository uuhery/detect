"""
Entry point for the switch audit agent.

Single-device usage:
    uv run python -m switch_audit.main --target 192.168.1.1

Network BFS usage (lateral expansion):
    uv run python -m switch_audit.main --targets 192.168.1.1 192.168.1.2
    uv run python -m switch_audit.main --target-file hosts.txt --max-devices 20
"""

from __future__ import annotations

import argparse
import re
import socket
import uuid
from collections import deque
from datetime import datetime, timezone
from pathlib import Path

from switch_audit.core.config import settings
from switch_audit.core.langgraph.graph import build_graph
from switch_audit.core.logging import logger
from switch_audit.tools import ssh_exec
from switch_audit.tools.crypto import decode_type7


# ---------------------------------------------------------------------------
# SSH reachability probe (P4b)
# ---------------------------------------------------------------------------

def _is_ssh_reachable(host: str, port: int = 22, timeout: float = 2.0) -> bool:
    """TCP-level probe — 2s timeout, no SSH handshake.

    Reduces BFS stall from O(SSH_TIMEOUT) to O(2s) per unreachable device.
    """
    try:
        with socket.create_connection((host, port), timeout=timeout):
            return True
    except (socket.timeout, ConnectionRefusedError, OSError):
        return False


# ---------------------------------------------------------------------------
# Credential extraction from audit result (P4c)
# ---------------------------------------------------------------------------

_USERNAME_TYPE7_RE = re.compile(
    r"username\s+(\S+)\s+(?:privilege\s+\d+\s+)?(?:secret|password)\s+7\s+([0-9A-Fa-f]{4,})",
    re.IGNORECASE,
)
_USERNAME_PLAIN_RE = re.compile(
    r"username\s+(\S+)\s+(?:privilege\s+\d+\s+)?password\s+0\s+(\S+)",
    re.IGNORECASE,
)


def extract_propagatable_creds(result: dict) -> list[tuple[str, str]]:
    """Extract credentials that may be reused on neighboring devices.

    Sources (in priority order):
      1. default_credentials check — already-validated working credentials
      2. running_config — Type 7 decoded username+password pairs
      3. running_config — plaintext (password 0) username+password pairs

    Returns: [(username, password), ...]
    Memory-only: never written to DB, ChromaDB, or logs.
    """
    creds: set[tuple[str, str]] = set()

    # Source 1: algorithmically confirmed default creds
    for r in result.get("check_results", []):
        if r["check_id"] == "default_credentials":
            for c in r["data"].get("working_credentials", []):
                creds.add((c["username"], c["password"]))

    # Sources 2+3: running_config text scan
    config_text = ""
    for r in result.get("check_results", []):
        if r["check_id"] == "running_config":
            data = r.get("data", {})
            config_text = data.get("running") or data.get("raw", "")
            break

    if config_text:
        for m in _USERNAME_TYPE7_RE.finditer(config_text):
            decoded = decode_type7(m.group(2))
            if not decoded.startswith("ERROR"):
                creds.add((m.group(1), decoded))
        for m in _USERNAME_PLAIN_RE.finditer(config_text):
            creds.add((m.group(1), m.group(2)))

    return list(creds)


# ---------------------------------------------------------------------------
# Credential pool testing (P5c)
# ---------------------------------------------------------------------------

def _find_working_credential(
    target: str,
    cred_pool: list[tuple[str, str]],
) -> tuple[str, str] | None:
    """Try credential pool against target; return first working pair.

    Only tests pool credentials (discovered from prior audits).
    The default credential table is tested inside the device audit itself
    via the default_credentials check.
    5s timeout per attempt; failures are silent.
    """
    for user, pwd in cred_pool:
        raw = ssh_exec(
            host=target,
            port=settings.SSH_PORT,
            username=user,
            password=pwd,
            command="show version",
            timeout=5,
            device_type=settings.SSH_DEVICE_TYPE,
        )
        if not raw.startswith("[ssh_error]"):
            logger.info("network_audit.cred_reuse", target=target, username=user)
            return (user, pwd)
    return None


# ---------------------------------------------------------------------------
# Single-device audit (P4b: reachability guard + credential override)
# ---------------------------------------------------------------------------

def run_audit(
    target: str,
    session_id: str | None = None,
    credential_override: tuple[str, str] | None = None,
    visited_targets: set[str] | None = None,
) -> dict | None:
    """Run a full audit for one device.

    Returns the final LangGraph result dict, or None if the device is
    unreachable (TCP probe failed — avoids 30s SSH hang per device).
    """
    if not _is_ssh_reachable(target, settings.SSH_PORT):
        logger.warning("run_audit.unreachable", target=target)
        return None

    session_id = session_id or str(uuid.uuid4())
    logger.info(
        "audit.start",
        target=target,
        session_id=session_id,
        model=settings.DEFAULT_LLM_MODEL,
        cred_override=credential_override[0] if credential_override else None,
    )

    graph = build_graph()

    initial_state = {
        "session_id": session_id,
        "target": target,
        "started_at": datetime.now(timezone.utc).isoformat(),
        # Device profile (profiler writes)
        "device_os": "",
        "device_vendor": "",
        "device_version": "",
        "access_method": "",
        # CVE enrichment (enrich writes)
        "cve_context": None,
        # Audit plan (profiler writes)
        "pending_checks": [],
        "completed_checks": [],
        # Evidence (executor writes)
        "check_results": [],
        # Analysis (analyze writes)
        "facts": [],
        "attack_chains": [],
        # Memory enrichment (search_memory writes)
        "enriched_strategy": "",
        # Handoff (adviser writes)
        "proposed_check_id": "",
        "adviser_reasoning": "",
        # Lateral discovery (discover writes, BFS reads)
        "discovery_queue": [],
        "visited_targets": list(visited_targets or {target}),
        # Control
        "trial_count": 0,
        "status": "running",
        "report_path": "",
    }

    # Temporarily override SSH credentials if a prior device's creds work here
    if credential_override:
        original_user = settings.SSH_USERNAME
        original_pass = settings.SSH_PASSWORD
        settings.SSH_USERNAME = credential_override[0]
        settings.SSH_PASSWORD = credential_override[1]

    try:
        config = {"configurable": {"thread_id": session_id}}
        result = graph.invoke(initial_state, config=config)
    finally:
        if credential_override:
            settings.SSH_USERNAME = original_user
            settings.SSH_PASSWORD = original_pass

    logger.info(
        "audit.complete",
        session_id=session_id,
        trials=result["trial_count"],
        checks_done=len(result.get("completed_checks", [])),
        facts_found=len(result.get("facts", [])),
        chains_found=len(result.get("attack_chains", [])),
        neighbors_found=len(result.get("discovery_queue", [])),
        status=result["status"],
        report_path=result.get("report_path", ""),
    )

    if result.get("report_path"):
        print(f"\nReport: {result['report_path']}\n")

    return result


# ---------------------------------------------------------------------------
# Network-level BFS orchestration (P5b)
# ---------------------------------------------------------------------------

def _write_network_summary(
    all_reports: list[str],
    visited: set[str],
    cred_reuse_map: dict[str, list[str]],
) -> None:
    """Write a cross-device network summary report.

    Sections:
      1. Audit scope (devices audited vs skipped)
      2. Credential reuse paths (blast radius visualization)
      3. Highest-priority findings across all devices
    """
    lines: list[str] = [
        "# Network Audit Summary",
        "",
        f"| Devices audited | {len(visited)} |",
        f"|---|---|",
        f"| Reports generated | {len(all_reports)} |",
        "",
    ]

    if cred_reuse_map:
        lines += ["## Credential Reuse Paths", ""]
        for source_cred, targets in cred_reuse_map.items():
            lines.append(
                f"- Credential `{source_cred}` worked on **{len(targets)}** device(s): "
                + ", ".join(f"`{t}`" for t in targets)
            )
        lines.append("")

    if all_reports:
        lines += ["## Individual Reports", ""]
        for rp in all_reports:
            lines.append(f"- [{Path(rp).name}]({rp})")
        lines.append("")

    summary_path = Path("reports") / "network_summary.md"
    summary_path.parent.mkdir(exist_ok=True)
    summary_path.write_text("\n".join(lines), encoding="utf-8")
    print(f"\nNetwork summary: {summary_path}\n")
    logger.info("network_audit.summary_written", path=str(summary_path), devices=len(visited))


def run_network_audit(
    seeds: list[str],
    max_devices: int = 20,
) -> None:
    """BFS network audit from seed IP(s).

    Invariants:
      I1: queue ∩ visited = ∅  (no device audited twice)
      I2: |visited| strictly +1 per iteration
      I3: |queue| ≤ |V| - |visited|, V finite → guaranteed termination

    Credential propagation: creds found on device A are tried on device B
    before falling back to the default credential table.
    """
    queue: deque[str] = deque(seeds)
    visited: set[str] = set()
    cred_pool: list[tuple[str, str]] = []
    all_reports: list[str] = []
    # Maps "username" → [targets where this cred was reused from the pool]
    cred_reuse_map: dict[str, list[str]] = {}

    while queue and len(visited) < max_devices:
        target = queue.popleft()
        if target in visited:   # I1 guard (defensive; should not trigger)
            continue

        logger.info(
            "network_audit.start",
            target=target,
            audited=len(visited),
            queued=len(queue),
        )

        # Try pool creds before using configured defaults
        working_cred = _find_working_credential(target, cred_pool)
        if working_cred:
            cred_reuse_map.setdefault(working_cred[0], []).append(target)

        result = run_audit(
            target,
            credential_override=working_cred,
            visited_targets=visited | {target},
        )
        visited.add(target)   # I2: always increment even on failure

        if result:
            if result.get("report_path"):
                all_reports.append(result["report_path"])

            # Propagate newly discovered credentials to pool
            new_creds = extract_propagatable_creds(result)
            for c in new_creds:
                if c not in cred_pool:
                    cred_pool.append(c)
                    logger.info(
                        "network_audit.new_cred",
                        source_target=target,
                        username=c[0],
                    )

            # BFS expansion: add LLDP/ARP discovered neighbors
            for neighbor in result.get("discovery_queue", []):
                if neighbor not in visited:
                    queue.append(neighbor)

        logger.info(
            "network_audit.progress",
            audited=len(visited),
            queued=len(queue),
            cred_pool_size=len(cred_pool),
        )

    if queue:
        logger.warning(
            "network_audit.truncated",
            remaining=len(queue),
            max_devices=max_devices,
        )

    _write_network_summary(all_reports, visited, cred_reuse_map)


# ---------------------------------------------------------------------------
# CLI entry point
# ---------------------------------------------------------------------------

def main() -> None:
    parser = argparse.ArgumentParser(description="Switch Security Audit Agent")

    target_group = parser.add_mutually_exclusive_group()
    target_group.add_argument("--target", help="Single target IP or hostname")
    target_group.add_argument("--targets", nargs="+", help="Multiple seed IPs for BFS")
    target_group.add_argument("--target-file", help="File with one IP per line (BFS seeds)")

    parser.add_argument("--session-id", default=None, help="Resume a previous session by ID")
    parser.add_argument(
        "--max-devices", type=int, default=20,
        help="BFS upper bound: max devices to audit (default: 20)",
    )
    args = parser.parse_args()

    # Resolve seed list
    if args.targets:
        seeds = args.targets
    elif args.target_file:
        seeds = [
            line.strip() for line in Path(args.target_file).read_text().splitlines()
            if line.strip() and not line.startswith("#")
        ]
    else:
        seeds = [args.target or "192.168.1.1"]

    if len(seeds) == 1 and args.session_id:
        # Single-device resume
        run_audit(target=seeds[0], session_id=args.session_id)
    elif len(seeds) == 1:
        run_audit(target=seeds[0])
    else:
        run_network_audit(seeds=seeds, max_devices=args.max_devices)


if __name__ == "__main__":
    main()
