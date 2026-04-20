"""
Entry point for the switch audit agent.

Usage:
    uv run python -m switch_audit.main --target 192.168.1.1
"""

import argparse
import uuid
from datetime import datetime, timezone

from switch_audit.core.config import settings
from switch_audit.core.langgraph.graph import build_graph
from switch_audit.core.logging import logger


def run_audit(target: str, session_id: str | None = None) -> None:
    session_id = session_id or str(uuid.uuid4())
    logger.info(
        "audit.start",
        target=target,
        session_id=session_id,
        model=settings.DEFAULT_LLM_MODEL,
    )

    graph = build_graph()

    # Minimal initial state — profiler fills device_os/vendor/access_method/pending_checks
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
        "cve_context": None,  # None = not yet queried
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
        # Control
        "trial_count": 0,
        "status": "running",
        "report_path": "",
    }

    config = {"configurable": {"thread_id": session_id}}
    result = graph.invoke(initial_state, config=config)

    logger.info(
        "audit.complete",
        session_id=session_id,
        trials=result["trial_count"],
        checks_done=len(result.get("completed_checks", [])),
        facts_found=len(result.get("facts", [])),
        chains_found=len(result.get("attack_chains", [])),
        status=result["status"],
        report_path=result.get("report_path", ""),
    )

    if result.get("report_path"):
        print(f"\nReport: {result['report_path']}\n")


def main() -> None:
    parser = argparse.ArgumentParser(description="Switch Security Audit Agent")
    parser.add_argument("--target", default="192.168.1.1", help="Target IP or hostname")
    parser.add_argument("--session-id", default=None, help="Resume a previous session by ID")
    args = parser.parse_args()
    run_audit(target=args.target, session_id=args.session_id)


if __name__ == "__main__":
    main()
