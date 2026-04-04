"""Entry point for the switch audit agent.

Usage:
    uv run python -m switch_audit.main --target 192.168.1.1

For LangSmith tracing, set in .env:
    LANGCHAIN_TRACING_V2=true
    LANGCHAIN_API_KEY=<your-key>
    LANGCHAIN_PROJECT=switch-audit
"""

import argparse
import uuid

from switch_audit.core.config import settings
from switch_audit.core.langgraph.graph import build_graph
from switch_audit.core.logging import logger


def run_audit(target: str, session_id: str | None = None) -> None:
    session_id = session_id or str(uuid.uuid4())
    logger.info(
        "audit.start",
        project=settings.PROJECT_NAME,
        environment=settings.ENVIRONMENT.value,
        target=target,
        session_id=session_id,
        langsmith_tracing=settings.LANGCHAIN_TRACING_V2,
    )

    graph = build_graph()

    initial_state = {
        "messages": [],
        "session_id": session_id,
        "target": target,
        "hypothesis": "",
        "observations": [],
        "executed_commands": [],
        "trial_count": 0,
        "status": "running",
    }
    config = {"configurable": {"thread_id": session_id}}

    result = graph.invoke(initial_state, config=config)

    logger.info(
        "audit.complete",
        session_id=session_id,
        trials=result["trial_count"],
        observations=len(result["observations"]),
        status=result["status"],
    )

    # Time-travel demo: show every checkpointed state transition
    logger.info("audit.checkpoint_history")
    for state_snapshot in graph.get_state_history(config):
        logger.info(
            "checkpoint",
            step=state_snapshot.metadata.get("step"),
            trial_count=state_snapshot.values.get("trial_count"),
            hypothesis=state_snapshot.values.get("hypothesis"),
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Switch Vulnerability Audit Agent")
    parser.add_argument("--target", default="192.168.1.1", help="Target device IP or hostname")
    parser.add_argument("--session-id", default=None, help="Resume a previous session by ID")
    args = parser.parse_args()

    run_audit(target=args.target, session_id=args.session_id)


if __name__ == "__main__":
    main()
