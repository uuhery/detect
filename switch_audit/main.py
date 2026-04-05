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
from datetime import datetime, timezone

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
        # LangGraph managed
        "messages": [],
        # 会话标识
        "session_id": session_id,
        "started_at": datetime.now(timezone.utc).isoformat(),
        # 目标设备
        "target": target,
        "device_os": "",           # analyze 节点从 show version 填充
        # 执行日志
        "command_history": [],
        "executed_commands": [],
        # 分析产物（Iter 2 的 analyze 节点填充，此处初始化为空）
        "facts": [],
        "attack_chains": [],
        # 命令候选集（Iter 3 的 analyze 节点从 running-config 派生）
        "available_commands": [],
        # 调查方向（Iter 3 的 plan 节点填充）
        "directions": [],
        # 调查引导（Iter 2 后由 analyze 节点维护）
        "next_probes": [],
        # think 节点产物
        "reasoning": "",
        "proposed_command": "",
        # 控制
        "trial_count": 0,
        "status": "running",
        # 内部路由辅助（plan 节点写入，路由函数读取）
        "_plan_confirmed_count": -1,
    }
    config = {"configurable": {"thread_id": session_id}}

    result = graph.invoke(initial_state, config=config)

    logger.info(
        "audit.complete",
        session_id=session_id,
        trials=result["trial_count"],
        commands_executed=len(result["command_history"]),
        facts_found=len(result["facts"]),
        chains_found=len(result["attack_chains"]),
        status=result["status"],
    )

    # Time-travel demo: show every checkpointed state transition
    logger.info("audit.checkpoint_history")
    for state_snapshot in graph.get_state_history(config):
        logger.info(
            "checkpoint",
            step=state_snapshot.metadata.get("step"),
            trial_count=state_snapshot.values.get("trial_count"),
            reasoning_preview=state_snapshot.values.get("reasoning", "")[:80],
        )


def main() -> None:
    parser = argparse.ArgumentParser(description="Switch Vulnerability Audit Agent")
    parser.add_argument("--target", default="192.168.1.1", help="Target device IP or hostname")
    parser.add_argument("--session-id", default=None, help="Resume a previous session by ID")
    args = parser.parse_args()

    run_audit(target=args.target, session_id=args.session_id)


if __name__ == "__main__":
    main()
