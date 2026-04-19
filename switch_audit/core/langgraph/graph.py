"""
Audit graph topology — Phase 1 + memory layer.

Flow:
  START → profiler → search_memory → adviser → executor → analyze → store_success → _route
                                                                                  → adviser (loop)
                                                                                  └→ report → END

profiler       runs every iteration but returns {} after the first (idempotent).
search_memory  queries ChromaDB for prior findings; populates enriched_strategy (runs once).
adviser        picks the next pending check_id (sequential in Phase 1).
executor       runs the check via DeviceAccessLayer; always returns a CheckResult.
analyze        extracts Facts and updates AttackChains from the latest CheckResult.
store_success  persists new Facts and confirmed chains back to ChromaDB.
_route         loops to adviser while pending_checks remain; otherwise goes to report.
report         writes the Markdown report and marks status = "completed".
"""

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from switch_audit.core.langgraph.nodes import (
    adviser,
    analyze,
    executor,
    profiler,
    report,
    search_memory,
    store_success,
)
from switch_audit.core.langgraph.state import AuditState
from switch_audit.core.logging import logger

_MAX_TRIALS = 12  # safety ceiling; methodology has 10 checks, allow headroom


def _route(state: AuditState) -> str:
    """Route after store_success: loop to adviser or terminate to report."""
    if state["status"] != "running":
        return "report"
    if not state.get("pending_checks"):
        logger.info("graph.route.all_checks_done", trials=state["trial_count"])
        return "report"
    if state["trial_count"] >= _MAX_TRIALS:
        logger.info("graph.route.max_trials", trials=state["trial_count"])
        return "report"
    return "adviser"


def build_graph() -> CompiledStateGraph:
    builder = StateGraph(AuditState)

    builder.add_node("profiler", profiler)
    builder.add_node("search_memory", search_memory)
    builder.add_node("adviser", adviser)
    builder.add_node("executor", executor)
    builder.add_node("analyze", analyze)
    builder.add_node("store_success", store_success)
    builder.add_node("report", report)

    builder.add_edge(START, "profiler")
    builder.add_edge("profiler", "search_memory")
    builder.add_edge("search_memory", "adviser")
    builder.add_edge("adviser", "executor")
    builder.add_edge("executor", "analyze")
    builder.add_edge("analyze", "store_success")
    builder.add_conditional_edges(
        "store_success", _route, {"adviser": "adviser", "report": "report"}
    )
    builder.add_edge("report", END)

    graph = builder.compile(checkpointer=MemorySaver(), name="switch-audit-v2")
    logger.info("graph.built", max_trials=_MAX_TRIALS)
    return graph
