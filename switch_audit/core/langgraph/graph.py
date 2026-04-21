"""
Audit graph topology.

Flow:
  START → profiler → search_memory → adviser → executor → enrich → analyze → store_success → _route
                                                                                            → adviser (loop)
                                                                                            └→ report → END

profiler       runs every iteration but returns {} after the first (idempotent).
search_memory  queries ChromaDB for prior findings; populates enriched_strategy (runs once).
adviser        picks the next pending check_id (pure rule-based, zero LLM calls).
executor       runs the check via DeviceAccessLayer; always returns a CheckResult.
enrich         queries NIST NVD for CVEs matching device OS+version (idempotent, cached 6h).
analyze        extracts Facts and updates AttackChains from the latest CheckResult.
store_success  validates chain integrity (ghost fact_ids, confidence contradictions).
_route         loops to adviser while pending_checks remain; otherwise goes to report.
report         writes the Markdown report and marks status = "completed".
"""

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from switch_audit.core.langgraph.nodes import (
    adviser,
    analyze,
    discover,
    enrich,
    executor,
    profiler,
    report,
    search_memory,
    store_success,
)
from switch_audit.core.langgraph.state import AuditState
from switch_audit.core.logging import logger
from switch_audit.tools.device_access import load_methodology


def _compute_max_trials() -> int:
    """Derive trial ceiling from methodology size.

    Base: one trial per check.
    Buffer: 40% headroom for verification_needed re-runs.
    Formula: max(15, ceil(n_checks * 1.4))

    With 16 checks → 23 trials. Scales automatically as checks are added.
    """
    n = len(load_methodology())
    return max(15, int(n * 1.4) + (1 if n * 1.4 % 1 else 0))


def _route(state: AuditState, max_trials: int) -> str:
    """Route after store_success: loop to adviser or terminate to report."""
    if state["status"] != "running":
        return "report"
    if state["trial_count"] >= max_trials:
        logger.info("graph.route.max_trials", trials=state["trial_count"])
        return "report"
    if state.get("pending_checks"):
        return "adviser"
    logger.info("graph.route.all_checks_done", trials=state["trial_count"])
    return "report"


def build_graph() -> CompiledStateGraph:
    max_trials = _compute_max_trials()

    # Capture max_trials in closure for _route
    def route(state: AuditState) -> str:
        return _route(state, max_trials)

    builder = StateGraph(AuditState)

    builder.add_node("profiler", profiler)
    builder.add_node("search_memory", search_memory)
    builder.add_node("adviser", adviser)
    builder.add_node("executor", executor)
    builder.add_node("discover", discover)
    builder.add_node("enrich", enrich)
    builder.add_node("analyze", analyze)
    builder.add_node("store_success", store_success)
    builder.add_node("report", report)

    # Checks whose results feed the discover node for lateral target extraction:
    #   lldp_neighbors  → direct neighbor IPs
    #   arp_table       → same-subnet active hosts
    #   routing_table   → reachable subnets → candidate management IPs
    #   running_config  → TACACS/BGP peer/NTP/GRE tunnel IPs
    _DISCOVER_TRIGGERS = {"lldp_neighbors", "arp_table", "routing_table", "running_config"}

    def _route_to_discover(state: AuditState) -> str:
        results = state.get("check_results", [])
        if results and results[-1]["check_id"] in _DISCOVER_TRIGGERS:
            return "discover"
        return "enrich"

    builder.add_edge(START, "profiler")
    builder.add_edge("profiler", "search_memory")
    builder.add_edge("search_memory", "adviser")
    builder.add_edge("adviser", "executor")
    builder.add_conditional_edges(
        "executor",
        _route_to_discover,
        {"discover": "discover", "enrich": "enrich"},
    )
    builder.add_edge("discover", "enrich")
    builder.add_edge("enrich", "analyze")
    builder.add_edge("analyze", "store_success")
    builder.add_conditional_edges(
        "store_success", route, {"adviser": "adviser", "report": "report"}
    )
    builder.add_edge("report", END)

    graph = builder.compile(checkpointer=MemorySaver(), name="switch-audit-v2")
    logger.info("graph.built", max_trials=max_trials, n_checks=len(load_methodology()))
    return graph
