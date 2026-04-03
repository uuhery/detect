"""LangGraph audit workflow.

Graph topology (placeholder):

    [START]
       │
    think  ──── generates hypothesis
       │
     act   ──── dispatches probe, records observation
       │
    should_continue?
       ├── "think"  (loop back)
       └── END

The MemorySaver checkpointer means every state transition is persisted
in memory and can be time-travelled with graph.get_state() / graph.update_state().
Swap MemorySaver for AsyncPostgresSaver when you need durable storage.
"""

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from switch_audit.core.langgraph.nodes import act, think
from switch_audit.core.langgraph.state import AuditState
from switch_audit.core.logging import logger

# Maximum trials per session (safety limit during early experiments)
_MAX_TRIALS = 10


def _should_continue(state: AuditState) -> str:
    """Routing function: decide whether to keep probing or stop."""
    if state["status"] != "running":
        return END
    if state["trial_count"] >= _MAX_TRIALS:
        logger.info("audit.max_trials_reached", trials=state["trial_count"])
        return END
    return "think"


def build_graph() -> CompiledStateGraph:
    """Construct and compile the audit graph with an in-memory checkpointer."""
    builder = StateGraph(AuditState)

    builder.add_node("think", think)
    builder.add_node("act", act)

    builder.add_edge(START, "think")
    builder.add_edge("think", "act")
    builder.add_conditional_edges("act", _should_continue, {"think": "think", END: END})

    checkpointer = MemorySaver()
    graph = builder.compile(checkpointer=checkpointer, name="switch-audit")

    logger.info("graph.built", nodes=["think", "act"], max_trials=_MAX_TRIALS)
    return graph
