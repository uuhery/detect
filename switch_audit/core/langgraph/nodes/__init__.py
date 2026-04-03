"""Graph node implementations.

Each node is a pure function:  AuditState -> dict (partial state update).
Nodes must never mutate state directly; they return only the fields they change.

Current nodes (all placeholder — no functional logic yet):
  think    — analyse state, produce the next hypothesis
  act      — dispatch the atomic action implied by the hypothesis
  observe  — collect device response and score information gain
"""

from switch_audit.core.langgraph.state import AuditState
from switch_audit.core.logging import logger


def think(state: AuditState) -> dict:
    """Generate the next audit hypothesis based on accumulated observations."""
    logger.info(
        "node.think",
        trial=state["trial_count"],
        target=state["target"],
        previous_hypothesis=state["hypothesis"] or "<none>",
    )
    # TODO: replace with LLM call — query LLM with observations + knowledge base
    return {"hypothesis": f"placeholder_hypothesis_{state['trial_count']}"}


def act(state: AuditState) -> dict:
    """Execute the atomic probe implied by the current hypothesis."""
    logger.info(
        "node.act",
        hypothesis=state["hypothesis"],
        trial=state["trial_count"],
    )
    # TODO: replace with real tool call — send_raw_packet / read_device_state
    observation = f"placeholder_observation_for_{state['hypothesis']}"
    return {
        "observations": state["observations"] + [observation],
        "trial_count": state["trial_count"] + 1,
    }
