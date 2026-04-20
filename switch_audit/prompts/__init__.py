"""
Prompt loading and user-message construction.

System prompts (static markdown) live in this directory.
User messages (dynamic, state-derived) are built here as plain Python strings
so the construction logic stays co-located with the prompt it serves.
"""

from pathlib import Path

from switch_audit.tools.device_access import load_methodology

_PROMPTS_DIR = Path(__file__).parent


def load_analyze_prompt() -> str:
    return (_PROMPTS_DIR / "analyze.md").read_text(encoding="utf-8")


def load_adviser_prompt() -> str:
    return (_PROMPTS_DIR / "adviser.md").read_text(encoding="utf-8")


def build_adviser_user_message(state: dict) -> str:
    """Build the per-invocation user message for the adviser LLM call.

    Sections (all derived from state — no LLM input here):
      1. Device context
      2. Pending checks with security_relevance from methodology
      3. Attack chains that need verification (priority signal)
      4. Memory hints from prior audits (enriched_strategy)
    """
    methodology = {c["id"]: c for c in load_methodology()}
    pending = state.get("pending_checks", [])

    # 1. Device context
    device_section = (
        f"Device: {state.get('device_vendor', 'Unknown')} {state.get('device_os', 'unknown')}\n"
        f"Access method: {state.get('access_method', 'unknown')} | "
        f"Trial: {state.get('trial_count', 0)}"
    )

    # 2. Pending checks
    if pending:
        lines = []
        for cid in pending:
            spec = methodology.get(cid, {})
            lines.append(
                f"  - {cid}: {spec.get('description', '')} "
                f"[{spec.get('security_relevance', '')}]"
            )
        pending_section = "## Pending Checks\n" + "\n".join(lines)
    else:
        pending_section = "## Pending Checks\n  (none — all checks complete)"

    # 3. Attack chains awaiting verification
    urgent = [
        c for c in state.get("attack_chains", [])
        if c.get("verification_needed") and c.get("confidence") != "refuted"
    ]
    if urgent:
        chain_lines = [
            f"  [{c['id']}] \"{c['title']}\" "
            f"(confidence={c['confidence']}, severity={c['severity']}) "
            f"→ needs: {', '.join(c['verification_needed'])}"
            for c in urgent
        ]
        chains_section = "## Attack Chains Awaiting Verification\n" + "\n".join(chain_lines)
    else:
        chains_section = "## Attack Chains Awaiting Verification\n  (none)"

    # 4. Memory hints
    hints = state.get("enriched_strategy", "").strip()
    device_os = state.get("device_os", "this device type")
    hints_section = (
        f"## Memory Hints (prior findings on {device_os})\n"
        + (hints if hints else "  (cold start — no prior findings for this device type)")
    )

    return "\n\n".join([device_section, pending_section, chains_section, hints_section])
