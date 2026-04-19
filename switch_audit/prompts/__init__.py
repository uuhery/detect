"""
Prompt loading.

Phase 1 only needs analyze.md — there is no system prompt for adviser
(sequential selection, no LLM) or executor (DeviceAccessLayer handles HOW).
"""

from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


def load_analyze_prompt() -> str:
    return (_PROMPTS_DIR / "analyze.md").read_text(encoding="utf-8")
