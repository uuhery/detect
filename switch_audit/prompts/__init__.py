"""
Prompt loading — system prompts (static markdown) live in this directory.
"""

from pathlib import Path

_PROMPTS_DIR = Path(__file__).parent


def load_analyze_prompt() -> str:
    return (_PROMPTS_DIR / "analyze.md").read_text(encoding="utf-8")
