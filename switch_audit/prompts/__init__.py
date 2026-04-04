"""Load prompts from markdown files."""

from pathlib import Path


def load_system_prompt() -> str:
    prompt_path = Path(__file__).parent / "system.md"
    return prompt_path.read_text(encoding="utf-8")


def load_analyze_prompt() -> str:
    prompt_path = Path(__file__).parent / "analyze.md"
    return prompt_path.read_text(encoding="utf-8")
