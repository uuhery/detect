"""Load prompts from markdown files.

知识库注入机制：
  load_command_kb()  — 解析 ios_xe_commands.yaml，返回结构化数据
  render_kb_section() — 将知识库渲染成 Markdown 文本块，注入进两个 prompt
  load_system_prompt() / load_analyze_prompt() — 在原始 prompt 后追加知识库块

这样 system.md 和 analyze.md 都从同一份 YAML 获取命令知识，
模型看到的合法命令集始终一致，不存在两套来源。
"""

from __future__ import annotations

from functools import lru_cache
from pathlib import Path

import yaml

_PROMPTS_DIR = Path(__file__).parent
_KB_PATH = _PROMPTS_DIR.parent / "knowledge" / "ios_xe_commands.yaml"


@lru_cache(maxsize=1)
def load_command_kb() -> list[dict]:
    """解析命令知识库 YAML，返回 categories 列表。

    使用 lru_cache 避免每次节点调用都重新读盘。
    返回结构：
      [
        {"id": "identity", "name": "...", "desc": "...",
         "commands": [{"cmd": "show version", "desc": "..."}, ...]},
        ...
      ]
    """
    raw = yaml.safe_load(_KB_PATH.read_text(encoding="utf-8"))
    return raw.get("categories", [])


def render_kb_section() -> str:
    """将命令知识库渲染为 Markdown 文本块，供注入进 prompt。

    渲染格式：每个类别一个二级标题，命令以 backtick 行列出。
    例：
      ### 设备身份与全局配置
      （获取设备型号、版本、完整配置，是每次审计的起点）
      - `show version` — IOS XE 版本、硬件型号、序列号、运行时长
      - `show running-config` — 完整运行配置，最高信息密度来源
    """
    lines: list[str] = [
        "## IOS XE Command Knowledge Base",
        "",
        "以下是所有合法的只读审计命令，按功能分类。",
        "**你只能使用此列表中的命令**，不得使用未列出的命令。",
        "",
    ]
    for cat in load_command_kb():
        lines.append(f"### {cat['name']}")
        lines.append(f"（{cat['desc']}）")
        for entry in cat.get("commands", []):
            lines.append(f"- `{entry['cmd']}` — {entry['desc']}")
        lines.append("")
    return "\n".join(lines)


def all_valid_commands() -> list[str]:
    """返回知识库中所有命令的扁平列表，供代码层去重/验证使用。"""
    return [
        entry["cmd"]
        for cat in load_command_kb()
        for entry in cat.get("commands", [])
    ]


def load_system_prompt() -> str:
    base = (_PROMPTS_DIR / "system.md").read_text(encoding="utf-8")
    kb = render_kb_section()
    return f"{base}\n\n---\n\n{kb}"


def load_analyze_prompt() -> str:
    base = (_PROMPTS_DIR / "analyze.md").read_text(encoding="utf-8")
    kb = render_kb_section()
    return f"{base}\n\n---\n\n{kb}"
