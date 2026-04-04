"""图节点实现。

每个节点都是纯函数：AuditState -> dict（部分状态更新）。
节点只返回它们修改的字段，不直接修改状态对象。

当前节点（Iter 1）：
  think   — 读取结构化状态，调用 LLM，产出 reasoning + proposed_command
  act     — 执行 proposed_command，写入 CommandRecord，维护去重列表

Iter 2 将新增：
  analyze — 从最新 CommandRecord 中提取 Facts，推断 AttackChains，更新 next_probes
"""

import json
import logging
import re
from datetime import datetime, timezone
from typing import Final

from langchain_openai import ChatOpenAI

# 抑制 netmiko / paramiko 的 read_channel 调试噪音
logging.getLogger("netmiko").setLevel(logging.WARNING)
logging.getLogger("paramiko").setLevel(logging.WARNING)

from switch_audit.core.config import settings
from switch_audit.core.langgraph.state import AuditState, CommandRecord
from switch_audit.core.logging import logger
from switch_audit.prompts import load_system_prompt
from switch_audit.tools import ssh_exec

_llm = ChatOpenAI(
    model=settings.DEFAULT_LLM_MODEL,
    temperature=settings.DEFAULT_LLM_TEMPERATURE,
    api_key=settings.OPENAI_API_KEY,
    base_url=settings.OPENAI_BASE_URL,
)

# Iter 0 脚手架：临时侦察清单，告知 LLM 还有哪些方向未覆盖。
# Iter 3（动态规划节点）落地后删除。
_RECON_CHECKLIST: Final[list[str]] = [
    "show version",
    "show running-config",
    "show ip interface brief",
    "show mac address-table",
    "show vlan",
    "show spanning-tree",
    "show spanning-tree detail",
    "show ip ssh",
    "show line vty 0 4",
    "show users",
    "show privilege",
    "show cdp neighbors",
    "show interfaces trunk",
    "show port-security",
    "show ip http server status",
]

# think() 构建上下文时最多使用最近 N 条命令记录（Iter 4 引入摘要前的临时限制）
_CONTEXT_WINDOW_RECENT = 6


def _build_think_context(state: AuditState) -> str:
    """构建 think() 的 user message。

    结构化地提供三类信息：
    1. 去重约束（已执行命令）
    2. 调查引导（next_probes + 剩余清单）
    3. 近期观察（command_history 的最近 N 条）

    近期观察只取最后 N 条，是 Iter 4 记忆管理的前置约定：
    长 session 不会因为历史太多而撑爆 context window。
    """
    executed: list[str] = state.get("executed_commands", [])
    next_probes: list[str] = state.get("next_probes", [])

    # 剩余清单 = 临时清单 - 已执行（Iter 3 后替换为动态计划）
    remaining = [c for c in _RECON_CHECKLIST if c not in executed]

    # 已执行命令
    executed_section = (
        "\n".join(f"  - {c}" for c in executed) if executed else "  (none yet)"
    )

    # 调查优先级：
    # 1. next_probes（来自 attack_chains.verification_needed，Iter 2 后有内容）
    # 2. 剩余清单（Iter 0 脚手架）
    if next_probes:
        guidance_section = (
            "## Priority: verify these attack chain hypotheses first\n"
            + "\n".join(f"  - {p}" for p in next_probes)
            + "\n\n## Also uncovered:\n"
            + ("\n".join(f"  - {c}" for c in remaining) if remaining else "  (all covered)")
        )
    else:
        guidance_section = (
            "## Suggested next directions (prefer these):\n"
            + ("\n".join(f"  - {c}" for c in remaining) if remaining else "  (all covered)")
        )

    # 近期命令历史（最多 _CONTEXT_WINDOW_RECENT 条）
    recent_history = state.get("command_history", [])[-_CONTEXT_WINDOW_RECENT:]
    if recent_history:
        history_section = "\n\n".join(
            f"[trial={r['trial']}] $ {r['command']}\n{r['output']}"
            for r in recent_history
        )
    else:
        history_section = "(none yet)"

    # 已发现的攻击链摘要（Iter 2 后有内容，Iter 1 始终为空）
    chains = state.get("attack_chains", [])
    if chains:
        chains_section = "\n".join(
            f"  - [{c['id']}] {c['title']} "
            f"(severity={c['severity']}, confidence={c['confidence']})"
            + (f"\n    needs verification: {c['verification_needed']}" if c.get("verification_needed") else "")
            for c in chains
        )
    else:
        chains_section = "  (none yet — analyze node not yet active)"

    return (
        f"Target: {state['target']}"
        + (f" | OS: {state['device_os']}" if state.get("device_os") else "")
        + f" | Trial: {state['trial_count']}\n\n"
        f"## Commands already executed — DO NOT propose any of these:\n"
        f"{executed_section}\n\n"
        f"{guidance_section}\n\n"
        f"## Attack chains discovered so far:\n"
        f"{chains_section}\n\n"
        f"## Recent observations (last {_CONTEXT_WINDOW_RECENT} commands):\n"
        f"{history_section}\n\n"
        f"Generate next hypothesis."
    )


def _parse_think_response(raw: str) -> tuple[str, str]:
    """从 LLM 输出中解析 reasoning 和 proposed_command。

    支持两种格式：
    1. ```json {"reasoning": "...", "proposed_command": "..."}```
    2. 旧格式兼容：{"reasoning": "...", "proposed_action": "..."}

    解析失败时返回原始文本作为 reasoning，"show version" 作为安全默认命令。
    """
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    text = match.group(1) if match else raw

    try:
        data = json.loads(text)
        reasoning = data.get("reasoning", raw)
        # 兼容旧字段名 proposed_action（Iter 0 遗留）
        command = data.get("proposed_command") or data.get("proposed_action", "show version")
        return reasoning, command
    except (json.JSONDecodeError, AttributeError):
        return raw, "show version"


def think(state: AuditState) -> dict:
    """读取结构化状态，调用 LLM，产出 reasoning 和 proposed_command。

    输出两个独立字段（替代原 hypothesis str）：
    - reasoning: LLM 的推理过程，可解释，供人工审阅
    - proposed_command: 干净的单条命令字符串，act() 直接使用，无需解析
    """
    logger.info(
        "node.think",
        trial=state["trial_count"],
        target=state["target"],
        executed_count=len(state.get("executed_commands", [])),
        chains_found=len(state.get("attack_chains", [])),
        next_probes=state.get("next_probes", []),
    )

    user_msg = _build_think_context(state)

    response = _llm.invoke([
        {"role": "system", "content": load_system_prompt()},
        {"role": "user", "content": user_msg},
    ])

    reasoning, proposed_command = _parse_think_response(response.content.strip())

    logger.info(
        "node.think.result",
        proposed_command=proposed_command,
        reasoning_preview=reasoning[:100],
    )

    return {
        "reasoning": reasoning,
        "proposed_command": proposed_command,
    }


def act(state: AuditState) -> dict:
    """执行 proposed_command，写入 CommandRecord，维护去重列表。

    直接读取 state["proposed_command"]，无需从 JSON blob 解析。
    去重保护：命令已执行时写入 skipped_duplicate 记录，不触发 SSH。
    """
    command = state.get("proposed_command", "show version")
    executed: list[str] = state.get("executed_commands", [])
    timestamp = datetime.now(timezone.utc).isoformat()

    logger.info(
        "node.act",
        command=command,
        trial=state["trial_count"],
        target=state["target"],
    )

    # 程序级去重：即使模型违反约束，也不空转浪费 SSH 配额
    if command in executed:
        logger.warning("node.act.duplicate_skipped", command=command)
        record: CommandRecord = {
            "trial": state["trial_count"],
            "command": command,
            "output": "(This command was already executed. Choose a different direction.)",
            "status": "skipped_duplicate",
            "timestamp": timestamp,
        }
        return {
            "command_history": state.get("command_history", []) + [record],
            "executed_commands": executed,     # 不追加，命令未实际执行
            "trial_count": state["trial_count"] + 1,
        }

    raw_output = ssh_exec(
        host=state["target"],
        port=settings.SSH_PORT,
        username=settings.SSH_USERNAME,
        password=settings.SSH_PASSWORD,
        command=command,
        timeout=settings.SSH_TIMEOUT,
        device_type=settings.SSH_DEVICE_TYPE,
    )

    status = "ssh_error" if raw_output.startswith("[ssh_error]") else "ok"
    record = {
        "trial": state["trial_count"],
        "command": command,
        "output": raw_output,
        "status": status,
        "timestamp": timestamp,
    }

    logger.info("node.act.result", status=status, output_preview=raw_output[:200])

    return {
        "command_history": state.get("command_history", []) + [record],
        "executed_commands": executed + [command],
        "trial_count": state["trial_count"] + 1,
    }
