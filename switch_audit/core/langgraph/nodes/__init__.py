"""图节点实现。

每个节点都是纯函数：AuditState -> dict（部分状态更新）。
节点必须永远不直接修改状态；它们只返回它们修改的字段。

当前节点：
  思考 — 调用 LLM 生成下一个审计假设
  行动 — 通过 SSH 在目标设备上执行探测命令
"""

import json
import logging
import re
from typing import Final

from langchain_openai import ChatOpenAI

# 抑制 netmiko / paramiko 的 read_channel 调试噪音
logging.getLogger("netmiko").setLevel(logging.WARNING)
logging.getLogger("paramiko").setLevel(logging.WARNING)

from switch_audit.core.config import settings
from switch_audit.core.langgraph.state import AuditState
from switch_audit.core.logging import logger
from switch_audit.prompts import load_system_prompt
from switch_audit.tools import ssh_exec

_llm = ChatOpenAI(
    model=settings.DEFAULT_LLM_MODEL,
    temperature=settings.DEFAULT_LLM_TEMPERATURE,
    api_key=settings.OPENAI_API_KEY,
    base_url=settings.OPENAI_BASE_URL,
)

# Iter 0：临时侦察清单，用于告知 LLM 还有哪些方向未覆盖。
# 注意：这是脚手架，Iter 3（动态规划节点）落地后会删除。
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


def think(state: AuditState) -> dict:
    """通过查询 LLM 生成下一个审计假设。"""
    executed: list[str] = state.get("executed_commands", [])
    remaining = [c for c in _RECON_CHECKLIST if c not in executed]

    logger.info(
        "node.think",
        trial=state["trial_count"],
        target=state["target"],
        executed_count=len(executed),
        remaining_count=len(remaining),
    )

    # 结构化的上下文：明确区分"已执行"和"待检查"
    executed_section = (
        "\n".join(f"  - {c}" for c in executed) if executed else "  (none yet)"
    )
    remaining_section = (
        "\n".join(f"  - {c}" for c in remaining) if remaining else "  (all covered)"
    )
    observations_section = (
        "\n\n".join(state["observations"]) if state["observations"] else "(none yet)"
    )

    user_msg = (
        f"Target device: {state['target']}\n"
        f"Trial: {state['trial_count']}\n\n"
        f"## Commands already executed — DO NOT propose any of these again:\n"
        f"{executed_section}\n\n"
        f"## Suggested next directions (prefer these, but you may propose others):\n"
        f"{remaining_section}\n\n"
        f"## Observations so far:\n"
        f"{observations_section}\n\n"
        f"Generate the next hypothesis."
    )

    response = _llm.invoke([
        {"role": "system", "content": load_system_prompt()},
        {"role": "user", "content": user_msg},
    ])

    hypothesis = response.content.strip()
    logger.info("node.think.result", hypothesis=hypothesis[:120])
    return {"hypothesis": hypothesis}


def _extract_proposed_action(hypothesis_raw: str) -> str:
    """从 LLM 输出中提取 proposed_action 字段（兼容 markdown 代码块）。"""
    # 去掉可能的 markdown ```json ... ``` 包裹
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", hypothesis_raw, re.DOTALL)
    text = match.group(1) if match else hypothesis_raw
    try:
        return json.loads(text).get("proposed_action", "id")
    except (json.JSONDecodeError, AttributeError):
        # 解析失败时退回到最安全的只读命令
        return "id"


def act(state: AuditState) -> dict:
    """通过 SSH 在目标设备上执行 LLM 建议的探测命令。"""
    command = _extract_proposed_action(state["hypothesis"])
    executed: list[str] = state.get("executed_commands", [])

    logger.info(
        "node.act",
        command=command,
        trial=state["trial_count"],
        target=state["target"],
    )

    # 程序级去重：即使模型违反约束，也不会空转浪费 SSH 配额
    if command in executed:
        logger.warning("node.act.duplicate_skipped", command=command)
        observation = (
            f"[trial={state['trial_count']}] [SKIPPED: duplicate] $ {command}\n"
            f"(This command was already executed. Choose a different investigation direction.)"
        )
        return {
            "observations": state["observations"] + [observation],
            "executed_commands": executed,
            "trial_count": state["trial_count"] + 1,
        }

    output = ssh_exec(
        host=state["target"],
        port=settings.SSH_PORT,
        username=settings.SSH_USERNAME,
        password=settings.SSH_PASSWORD,
        command=command,
        timeout=settings.SSH_TIMEOUT,
        device_type=settings.SSH_DEVICE_TYPE,
    )

    logger.info("node.act.result", output=output[:200])
    observation = f"[trial={state['trial_count']}] $ {command}\n{output}"
    return {
        "observations": state["observations"] + [observation],
        "executed_commands": executed + [command],
        "trial_count": state["trial_count"] + 1,
    }
