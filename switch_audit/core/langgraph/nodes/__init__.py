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


def think(state: AuditState) -> dict:
    """通过查询 LLM 生成下一个审计假设。"""
    logger.info(
        "node.think",
        trial=state["trial_count"],
        target=state["target"],
        previous_hypothesis=state["hypothesis"] or "<none>",
    )

    user_msg = (
        f"Target device: {state['target']}\n"
        f"Trial: {state['trial_count']}\n"
        f"Previous hypothesis: {state['hypothesis'] or 'none'}\n"
        f"Observations so far:\n"
        + ("\n".join(f"  - {o}" for o in state["observations"]) or "  (none yet)")
        + "\n\nGenerate the next hypothesis."
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
    logger.info(
        "node.act",
        command=command,
        trial=state["trial_count"],
        target=state["target"],
    )

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
        "trial_count": state["trial_count"] + 1,
    }
