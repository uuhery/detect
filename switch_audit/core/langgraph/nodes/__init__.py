"""图节点实现。

每个节点都是纯函数：AuditState -> dict（部分状态更新）。
节点必须永远不直接修改状态；它们只返回它们修改的字段。

当前节点：
  思考 — 调用 LLM 生成下一个审计假设
  行动 — 占位符：将原子探测派遣到设备
"""

from langchain_openai import ChatOpenAI

from switch_audit.core.config import settings
from switch_audit.core.langgraph.state import AuditState
from switch_audit.core.logging import logger
from switch_audit.prompts import load_system_prompt

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


def act(state: AuditState) -> dict:
    """执行当前假设隐含的原子探测。"""
    logger.info(
        "node.act",
        hypothesis=state["hypothesis"],
        trial=state["trial_count"],
    )
    # TODO: 替换为真实的工具调用 — send_raw_packet / read_device_state
    observation = f"placeholder_observation_for_{state['hypothesis']}"
    return {
        "observations": state["observations"] + [observation],
        "trial_count": state["trial_count"] + 1,
    }
