"""LangGraph审计工作流程。

图拓扑（占位符）：

[开始]
   │
思考 ──── 生成假设
   │
行动 ──── 派遣探测，记录观察
   │
是否继续？
   ├── "思考"（循环返回）
   └── 结束

内存检查点意味着每个状态转换都会在内存中持久化，并且可以通过 graph.get_state() / graph.update_state() 进行时间旅行。
当需要持久化存储时，将 MemorySaver 替换为 AsyncPostgresSaver。
"""

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from switch_audit.core.langgraph.nodes import act, think
from switch_audit.core.langgraph.state import AuditState
from switch_audit.core.logging import logger

# 每个会话的最大试验次数
_MAX_TRIALS = 8


def _should_continue(state: AuditState) -> str:
    """路由函数：决定是否继续探测或停止。"""
    if state["status"] != "running":
        return END
    if state["trial_count"] >= _MAX_TRIALS:
        logger.info("audit.max_trials_reached", trials=state["trial_count"])
        return END
    return "think"


def build_graph() -> CompiledStateGraph:
    """构建并编译具有内存检查点的审计图。"""
    builder = StateGraph(AuditState)

    builder.add_node("think", think)
    builder.add_node("act", act)

    builder.add_edge(START, "think")
    builder.add_edge("think", "act")
    builder.add_conditional_edges("act", _should_continue, {"think": "think", END: END})

    checkpointer = MemorySaver()
    graph = builder.compile(checkpointer=checkpointer, name="switch-audit")

    logger.info("graph.built", nodes=["think", "act"], max_trials=_MAX_TRIALS)
    return graph
