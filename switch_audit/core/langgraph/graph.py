"""LangGraph 审计工作流程。

图拓扑（Iter 2）：

[开始]
   │
思考 ──── 生成 reasoning + proposed_command
   │
行动 ──── 执行命令，写入 CommandRecord
   │
分析 ──── 提取 Facts，推断 AttackChains，更新 next_probes
   │
是否继续？
   ├── "思考"（循环返回）
   └── 结束

路由函数从 act 后移到 analyze 后：
  act → analyze 用直连 edge（analyze 内部处理 skipped_duplicate 的跳过逻辑）。
  路由判断依赖 trial_count（act 写入）和 status（不变），analyze 不修改这两个字段。
  路由函数与 Iter 1 完全相同，只是调用位置从 act 后变为 analyze 后。

内存检查点：每个状态转换都在内存中持久化，支持 graph.get_state() / graph.update_state() 时间旅行。
"""

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from switch_audit.core.langgraph.nodes import act, analyze, think
from switch_audit.core.langgraph.state import AuditState
from switch_audit.core.logging import logger

# 每个会话的最大试验次数
_MAX_TRIALS = 20


def _should_continue(state: AuditState) -> str:
    """路由函数：决定是否继续探测或停止。与 Iter 1 逻辑完全一致。"""
    if state["status"] != "running":
        return END
    if state["trial_count"] >= _MAX_TRIALS:
        logger.info("audit.max_trials_reached", trials=state["trial_count"])
        return END
    return "think"


def build_graph() -> CompiledStateGraph:
    """构建并编译具有内存检查点的审计图（Iter 2：think → act → analyze 三节点循环）。"""
    builder = StateGraph(AuditState)

    builder.add_node("think", think)
    builder.add_node("act", act)
    builder.add_node("analyze", analyze)          # Iter 2 新增

    builder.add_edge(START, "think")
    builder.add_edge("think", "act")
    builder.add_edge("act", "analyze")             # act 后无条件进 analyze
    builder.add_conditional_edges(                 # 路由从 act 后移到 analyze 后
        "analyze",
        _should_continue,
        {"think": "think", END: END},
    )

    checkpointer = MemorySaver()
    graph = builder.compile(checkpointer=checkpointer, name="switch-audit")

    logger.info("graph.built", nodes=["think", "act", "analyze"], max_trials=_MAX_TRIALS)
    return graph
