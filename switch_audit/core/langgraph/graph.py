"""LangGraph 审计工作流程。

图拓扑（Iter 3）：

[开始]
   │
规划 ──── 生成 directions（BFS 战略决策）
   │
思考 ──── 生成 reasoning + proposed_command（DFS 战术决策）
   │
行动 ──── 执行命令，写入 CommandRecord
   │
分析 ──── 提取 Facts，推断 AttackChains，更新 next_probes
   │
路由判断
   ├── "plan"（有新 confirmed 链 → 重规划）
   ├── "think"（继续探测）
   └── END

路由逻辑（analyze 后）：
  1. status != running → END
  2. trial_count >= _MAX_TRIALS → END
  3. analyze 产出新的 confirmed chain（confirmed_count 增加）→ "plan"（重规划）
  4. 否则 → "think"

为什么把"是否重规划"放在路由函数而不是 analyze 节点：
  - analyze 的职责是感知（提取 Facts / 更新 AttackChains），不做流程控制决策
  - 路由函数是纯代码逻辑，可读性强，LangSmith 中可以直接观察路由结果
  - confirmed_count 是可从 state 计算的客观指标，不依赖 LLM 判断

内存检查点：每个状态转换都在内存中持久化，支持 graph.get_state() / graph.update_state() 时间旅行。
"""

from langgraph.checkpoint.memory import MemorySaver
from langgraph.graph import END, START, StateGraph
from langgraph.graph.state import CompiledStateGraph

from switch_audit.core.langgraph.nodes import act, analyze, plan, think
from switch_audit.core.langgraph.state import AuditState
from switch_audit.core.logging import logger

# 每个会话的最大试验次数
_MAX_TRIALS = 12  # Iter 3 增加上限：plan 节点让每次 trial 更有价值，可以跑更多轮


def _count_confirmed(state: AuditState) -> int:
    """计算当前 state 中 confidence == 'confirmed' 的 AttackChain 数量。

    用于路由函数判断是否需要触发重规划：
    当 confirmed 链数量比上一轮增加时，说明有重大发现，plan 节点需要重新评估方向。

    独立为函数的原因：逻辑可测试，语义清晰。
    """
    return sum(
        1 for c in state.get("attack_chains", [])
        if c.get("confidence") == "confirmed"
    )


def _should_continue(state: AuditState) -> str:
    """路由函数：决定 analyze 后的下一步。

    决策优先级（从高到低）：
    1. 终止条件（status / trial_count）
    2. 重规划条件（新增 confirmed chain AND next_probes 已耗尽）
    3. 继续探测

    重规划触发条件：
    - confirmed_count 存入 state（_plan_confirmed_count），在 plan() 执行后记录快照
    - 路由函数对比当前 confirmed_count 与快照，发现增量时：
        - next_probes 非空 → 继续 think（让 DFS 深挖先完成，不打断链式验证）
        - next_probes 空   → 触发 plan 重规划（此时才有意义探索新攻击面）
    - 这避免了 plan 重规划打断 analyze→next_probes→think 的链式深挖回路。

    注意：_plan_confirmed_count 字段由 plan() 写入，初始值 -1（确保 trial=0 时不误触发）。
    """
    if state["status"] != "running":
        return END
    if state["trial_count"] >= _MAX_TRIALS:
        logger.info("audit.max_trials_reached", trials=state["trial_count"])
        return END

    # 对比当前 confirmed 链数量与 plan 执行时的快照
    current_confirmed = _count_confirmed(state)
    snapshot = state.get("_plan_confirmed_count", -1)

    if current_confirmed > snapshot:
        # 有新的 confirmed 链，但先看 next_probes 是否还有待验证命令
        next_probes = state.get("next_probes", [])
        if next_probes:
            # next_probes 非空：链式深挖尚未完成，继续让 think 执行验证命令
            # plan 重规划延迟到 next_probes 耗尽后再触发
            logger.info(
                "audit.replan_deferred",
                confirmed_now=current_confirmed,
                confirmed_at_last_plan=snapshot,
                pending_probes=len(next_probes),
            )
            return "think"
        # next_probes 空：所有已知 speculative/likely 链已验证完毕，重规划有意义
        logger.info(
            "audit.replan_triggered",
            confirmed_now=current_confirmed,
            confirmed_at_last_plan=snapshot,
            reason="next_probes_exhausted",
        )
        return "plan"

    return "think"


def build_graph() -> CompiledStateGraph:
    """构建并编译具有内存检查点的审计图（Iter 3：plan → think → act → analyze 四节点）。"""
    builder = StateGraph(AuditState)

    builder.add_node("plan", plan)
    builder.add_node("think", think)
    builder.add_node("act", act)
    builder.add_node("analyze", analyze)

    builder.add_edge(START, "plan")          # 始终从 plan 开始（Generator 模式）
    builder.add_edge("plan", "think")
    builder.add_edge("think", "act")
    builder.add_edge("act", "analyze")
    builder.add_conditional_edges(
        "analyze",
        _should_continue,
        {"plan": "plan", "think": "think", END: END},
    )

    checkpointer = MemorySaver()
    graph = builder.compile(checkpointer=checkpointer, name="switch-audit")

    logger.info("graph.built", nodes=["plan", "think", "act", "analyze"], max_trials=_MAX_TRIALS)
    return graph
