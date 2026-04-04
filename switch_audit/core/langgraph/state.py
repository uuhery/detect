"""
交换机漏洞检测图的审计状态模式。

每个字段都是一级可观察对象：每个节点都从该模式读取并写入该模式，这意味着任何步骤都可以被检查点记录和重放。

设计原则：状态即审计日志——如果某事件发生但未在状态中体现，则视为未发生。
"""

from typing import Annotated

from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class AuditState(TypedDict):
    # ── LangGraph managed ──────────────────────────────────────────────
    # add_messages 归约器：新消息被追加，而非替换
    messages: Annotated[list, add_messages]

    # ── 会话上下文 ────────────────────────────────────────────────
    session_id: str
    target: str          # 设备 IP / 主机名 / 串行路径

    # ── 审计循环 ─────────────────────────────────────────────────────
    # 当前正在测试的假设（由 think 节点生成）
    hypothesis: str
    # 从设备累积的观察结果（由 observe 节点追加）
    observations: list[str]
    # 已完成的 think → act → observe 循环次数
    trial_count: int
    # "running" | "completed" | "error"
    status: str
