"""
交换机漏洞审计图的状态模式。

核心目标：发现"跨多条命令输出才能推断的复合漏洞攻击链"。
状态的每个字段都服务于这个目标，或服务于让 Agent 循环可靠运行。

设计原则：
  1. 状态即审计日志 — 每个字段是可审计的一等事实，不存在调试字符串
  2. 结构先于文本 — 能用 TypedDict 表达的不用 str
  3. 推理与行动分离 — reasoning (why) 和 proposed_command (what) 是独立字段
  4. Fact 是原子，AttackChain 是分子 — 复合链由 ≥2 个独立事实组合推断

节点与字段的读写关系：
  think()   读: command_history(recent), executed_commands, attack_chains,
                next_probes, device_os, trial_count
            写: reasoning, proposed_command

  act()     读: proposed_command, executed_commands
            写: command_history(append), executed_commands(append), trial_count(+1)

  analyze() 读: command_history[-1], facts, attack_chains, device_os   [Iter 2]
            写: facts(append), attack_chains(upsert), next_probes, device_os
"""

from typing import Annotated

from langgraph.graph.message import add_messages
from typing_extensions import TypedDict


class CommandRecord(TypedDict):
    """单次命令执行的完整记录。只追加，不修改。

    存在理由：
      替代原 observations: list[str]。
      analyze 节点需要知道"哪个命令产生了哪段输出"才能正确归因 Fact。
      status 字段让 think 节点知道某命令是否失败，避免重试失败路径。

    不变量：trial 与 command_history 的下标一一对应。
    """
    trial: int
    command: str
    output: str    # 原始输出，不截断
    status: str    # "ok" | "ssh_error" | "skipped_duplicate"
    timestamp: str # ISO 8601，UTC


class Fact(TypedDict):
    """从单条命令输出中提取的一个安全相关事实。

    存在理由：
      Facts 是 AttackChain 的原子构成单元。
      analyze 节点每次只读最新命令的输出，但要与历史事实关联，
      把历史输出全部重新送入 LLM 代价太高。
      facts 列表提供所有历史事实的结构化摘要，是跨命令关联推理的桥梁。

    设计约束：
      一个 Fact 只陈述一件事，来自一条命令，content 一句话。
      单独看通常是 low/medium 危险度，多个组合才能构成 high/critical 攻击链。
    """
    id: str             # "f{trial}-{index}"，全局唯一，用于被 AttackChain 引用
    trial: int          # 从哪一轮的命令输出中提取
    source_command: str # 来源命令，用于人工复核时追溯
    content: str        # 一句话陈述，e.g. "HTTP 管理界面在端口 80 开放，无 IP ACL 限制"
    raw_evidence: str   # 原始文本中支撑该事实的片段（≤3 行），供人工验证


class AttackChain(TypedDict):
    """跨多条命令输出推断出的复合漏洞攻击链。

    存在理由（核心）：
      这是 Agent 区别于规则系统的关键产出。
      规则系统每条规则独立匹配，只能报告单个 Fact。
      Agent 能发现需要 ≥2 个 Fact 同时为真才能构成的可利用路径。

      例：
        Fact A: "enable password 使用 Type 7 编码（可逆）"          来自 show running-config
        Fact B: "HTTP 管理界面使用 enable 密码认证，无 IP ACL"     来自 show ip http server status
        → 规则系统：两条独立 finding（low + medium）
        → AttackChain：一条 high severity 的完整攻击路径

    severity 语义：
      基于整条链的可利用性，而非单个 Fact 的严重度。
      两个 low Fact 的组合可能产生 high 的 AttackChain。

    confidence 驱动 next_probes：
      "speculative" → verification_needed 里的命令会进入 next_probes
      → think 节点优先执行这些命令 → 下一轮 analyze 提升 confidence
      这是 Agent 的"目标导向探测"行为，区别于随机探索。
    """
    id: str                        # "c{trial}-{index}"，全局唯一
    title: str                     # 一行标题，e.g. "可逆密码 → HTTP 管理员访问"
    fact_ids: list[str]            # 构成此链的 Fact ID 列表（≥2 个才是复合链）
    attack_narrative: str          # 攻击步骤："攻击者可以：1)... → 2)... → 3) 获得 X 权限"
    severity: str                  # "critical" | "high" | "medium" | "low"
    confidence: str                # "confirmed" | "likely" | "speculative"
                                   # confirmed : 所有事实直接从设备输出读取
                                   # likely    : 部分事实从间接证据推断
                                   # speculative: 需要额外命令验证才能确认
    verification_needed: list[str] # confidence != confirmed 时，这些命令能提升置信度
    trial_first_seen: int          # 第一次推断出此链的 trial，用于分析"第几步发现了复合链"


class AuditState(TypedDict):
    # ── LangGraph managed ────────────────────────────────────────────────────
    # add_messages 归约器：新消息追加，不替换。
    # 当前阶段未充分利用（think 每次重建消息），Iter 4 记忆管理时会启用。
    messages: Annotated[list, add_messages]

    # ── 会话标识 ─────────────────────────────────────────────────────────────
    session_id: str  # LangGraph thread_id，支持 checkpoint 断点恢复
    started_at: str  # ISO 8601 UTC。最终报告中标注审计时间窗口；计算审计耗时

    # ── 目标设备 ─────────────────────────────────────────────────────────────
    target: str      # 用户提供的 IP / 主机名，不可变

    device_os: str   # 由 analyze 节点从 show version 输出中提取，初始为空字符串。
                     # 存在理由：不同 OS 版本命令语法不同（IOS XE vs NX-OS vs IOS）；
                     # 后期 Iter 6 中与 CVE 数据库关联时需要精确版本号。
                     # e.g. "Cisco IOS XE 17.15.1 / C9KV-UADP-8P"

    # ── 执行日志（只追加，不修改） ───────────────────────────────────────────
    command_history: list[CommandRecord]  # 所有命令的结构化执行记录
                                          # 替代原 observations: list[str]
                                          # think 节点用最近 N 条构建上下文（避免全量送入 LLM）

    executed_commands: list[str]  # 已执行命令的有序列表
                                  # 与 command_history 冗余，但 act() 去重检查时需要 O(1) 查找
                                  # 设计权衡：轻微冗余换取逻辑清晰

    # ── 分析产物（由 analyze 节点填充，Iter 2 引入） ────────────────────────
    facts: list[Fact]                # 从历次命令输出中提取的安全事实原子
                                     # 是 analyze 节点跨命令关联推理的原材料
                                     # Iter 1 阶段始终为空列表，Iter 2 后开始填充

    attack_chains: list[AttackChain] # 发现的复合攻击链
                                     # Agent 的核心产出，区别于规则系统的关键字段
                                     # Iter 1 阶段始终为空列表，Iter 2 后开始填充

    # ── 调查方向（plan → think 的战略输入，Iter 3 引入） ────────────────────
    directions: list[dict]  # plan 节点输出的有优先级的调查方向列表。
                            # 每项：{"priority": int, "focus": str, "rationale": str}
                            # think 节点读取这些方向，在约束范围内选最优命令。
                            # 存在理由：把"往哪里挖（BFS）"从 think 中剥离，让 think 专注"怎么挖（DFS）"。
                            # 触发时机：trial=0（初始规划）；analyze 产出新 confirmed 链（重规划）。

    # ── 调查引导（analyze → think 的反馈回路，Iter 2 引入） ─────────────────
    next_probes: list[str]  # analyze 节点根据 attack_chains.verification_needed 汇总的
                            # 高优先级下一步命令。think 节点优先从此列表选择。
                            # 空时 think 节点自由探索（当前 Iter 1 行为）。
                            # 这是 Agent"目标导向"的实现：发现不完整的链 → 主动验证它

    # ── think 节点产物（think → act 之间传递） ──────────────────────────────
    reasoning: str         # LLM 的推理过程：为什么选这个命令，期望发现什么
                           # 替代原 hypothesis: str（hypothesis 把推理和行动混在一起）
                           # 存在价值：可解释性；人工审阅时理解 Agent 的决策逻辑

    proposed_command: str  # 下一步要执行的单条命令
                           # 替代原来从 JSON blob hypothesis 中用 regex 解析 proposed_action
                           # act() 直接读取，无需解析，消除了解析失败回退到 "id" 的脆弱性

    # ── 控制 ─────────────────────────────────────────────────────────────────
    trial_count: int
    status: str  # "running" | "completed" | "error"

    # ── 内部路由辅助（不暴露给 LLM） ─────────────────────────────────────────
    _plan_confirmed_count: int  # plan() 执行时记录的 confirmed AttackChain 数量快照。
                                # 路由函数用它判断：当前 confirmed 数 > 快照 → 有新发现 → 触发重规划。
                                # 初始值 -1（确保 trial=0 时 plan 已执行后，confirmed=0 > -1 不成立，
                                # 不会在首轮 analyze 后立即再次触发 plan）。
                                # 设计权衡：用一个 int 字段替代"是否需要重规划"的复杂判断逻辑，
                                # 代价是 state 多一个内部字段，收益是路由逻辑清晰可测试。
