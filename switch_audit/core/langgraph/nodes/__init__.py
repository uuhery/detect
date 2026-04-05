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
from switch_audit.prompts import load_analyze_prompt, load_plan_prompt, load_system_prompt
from switch_audit.tools import ssh_exec

_llm = ChatOpenAI(
    model=settings.DEFAULT_LLM_MODEL,
    temperature=settings.DEFAULT_LLM_TEMPERATURE,
    api_key=settings.OPENAI_API_KEY,
    base_url=settings.OPENAI_BASE_URL,
)

# ── 命令模板库（Iter 3 引入） ─────────────────────────────────────────────
# 格式：(触发条件, 命令字符串, 安全价值说明)
#
# 触发条件语义：
#   "always"        — 无条件加入候选集（基础侦察，任何 IOS XE 设备都有效）
#   其他字符串      — 作为 substring 在 show running-config 输出中查找；
#                     找到则将命令加入候选集，否则跳过
#
# 这是系统中唯一需要人工维护的静态知识，职责单一：
#   只保证"语法正确"，不决定"执行顺序"（那是 think 的工作）
#
# 新增 IOS XE 功能支持：在此追加一行即可，无需修改任何其他代码
_COMMAND_TEMPLATES: Final[list[tuple[str, str, str]]] = [
    # 基础侦察（无条件）
    ("always",                    "show version",                                    "device identity, OS version, CVE exposure"),
    ("always",                    "show running-config",                             "full config baseline, source of available_commands"),
    ("always",                    "show ip interface brief",                         "interface state overview"),
    ("always",                    "show mac address-table",                          "L2 MAC table, potential flooding evidence"),
    # 管理平面
    ("ip http server",            "show ip http server status",                      "HTTP management plane exposure"),
    ("ip http secure-server",     "show ip http server status",                      "HTTPS management plane exposure"),
    ("ip ssh",                    "show ip ssh",                                     "SSH version and timeout config"),
    ("line vty",                  "show line vty 0 4",                               "VTY lines transport and timeout"),
    ("username",                  "show users",                                      "active privileged sessions"),
    ("username",                  "show privilege",                                  "current exec privilege level"),
    # AAA（只加已知有效命令，show aaa authentication/authorization 在 IOS XE 不存在）
    ("aaa new-model",             "show aaa servers",                                "AAA server list and reachability"),
    ("tacacs server",             "show tacacs",                                     "TACACS+ server status and RTT"),
    ("radius server",             "show radius statistics",                          "RADIUS server statistics"),
    # L2 安全
    ("spanning-tree",             "show spanning-tree detail",                       "STP root, PortFast, BPDU guard per port"),
    ("spanning-tree",             "show spanning-tree summary",                      "global STP protection: portfast default, bpduguard default"),
    ("switchport mode trunk",     "show interfaces trunk",                           "trunk native VLAN, allowed VLANs"),
    ("switchport mode access",    "show port-security",                              "port security status on access ports"),
    ("switchport mode access",    "show vlan brief",                                 "VLAN membership, access port assignments"),
    # RESTCONF / NETCONF / gNXI
    ("restconf",                  "show platform software yang-management process",  "RESTCONF/NETCONF daemon status"),
    ("netconf-yang",              "show platform software yang-management process",  "RESTCONF/NETCONF daemon status"),
    # CDP（信息泄露）：IOS XE 默认开启，不写入 running-config，用 always 触发
    ("always",                    "show cdp neighbors",                              "CDP neighbor exposure, topology leak"),
    # 路由 / 日志
    ("ip route",                  "show ip route summary",                           "routing table overview"),
    ("logging",                   "show logging",                                    "security-relevant syslog entries"),
    ("ntp server",                "show ntp status",                                 "NTP authentication status"),
    # 密码类型（直接从 running-config 提取更精确）
    ("enable password",           "show running-config | include enable",            "enable password encoding type (Type 7 = reversible)"),
    ("enable secret",             "show running-config | include enable",            "enable secret hash type"),
]


def _derive_available_commands(running_config: str) -> list[str]:
    """从 show running-config 输出派生本会话的命令候选集。

    返回的列表满足：
    1. 语法正确  — 来自 _COMMAND_TEMPLATES，不是 LLM 生成
    2. 设备相关  — 触发条件在 running-config 中存在，或标记为 always

    设计原则：
    - 纯代码逻辑，无 LLM，O(n·m) 但 n、m 都很小（< 30 条模板）
    - 去重：同一命令字符串只出现一次（多个触发条件可能指向同一命令）
    - 顺序：按 _COMMAND_TEMPLATES 的定义顺序，保证可重复性
    """
    seen: set[str] = set()
    commands: list[str] = []
    for trigger, command, _ in _COMMAND_TEMPLATES:
        if command in seen:
            continue
        if trigger == "always" or trigger in running_config:
            commands.append(command)
            seen.add(command)
    return commands

# think() 构建上下文时最多使用最近 N 条命令记录。
# Iter 3 降为 2：战略方向已由 plan 节点提供，think 不需要回溯全量历史。
# Iter 4 引入摘要机制后，旧记录用摘要替代，此值可适当提高。
_CONTEXT_WINDOW_RECENT = 2


def _build_think_context(state: AuditState) -> str:
    """构建 think() 的 user message（Iter 3 精简版）。

    Iter 3 后 think 是纯战术层：只需知道"禁止什么"、"往哪里走"、"最近发生了什么"。
    战略决策（BFS 方向选择）已在 plan 节点完成，think 不需要再做这件事。

    四段结构（按信息密度从高到低排列）：

    1. 去重约束（已执行命令）
       — 硬性约束，think 必须看到才能避免重复。
       — 是 LLM 唯一需要逐字记住的列表。

    2. 优先级 1：next_probes（来自 analyze.verification_needed）
       — 这些命令能直接把 speculative/likely 链升级为 confirmed。
       — 高于 directions：因为它们是 analyze 节点基于已有证据推断出的最有价值路径。
       — 明确标注"NOT yet executed"，消除 iter2 的误判 bug。

    3. 优先级 2：directions（来自 plan 节点）
       — BFS 方向，已由 plan 节点在全局视野下选好。
       — think 从中选一条，决定本轮命令。
       — 不需要逐字理解，只需作为命令选择的参考框架。

    4. 最近 2 条命令输出（短暂上下文）
       — 帮助 think 理解"上一步发现了什么"，避免选重复方向的命令。
       — 只取 2 条（不是 6 条）：战略方向已由 plan 提供，think 不需要回溯全量历史。
       — 这是 Iter 4 记忆管理的前置约定。

    信息不传入：
    - 全量 facts（已由 plan 提炼成 directions.rationale）
    - 全量 attack_chains（已由 plan 提炼成 directions）
    - _RECON_CHECKLIST（已被 available_commands 替代，Iter 3 后不再使用）
    """
    executed: list[str] = state.get("executed_commands", [])
    next_probes: list[str] = state.get("next_probes", [])
    directions: list[dict] = state.get("directions", [])
    available_commands: list[str] = state.get("available_commands", [])

    # ── 段一：去重约束 ──────────────────────────────────────────────────────
    executed_section = (
        "\n".join(f"  - {c}" for c in executed) if executed else "  (none yet)"
    )

    # ── 段二：next_probes（优先级 1，来自 analyze）──────────────────────────
    # 明确标注"NOT yet executed"，避免 think 误以为这些命令已在执行中（iter2 的 bug）
    if next_probes:
        probes_section = (
            "## Priority 1 — run ONE of these next "
            "(NOT yet executed — will confirm a partially-known attack chain):\n"
            + "\n".join(f"  - {p}" for p in next_probes)
        )
    else:
        probes_section = (
            "## Priority 1 — attack chain verification\n"
            "  (no pending probes — all known chains are either confirmed or have no verification commands)"
        )

    # ── 段三：directions（优先级 2，来自 plan）──────────────────────────────
    # directions 是 plan 节点在全局视野下做完 BFS 决策后的结果，think 直接消费。
    # 每条方向含 rationale（为什么要调查这个方向），帮助 think 选出与当前证据最相关的命令。
    if directions:
        dir_lines = "\n".join(
            f"  [{d['priority']}] {d['focus']}\n"
            f"      rationale: {d['rationale']}"
            for d in directions
        )
        directions_section = (
            "## Priority 2 — investigation directions (from plan node, use if Priority 1 is empty):\n"
            + dir_lines
        )
    else:
        directions_section = (
            "## Priority 2 — investigation directions\n"
            "  (plan node has not yet produced directions — use your own judgement)"
        )

    # ── 段四：命令候选集（来自设备自身配置，语法保证正确）──────────────────
    # available_commands 在 analyze 处理 show running-config 后填充。
    # 在此之前（trial 0 和 1），列表为空，think 使用 Fallback 模式。
    # 已执行的命令从候选集中过滤掉，think 只看剩余可选项。
    executed_set = set(executed)
    if available_commands:
        remaining = [c for c in available_commands if c not in executed_set]
        if remaining:
            candidates_section = (
                "## Available Commands — choose ONLY from this list "
                "(syntax verified from device config):\n"
                + "\n".join(f"  - {c}" for c in remaining)
            )
        else:
            candidates_section = (
                "## Available Commands\n"
                "  (all derived commands have been executed — use Fallback)"
            )
    else:
        candidates_section = (
            "## Available Commands\n"
            "  (not yet derived — show running-config has not been executed yet;\n"
            "   use your own IOS XE knowledge for this trial only)"
        )

    # ── 段五：最近 2 条命令输出（短暂上下文）──────────────────────────────
    # 只取 2 条（_CONTEXT_WINDOW_RECENT 已从 6 降为 2）。
    # think 需要知道"上一步执行了什么、发现了什么"，但不需要全量历史。
    recent_history = state.get("command_history", [])[-_CONTEXT_WINDOW_RECENT:]
    if recent_history:
        history_section = "\n\n".join(
            f"[trial={r['trial']}] $ {r['command']}\n"
            f"status={r['status']}\n"
            f"{r['output'][:800]}"   # 截断过长输出，think 不需要读完整原文（analyze 已处理）
            for r in recent_history
        )
    else:
        history_section = "(none yet)"

    return (
        f"Target: {state['target']}"
        + (f" | OS: {state['device_os']}" if state.get("device_os") else "")
        + f" | Trial: {state['trial_count']}\n\n"
        f"## Commands already executed — DO NOT propose any of these:\n"
        f"{executed_section}\n\n"
        f"{probes_section}\n\n"
        f"{directions_section}\n\n"
        f"{candidates_section}\n\n"
        f"## Recent context (last {_CONTEXT_WINDOW_RECENT} commands):\n"
        f"{history_section}\n\n"
        f"Choose the single most valuable command to run next."
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


def _build_analyze_context(state: AuditState) -> str:
    """构建 analyze() 的 user message。

    五段结构：
    1. 最新 CommandRecord 的完整输出（供提取 Facts 和 raw_evidence 逐字引用）
    2. 历史 Facts 摘要（id + source_command + content，省略 raw_evidence 节省 tokens）
    3. 已有 AttackChains 摘要（id + title + fact_ids + confidence，供 LLM 声明 existing_chain_id）
    4. ID 提示段（明确当前 trial 编号和下一个可用 index，防止 LLM 幻觉编号）
    5. 可用命令候选集（available_commands，LLM 选择 verification_needed 时必须从此列表中选）

    设计原则：
    - 最新命令输出完整传入，因为 LLM 需要从中原文引用 raw_evidence
    - 历史 Facts 省略 raw_evidence：证据已存于 command_history，反复传入只浪费 tokens
    - 全量 Facts 传入（不过滤）：保证跨主题的关联不遗漏（如 STP + CDP 的跨层链）
    - available_commands 传入：让 LLM 知道哪些命令是语法合法的，verification_needed 只从此列表选
    """
    history = state.get("command_history", [])
    if not history:
        return "(no command history — analyze should not have been called)"

    latest: CommandRecord = history[-1]
    current_trial = latest["trial"]

    # 段一：最新命令的完整记录
    latest_section = (
        f"## Latest Command (trial={current_trial})\n"
        f"Command: {latest['command']}\n"
        f"Status: {latest['status']}\n"
        f"Output:\n{latest['output']}"
    )

    # 段二：历史 Facts（全量，只传 id + source_command + content）
    existing_facts = state.get("facts", [])
    if existing_facts:
        facts_lines = [
            f"  [{f['id']}] (from `{f['source_command']}`, trial={f['trial']}): {f['content']}"
            for f in existing_facts
        ]
        facts_section = (
            "## Existing Facts (reference by id when building chains)\n"
            + "\n".join(facts_lines)
        )
    else:
        facts_section = "## Existing Facts\n  (none yet)"

    # 段三：已有 AttackChains（id + title + fact_ids + confidence，供 LLM 判断 existing_chain_id）
    existing_chains = state.get("attack_chains", [])
    if existing_chains:
        chains_lines = [
            f"  [{c['id']}] \"{c['title']}\" | facts={c['fact_ids']} | "
            f"severity={c['severity']} | confidence={c['confidence']}"
            for c in existing_chains
        ]
        chains_section = (
            "## Existing AttackChains "
            "(set existing_chain_id to update an existing one, or null to create new)\n"
            + "\n".join(chains_lines)
        )
    else:
        chains_section = "## Existing AttackChains\n  (none yet)"

    # 段四：ID 生成提示（防止 LLM 随意编号或使用已用过的 index）
    facts_this_trial = len([f for f in existing_facts if f["trial"] == current_trial])
    id_hint = (
        f"## ID Hints\n"
        f"  Current trial: {current_trial}\n"
        f"  New Fact IDs must use prefix: f{current_trial}-\n"
        f"  Next available fact index in this trial: {facts_this_trial} "
        f"(so first new fact is f{current_trial}-{facts_this_trial})\n"
        f"  New Chain IDs (only when existing_chain_id=null) must use prefix: c{current_trial}-"
    )

    # 段五：可用命令候选集（available_commands，由 show running-config 派生，语法保证正确）
    # 双重作用：
    #   1. 供 Rule 6 speculative chain 推断：未执行的命令可作为假设锚点
    #   2. 约束 verification_needed：LLM 只能从此列表中选，不得发明命令字符串
    available_commands: list[str] = state.get("available_commands", [])
    executed_set = set(state.get("executed_commands", []))
    if available_commands:
        unexecuted = [c for c in available_commands if c not in executed_set]
        executed_from_list = [c for c in available_commands if c in executed_set]
        lines = []
        if unexecuted:
            lines.append("  Not yet executed (can be used for verification_needed and Rule 6 speculation):")
            lines.extend(f"    - {c}" for c in unexecuted)
        if executed_from_list:
            lines.append("  Already executed (DO NOT put in verification_needed):")
            lines.extend(f"    - {c}" for c in executed_from_list)
        available_section = (
            "## Available Commands — verification_needed MUST only use commands from this list\n"
            "(This list is syntax-verified from the device's own running-config. "
            "Do NOT invent command strings outside this list.)\n"
            + "\n".join(lines)
        )
    else:
        available_section = (
            "## Available Commands\n"
            "  (not yet derived — show running-config has not been analyzed yet)\n"
            "  For verification_needed, use standard IOS XE show commands with correct syntax."
        )

    return "\n\n".join([latest_section, facts_section, chains_section, id_hint, available_section])


def _parse_analyze_response(raw: str, current_trial: int) -> tuple[list, list, str]:
    """从 LLM 输出解析 new_facts、chain_updates、device_os。

    返回：(new_facts: list[dict], chain_updates: list[dict], device_os: str)

    三层防御：
    1. regex 提取 JSON 代码块（与 _parse_think_response 一致的提取逻辑）
    2. json.loads 解析
    3. 字段级 .get() 带默认值——单字段格式错误不崩溃整体

    失败降级：JSON 解析失败 → ([], [], "") + warning log，analyze 继续返回 {}
    单个 Fact/Chain 格式错误 → 跳过该条目，不影响其他条目
    """
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    text = match.group(1) if match else raw.strip()

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning(
            "analyze.parse_failed",
            trial=current_trial,
            raw_preview=raw[:300],
        )
        return [], [], ""

    # 解析 new_facts（字段级防御）
    raw_facts = data.get("new_facts", [])
    new_facts: list[dict] = []
    for i, f in enumerate(raw_facts):
        if not isinstance(f, dict):
            continue
        content = f.get("content", "").strip()
        if not content:
            # content 为空的 Fact 无意义，跳过
            logger.warning("analyze.empty_fact_skipped", index=i, trial=current_trial)
            continue
        new_facts.append({
            "id": f.get("id", f"f{current_trial}-{i}"),
            "trial": f.get("trial", current_trial),
            "source_command": f.get("source_command", ""),
            "content": content,
            "raw_evidence": f.get("raw_evidence", ""),
        })

    # 解析 chain_updates（字段级防御）
    raw_chains = data.get("chain_updates", [])
    chain_updates: list[dict] = []
    for i, c in enumerate(raw_chains):
        if not isinstance(c, dict):
            continue
        title = c.get("title", "").strip()
        if not title:
            continue
        fact_ids = c.get("fact_ids", [])
        if not isinstance(fact_ids, list):
            fact_ids = [fact_ids] if fact_ids else []
        verification = c.get("verification_needed", [])
        if not isinstance(verification, list):
            verification = [verification] if verification else []
        chain_updates.append({
            "existing_chain_id": c.get("existing_chain_id"),  # None 表示新建
            "id": c.get("id", f"c{current_trial}-{i}"),
            "title": title,
            "fact_ids": fact_ids,
            "attack_narrative": c.get("attack_narrative", ""),
            "severity": c.get("severity", "medium"),
            "confidence": c.get("confidence", "speculative"),
            "verification_needed": verification,
            "trial_first_seen": c.get("trial_first_seen", current_trial),
        })

    device_os = data.get("device_os", "").strip()
    return new_facts, chain_updates, device_os


def _upsert_attack_chains(existing: list, updates: list) -> list:
    """将 LLM 产出的 chain_updates upsert 到现有 attack_chains 列表。

    upsert 规则：
    - existing_chain_id 非 None 且在列表中 → 更新已有链
      - confidence 只升级（单调性保证：speculative → likely → confirmed）
      - fact_ids 追加去重
      - verification_needed 替换为最新（新轮次的验证命令更精准）
      - attack_narrative 非空时替换（更好的描述）
      - id / title / trial_first_seen / severity 不变（需要更谨慎的评估才能改）
    - existing_chain_id 为 None 或不存在 → 追加新 AttackChain

    confidence 单调性在代码层强制执行，不依赖 LLM 遵循 prompt。
    """
    _CONFIDENCE_RANK = {"speculative": 0, "likely": 1, "confirmed": 2}

    # 构建 id → 列表下标的映射，O(1) 查找
    id_to_index: dict[str, int] = {chain["id"]: idx for idx, chain in enumerate(existing)}
    result = [dict(c) for c in existing]  # 浅拷贝，避免修改原 state

    for update in updates:
        existing_id = update.get("existing_chain_id")

        if existing_id and existing_id in id_to_index:
            # 更新已有链
            idx = id_to_index[existing_id]
            target = result[idx]

            # confidence 只升级（单调性）
            current_rank = _CONFIDENCE_RANK.get(target.get("confidence", "speculative"), 0)
            new_rank = _CONFIDENCE_RANK.get(update.get("confidence", "speculative"), 0)
            if new_rank > current_rank:
                target["confidence"] = update["confidence"]

            # fact_ids 追加去重
            existing_fact_set = set(target.get("fact_ids", []))
            for fid in update.get("fact_ids", []):
                if fid not in existing_fact_set:
                    target.setdefault("fact_ids", []).append(fid)
                    existing_fact_set.add(fid)

            # verification_needed 替换（更新版本可能有更精准的验证命令）
            if update.get("verification_needed") is not None:
                target["verification_needed"] = update["verification_needed"]

            # attack_narrative 若非空则替换（更好的叙述）
            if update.get("attack_narrative"):
                target["attack_narrative"] = update["attack_narrative"]

        else:
            # 新建链：移除 existing_chain_id 辅助字段，保留 AttackChain 标准字段
            new_chain = {
                "id": update["id"],
                "title": update["title"],
                "fact_ids": update.get("fact_ids", []),
                "attack_narrative": update.get("attack_narrative", ""),
                "severity": update.get("severity", "medium"),
                "confidence": update.get("confidence", "speculative"),
                "verification_needed": update.get("verification_needed", []),
                "trial_first_seen": update.get("trial_first_seen", 0),
            }
            id_to_index[new_chain["id"]] = len(result)
            result.append(new_chain)

    return result


def _compute_next_probes(
    attack_chains: list,
    executed_commands: list[str],
    available_commands: list[str] | None = None,
) -> list[str]:
    """从 speculative/likely 链的 verification_needed 汇总 next_probes。

    这是 analyze → think 反馈回路的核心：把"哪些攻击链还不确定"
    转化为"下一轮应该优先执行哪些命令"，驱动 Agent 目标导向探测。

    过滤与排序规则：
    1. 只取 confidence in ("speculative", "likely") 的链
    2. speculative 优先于 likely（更需要验证）
    3. 过滤已执行命令
    4. 当 available_commands 非空时，过滤不在列表中的命令（语法正确性保证）
       available_commands 为空（show running-config 尚未执行）时不过滤，保持 Fallback 能力
    5. 去重（多个链可能需要同一条命令）
    6. 同优先级内保持 LLM 产出的原始顺序
    """
    executed_set = set(executed_commands)
    available_set: set[str] | None = set(available_commands) if available_commands else None
    seen: set[str] = set()
    probes: list[str] = []

    # speculative=0（更高优先级，排前面），likely=1
    def _priority(chain: dict) -> int:
        return 0 if chain.get("confidence") == "speculative" else 1

    eligible = [
        c for c in attack_chains
        if c.get("confidence") in ("speculative", "likely")
    ]
    eligible.sort(key=_priority)

    for chain in eligible:
        for cmd in chain.get("verification_needed", []):
            cmd = cmd.strip()
            if not cmd:
                continue
            if cmd in executed_set:
                continue
            if available_set is not None and cmd not in available_set:
                # 命令不在 available_commands 中：语法可能有误，丢弃
                logger.warning(
                    "analyze.next_probe_filtered",
                    cmd=cmd,
                    reason="not in available_commands",
                )
                continue
            if cmd not in seen:
                probes.append(cmd)
                seen.add(cmd)

    return probes


def analyze(state: AuditState) -> dict:
    """从最新命令输出提取 Facts，推断/更新 AttackChains，更新 next_probes。

    节点职责（Iter 2 核心）：
    - 读: command_history[-1], facts, attack_chains, executed_commands, device_os
    - 写: facts(追加), attack_chains(upsert), next_probes(重算), device_os(条件更新)

    跳过条件：
    - 无命令历史（防御性检查，正常流程不应到达）
    - 最新记录 status == "skipped_duplicate"（无新信息，节省 API 调用）

    device_os 更新逻辑：只在 LLM 返回非空字符串时更新，不覆盖已有值。
    这确保 device_os 只在 show version 时被设置，后续命令不会清空它。
    """
    history = state.get("command_history", [])
    if not history:
        logger.warning("analyze.no_history")
        return {}

    latest: CommandRecord = history[-1]
    current_trial = latest["trial"]

    # skipped_duplicate：无新信息，跳过 LLM 调用
    if latest["status"] == "skipped_duplicate":
        logger.info("analyze.skipped_duplicate", trial=current_trial, command=latest["command"])
        return {}

    logger.info(
        "node.analyze",
        trial=current_trial,
        command=latest["command"],
        status=latest["status"],
        existing_facts=len(state.get("facts", [])),
        existing_chains=len(state.get("attack_chains", [])),
    )

    user_msg = _build_analyze_context(state)

    response = _llm.invoke([
        {"role": "system", "content": load_analyze_prompt()},
        {"role": "user", "content": user_msg},
    ])

    new_facts, chain_updates, device_os = _parse_analyze_response(
        response.content.strip(),
        current_trial=current_trial,
    )

    # 追加新 Facts（不去重：不同 trial 的 Fact 内容不同，同 trial 多个 Fact 也合理）
    updated_facts = state.get("facts", []) + new_facts

    # upsert AttackChains（更新已有 + 追加新链）
    updated_chains = _upsert_attack_chains(
        existing=state.get("attack_chains", []),
        updates=chain_updates,
    )

    # 重算 next_probes（基于最新的 attack_chains、executed_commands 和 available_commands）
    # available_commands 为空时不过滤（show running-config 尚未执行的 bootstrap 阶段）
    updated_probes = _compute_next_probes(
        attack_chains=updated_chains,
        executed_commands=state.get("executed_commands", []),
        available_commands=state.get("available_commands") or None,
    )

    logger.info(
        "node.analyze.result",
        trial=current_trial,
        new_facts=len(new_facts),
        chain_updates=len(chain_updates),
        total_facts=len(updated_facts),
        total_chains=len(updated_chains),
        next_probes=updated_probes,
        device_os_updated=bool(device_os),
    )

    result: dict = {
        "facts": updated_facts,
        "attack_chains": updated_chains,
        "next_probes": updated_probes,
    }
    # device_os 只在本次提取到时更新（空字符串不覆盖已有值）
    if device_os:
        result["device_os"] = device_os

    # available_commands：仅在处理 show running-config 时派生。
    # 理由：running-config 是设备的自描述，是命令集合的唯一可靠来源。
    # 其他命令的输出不包含足够的配置信息，不触发重派生。
    # 一旦填充，后续 trial 不再更新（除非重新执行 show running-config）。
    if latest["command"] == "show running-config" and latest["status"] == "ok":
        derived = _derive_available_commands(latest["output"])
        result["available_commands"] = derived
        logger.info(
            "node.analyze.available_commands_derived",
            trial=current_trial,
            count=len(derived),
        )

    return result


# ─────────────────────────────────────────────────────────────────────────────
# Iter 3：plan 节点（战略层 — BFS 决策）
# ─────────────────────────────────────────────────────────────────────────────

def _build_plan_context(state: AuditState) -> str:
    """构建 plan() 的 user message。

    plan 是战略层，需要"全局视野"：所有已知 Facts + AttackChains + 已执行命令 + device_os。
    目的是让 LLM 决定"往哪里挖"，而不是"怎么挖"。

    设计要点：
    - Facts 省略 raw_evidence（plan 不需要证据原文，只需要摘要判断方向）
    - AttackChains 包含 confidence（plan 需要知道哪些链已 confirmed，哪些还需验证）
    - 当前 directions 传入（Refiner 模式下可以参考已有方向，避免重复）
    - trial_count 传入（让 LLM 判断是 Generator 模式还是 Refiner 模式）
    """
    facts = state.get("facts", [])
    chains = state.get("attack_chains", [])
    executed = state.get("executed_commands", [])
    trial_count = state.get("trial_count", 0)
    device_os = state.get("device_os", "")
    current_directions = state.get("directions", [])

    # 段一：基本信息
    header = (
        f"Target: {state['target']}"
        + (f" | OS: {device_os}" if device_os else "")
        + f" | Trial: {trial_count}"
        + f" | Commands executed: {len(executed)}"
    )

    # 段二：已执行命令（让 plan 知道哪些面已经覆盖）
    executed_section = (
        "## Commands Executed\n"
        + ("\n".join(f"  - {c}" for c in executed) if executed else "  (none yet)")
    )

    # 段三：已有 Facts（id + source_command + content，无 raw_evidence）
    if facts:
        facts_lines = [
            f"  [{f['id']}] (from `{f['source_command']}`): {f['content']}"
            for f in facts
        ]
        facts_section = "## Existing Facts\n" + "\n".join(facts_lines)
    else:
        facts_section = "## Existing Facts\n  (none yet — this is the initial planning call)"

    # 段四：已有 AttackChains（id + title + severity + confidence + fact_ids）
    if chains:
        chains_lines = [
            f"  [{c['id']}] \"{c['title']}\" | severity={c['severity']} | "
            f"confidence={c['confidence']} | facts={c['fact_ids']}"
            for c in chains
        ]
        chains_section = "## Existing AttackChains\n" + "\n".join(chains_lines)
    else:
        chains_section = "## Existing AttackChains\n  (none yet)"

    # 段五：当前调查方向（Refiner 模式参考）
    if current_directions:
        dir_lines = [
            f"  [{d['priority']}] {d['focus']} — {d['rationale']}"
            for d in current_directions
        ]
        directions_section = (
            "## Current Directions (from previous plan call — refine or replace)\n"
            + "\n".join(dir_lines)
        )
    else:
        directions_section = "## Current Directions\n  (none — this is the first plan call)"

    return "\n\n".join([header, executed_section, facts_section, chains_section, directions_section])


def _parse_plan_response(raw: str) -> list[dict]:
    """从 LLM 输出解析 directions 列表。

    返回：list[dict]，每项包含 priority, focus, rationale。
    解析失败 → [] + warning log（plan 失败时 think 仍能靠 next_probes 继续工作）。
    """
    match = re.search(r"```(?:json)?\s*(\{.*?\})\s*```", raw, re.DOTALL)
    text = match.group(1) if match else raw.strip()

    try:
        data = json.loads(text)
    except (json.JSONDecodeError, ValueError):
        logger.warning("plan.parse_failed", raw_preview=raw[:300])
        return []

    raw_dirs = data.get("directions", [])
    directions: list[dict] = []
    for d in raw_dirs:
        if not isinstance(d, dict):
            continue
        focus = d.get("focus", "").strip()
        if not focus:
            continue
        directions.append({
            "priority": d.get("priority", len(directions) + 1),
            "focus": focus,
            "rationale": d.get("rationale", ""),
        })

    # 硬上限 3 个，防止 LLM 违反约束
    return directions[:3]


def plan(state: AuditState) -> dict:
    """战略层：综合所有已知信息，生成 1-3 个有优先级的调查方向。

    职责（Iter 3 核心）：
    - 读: facts, attack_chains, executed_commands, device_os, trial_count, directions
    - 写: directions（完全替换，不追加）

    触发时机（由 graph.py 的路由函数决定，此函数不做判断）：
    - trial_count == 0：session 开始，生成初始侦察方向（Generator 模式）
    - analyze 产出新的 confirmed chain：重大发现，更新调查方向（Refiner 模式）

    设计约束（plan.md 提示词层面已说明，代码层面强制）：
    - directions 上限 3 个（_parse_plan_response 截断）
    - plan 不写 facts/attack_chains/next_probes（只写 directions）
    - directions 不包含具体命令（提示词约束，代码无法直接验证）
    """
    logger.info(
        "node.plan",
        trial=state["trial_count"],
        target=state["target"],
        facts_count=len(state.get("facts", [])),
        chains_count=len(state.get("attack_chains", [])),
        current_directions=len(state.get("directions", [])),
    )

    user_msg = _build_plan_context(state)

    response = _llm.invoke([
        {"role": "system", "content": load_plan_prompt()},
        {"role": "user", "content": user_msg},
    ])

    directions = _parse_plan_response(response.content.strip())

    # 记录本次 plan 时的 confirmed chain 数量快照。
    # 路由函数用这个快照对比下一轮 analyze 后的 confirmed 数量，判断是否需要重规划。
    confirmed_snapshot = sum(
        1 for c in state.get("attack_chains", [])
        if c.get("confidence") == "confirmed"
    )

    logger.info(
        "node.plan.result",
        directions_count=len(directions),
        directions=[d["focus"] for d in directions],
        confirmed_snapshot=confirmed_snapshot,
    )

    return {
        "directions": directions,
        "_plan_confirmed_count": confirmed_snapshot,
    }
