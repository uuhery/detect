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
from pathlib import Path
from typing import Final

from langchain_openai import ChatOpenAI

# 抑制 netmiko / paramiko 的 read_channel 调试噪音
logging.getLogger("netmiko").setLevel(logging.WARNING)
logging.getLogger("paramiko").setLevel(logging.WARNING)

from switch_audit.core.config import settings
from switch_audit.core.langgraph.state import AuditState, CommandRecord
from switch_audit.core.logging import logger
from switch_audit.prompts import (
    all_valid_commands,
    load_analyze_prompt,
    load_system_prompt,
)
from switch_audit.tools import ssh_exec
from switch_audit.tools.crypto import decode_type7

# Type 7 密文正则：匹配 "password 7 <hex>" 和 "key 7 <hex>"
# 捕获组 1 = 完整匹配行片段，捕获组 2 = 纯密文部分
_TYPE7_RE = re.compile(r"((?:password|key)\s+7\s+([0-9A-Fa-f]{4,}))")

_llm = ChatOpenAI(
    model=settings.DEFAULT_LLM_MODEL,
    temperature=settings.DEFAULT_LLM_TEMPERATURE,
    api_key=settings.OPENAI_API_KEY,
    base_url=settings.OPENAI_BASE_URL,
)

# 必跑命令：无论模型选择什么，这两条必须在前两个 trial 完成。
# 原因：show version 提供设备身份（device_os），show running-config 提供最高密度的配置信息。
# 所有后续分析都依赖这两条的输出，缺失则 analyze 无法推断任何有意义的攻击链。
_MANDATORY_COMMANDS: Final[list[str]] = [
    "show version",
    "show running-config",
]

# 从知识库加载命令全集（SSOT：与注入进 prompt 的命令列表完全一致）
# all_valid_commands() 有 lru_cache，只读一次 YAML。
# 必跑命令排在前面，保证 think 优先选择它们。
_RECON_CHECKLIST: Final[list[str]] = _MANDATORY_COMMANDS + [
    c for c in all_valid_commands() if c not in _MANDATORY_COMMANDS
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

    # 未跑的必跑命令（最高优先级，早于 next_probes）
    mandatory_pending = [c for c in _MANDATORY_COMMANDS if c not in executed]

    # 剩余清单 = 知识库全集 - 已执行
    remaining = [c for c in _RECON_CHECKLIST if c not in executed]

    # 已执行命令
    executed_section = (
        "\n".join(f"  - {c}" for c in executed) if executed else "  (none yet)"
    )

    # 调查优先级（三级）：
    # 1. 必跑命令（未执行时最高优先）
    # 2. next_probes（来自 attack_chains.verification_needed）
    # 3. 剩余知识库命令
    if mandatory_pending:
        guidance_section = (
            "## MANDATORY — run ONE of these first (required baseline, not yet executed):\n"
            + "\n".join(f"  - {c}" for c in mandatory_pending)
            + (
                "\n\n## After mandatory commands, these are next (attack chain verification):\n"
                + "\n".join(f"  - {p}" for p in next_probes)
                if next_probes else ""
            )
        )
    elif next_probes:
        guidance_section = (
            "## Priority: run ONE of these next (needed to verify attack chain hypotheses):\n"
            + "\n".join(f"  - {p}" for p in next_probes)
            + "\n\n## Also uncovered (lower priority):\n"
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


def _build_analyze_context(state: AuditState) -> str:
    """构建 analyze() 的 user message。

    四段结构：
    1. 最新 CommandRecord 的完整输出（供提取 Facts 和 raw_evidence 逐字引用）
    2. 历史 Facts 摘要（id + source_command + content，省略 raw_evidence 节省 tokens）
    3. 已有 AttackChains 摘要（id + title + fact_ids + confidence，供 LLM 声明 existing_chain_id）
    4. ID 提示段（明确当前 trial 编号和下一个可用 index，防止 LLM 幻觉编号）

    设计原则：
    - 最新命令输出完整传入，因为 LLM 需要从中原文引用 raw_evidence
    - 历史 Facts 省略 raw_evidence：证据已存于 command_history，反复传入只浪费 tokens
    - 全量 Facts 传入（不过滤）：保证跨主题的关联不遗漏（如 STP + CDP 的跨层链）
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

    # 段五：未覆盖的侦察方向（供 Rule 6 推断 speculative chain 使用）
    # 只传命令名，不传输出——这些命令尚未执行，LLM 只能推断可能的关联，不能编造 Fact
    executed_set = set(state.get("executed_commands", []))
    uncovered = [c for c in _RECON_CHECKLIST if c not in executed_set]
    if uncovered:
        uncovered_section = (
            "## Uncovered reconnaissance areas (not yet executed)\n"
            "These commands have NOT been run yet. You may use them as anchors for speculative\n"
            "chain hypotheses (Rule 6), but do NOT extract Facts from them — no output exists.\n"
            + "\n".join(f"  - {c}" for c in uncovered)
        )
    else:
        uncovered_section = "## Uncovered reconnaissance areas\n  (all checklist commands have been executed)"

    # 段六：预计算解码（纯算法，结果注入作为 ground truth）
    precomputed = _precompute(latest["output"])

    return "\n\n".join([latest_section, facts_section, chains_section, id_hint, uncovered_section]) + precomputed


def _precompute(command_output: str) -> str:
    """对命令输出做算法精确计算，结果拼接到 analyze 上下文末尾。

    当前支持：Cisco Type 7 密码解码。
    结果标记为 ground truth，LLM 写 Fact 时应直接引用解码后的明文。
    """
    lines = []
    for m in _TYPE7_RE.finditer(command_output):
        plaintext = decode_type7(m.group(2))
        lines.append(f"  {m.group(1)}  →  plaintext: {plaintext}")
    if not lines:
        return ""
    return (
        "\n\n## Pre-decoded Values (algorithmically verified — treat as ground truth)\n"
        "Type 7 passwords in the output above have been decoded. "
        "When creating Facts about these passwords, include the plaintext in `content`.\n"
        + "\n".join(lines)
    )


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
        # confidence 由结构派生：verification_needed 非空则不可能是 confirmed。
        # LLM 声明的 confidence 只在 speculative/likely 之间有参考价值；
        # confirmed 完全由代码决定，不依赖 LLM 自我检查。
        llm_confidence = c.get("confidence", "speculative")
        if verification:
            confidence = llm_confidence if llm_confidence in ("speculative", "likely") else "likely"
        else:
            confidence = "confirmed"

        chain_updates.append({
            "existing_chain_id": c.get("existing_chain_id"),  # None 表示新建
            "id": c.get("id", f"c{current_trial}-{i}"),
            "title": title,
            "fact_ids": fact_ids,
            "attack_narrative": c.get("attack_narrative", ""),
            "severity": c.get("severity", "medium"),
            "confidence": confidence,
            "verification_needed": verification,
            "trial_first_seen": c.get("trial_first_seen", current_trial),
        })

    device_os = data.get("device_os", "").strip()
    return new_facts, chain_updates, device_os


def _find_overlapping_chain(existing: list, new_fact_ids: list) -> str | None:
    """按 fact_ids 重叠度检测重复链，返回应被更新的已有链 ID。

    判定标准：重叠数量同时满足：
      ≥ 2（最低基线，单个共享 fact 不足以判定为同一攻击路径）
      ≥ 新链 fact 数的一半（新链大部分证据已被现有链覆盖）
      ≥ 已有链 fact 数的一半（反向：现有链大部分证据也被新链覆盖）

    双向覆盖阈值防止误合并：
      两条链仅共享一个"入口 fact"（如 HTTP 启用）但走向不同 impact → 不合并
      两条链是同一路径的重述（大量 fact 重叠）→ 合并为 update
    """
    new_set = set(new_fact_ids)
    if len(new_set) < 2:
        return None
    best_id: str | None = None
    best_overlap = 0
    for chain in existing:
        existing_set = set(chain.get("fact_ids", []))
        if not existing_set:
            continue
        overlap = len(new_set & existing_set)
        if (
            overlap >= 2
            and overlap >= len(new_set) // 2
            and overlap >= len(existing_set) // 2
            and overlap > best_overlap
        ):
            best_overlap = overlap
            best_id = chain["id"]
    return best_id


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

        # 结构性去重：LLM 未声明 existing_chain_id 时，按 fact 重叠自动匹配已有链
        if not existing_id or existing_id not in id_to_index:
            auto_match = _find_overlapping_chain(result, update.get("fact_ids", []))
            if auto_match:
                logger.info(
                    "upsert.auto_deduplicated",
                    new_title=update.get("title"),
                    matched_to=auto_match,
                )
                existing_id = auto_match

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


def _compute_next_probes(attack_chains: list, executed_commands: list[str]) -> list[str]:
    """从 speculative/likely 链的 verification_needed 汇总 next_probes。

    这是 analyze → think 反馈回路的核心：把"哪些攻击链还不确定"
    转化为"下一轮应该优先执行哪些命令"，驱动 Agent 目标导向探测。

    过滤与排序规则：
    1. 只取 confidence in ("speculative", "likely") 的链
    2. speculative 优先于 likely（更需要验证）
    3. 过滤已执行命令
    4. 去重（多个链可能需要同一条命令）
    5. 同优先级内保持 LLM 产出的原始顺序
    """
    executed_set = set(executed_commands)
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
            if cmd and cmd not in executed_set and cmd not in seen:
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

    # 代码层清理：从所有链的 verification_needed 中移除已执行命令。
    # LLM 只在更新链时才会清空 verification_needed；若本轮未更新某条链，
    # 其 verification_needed 会残留已执行命令，导致 next_probes 重复推荐。
    executed_set = set(state.get("executed_commands", []))
    for chain in updated_chains:
        chain["verification_needed"] = [
            cmd for cmd in chain.get("verification_needed", [])
            if cmd not in executed_set
        ]

    # 重算 next_probes（基于最新的 attack_chains 和 executed_commands）
    updated_probes = _compute_next_probes(
        attack_chains=updated_chains,
        executed_commands=state.get("executed_commands", []),
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

    return result


# ── severity 排序权重（report 节点使用） ────────────────────────────────────
_SEVERITY_RANK = {"critical": 0, "high": 1, "medium": 2, "low": 3}


_ENABLE_CTX_RE = re.compile(r"^enable\s+(password|secret)\s+7\s+", re.IGNORECASE)
_USERNAME_CTX_RE = re.compile(r"^username\s+(\S+)(?:\s+privilege\s+(\d+))?", re.IGNORECASE)


def _infer_account_context(line: str) -> str:
    """从包含 Type 7 密码的完整配置行推断账号/用途描述。"""
    stripped = line.strip()
    m = _ENABLE_CTX_RE.match(stripped)
    if m:
        return f"enable {m.group(1)}"
    m = _USERNAME_CTX_RE.match(stripped)
    if m:
        name = m.group(1)
        priv = m.group(2)
        return f"username {name}" + (f" (privilege {priv})" if priv else "")
    if re.search(r"\bkey\s+7\b", stripped, re.IGNORECASE):
        return "Shared key (TACACS+/RADIUS)"
    return "(unknown)"


def _extract_decoded_credentials(command_history: list) -> list[dict]:
    """从全部命令历史中提取并解码所有 Type 7 密码，附带账号上下文。

    逐行扫描：用完整配置行推断账号类型（enable / username / shared key）。
    纯算法，不依赖 LLM 产出的 Fact。

    返回列表元素：
      ciphertext    — 原始密文
      plaintext     — 解码明文
      account       — 账号/用途描述（如 "enable password"、"username admin (privilege 15)"）
      source_command — 产生该输出的命令
    """
    results: list[dict] = []
    seen_ciphertexts: set[str] = set()
    for record in command_history:
        for line in record.get("output", "").splitlines():
            m = _TYPE7_RE.search(line)
            if not m:
                continue
            ciphertext = m.group(2)
            if ciphertext in seen_ciphertexts:
                continue
            seen_ciphertexts.add(ciphertext)
            results.append({
                "ciphertext": ciphertext,
                "plaintext": decode_type7(ciphertext),
                "account": _infer_account_context(line),
                "source_command": record.get("command", ""),
            })
    return results


def _render_chain(chain: dict, facts_by_id: dict) -> str:
    """将单条 AttackChain 渲染为 Markdown 段落。"""
    severity = chain.get("severity", "medium").upper()
    confidence = chain.get("confidence", "speculative")
    lines = [
        f"### [{severity}] {chain['title']}",
        f"",
        f"- **ID**: `{chain['id']}`",
        f"- **Confidence**: {confidence}",
        f"- **First seen**: trial {chain.get('trial_first_seen', '?')}",
        f"",
        f"**Attack narrative**",
        f"",
        f"{chain.get('attack_narrative', '(none)')}",
        f"",
        f"**Supporting facts**",
        f"",
    ]
    for fid in chain.get("fact_ids", []):
        fact = facts_by_id.get(fid)
        if fact:
            lines.append(f"- `{fid}` ({fact['source_command']}): {fact['content']}")
            if fact.get("raw_evidence"):
                # 缩进引用，最多显示 3 行
                evidence_lines = fact["raw_evidence"].strip().splitlines()[:3]
                lines.append(f"  > `{'  '.join(evidence_lines)}`")
        else:
            lines.append(f"- `{fid}` (fact not found)")

    if chain.get("verification_needed"):
        lines += [
            f"",
            f"**Verification commands needed**",
            f"",
        ]
        for cmd in chain["verification_needed"]:
            lines.append(f"- `{cmd}`")

    return "\n".join(lines)


def report(state: AuditState) -> dict:
    """审计结束后生成 Markdown 报告，写入磁盘，返回 report_path。

    报告结构：
      1. 标题 + 元数据（目标、OS、时间、trial 数）
      2. 执行摘要（各 severity 链的数量统计）
      3. 攻击链详情（按 severity 排序：critical → high → medium → low）
         每条链：标题、叙述、关联 facts + raw_evidence
      4. Facts 索引（所有 facts 的扁平列表，按 trial 排序）

    纯代码生成，不调用 LLM。
    报告写入 reports/<target>_<session_id[:8]>.md（相对于项目根目录）。
    """
    target = state["target"]
    session_id = state.get("session_id", "unknown")
    started_at = state.get("started_at", "")
    device_os = state.get("device_os", "unknown")
    trial_count = state.get("trial_count", 0)
    chains = state.get("attack_chains", [])
    facts = state.get("facts", [])

    logger.info(
        "node.report",
        target=target,
        chains=len(chains),
        facts=len(facts),
        trials=trial_count,
    )

    # facts 索引：id → dict，供链渲染时查找
    facts_by_id = {f["id"]: f for f in facts}

    # 攻击链按 severity 排序
    sorted_chains = sorted(chains, key=lambda c: _SEVERITY_RANK.get(c.get("severity", "medium"), 2))

    # 统计各 severity 数量
    counts: dict[str, int] = {"critical": 0, "high": 0, "medium": 0, "low": 0}
    for c in chains:
        sev = c.get("severity", "medium")
        counts[sev] = counts.get(sev, 0) + 1

    confirmed_count = sum(1 for c in chains if c.get("confidence") == "confirmed")

    # ── 报告正文 ────────────────────────────────────────────────────────────
    now = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    sections = [
        f"# Switch Security Audit Report",
        f"",
        f"| Field | Value |",
        f"|-------|-------|",
        f"| Target | `{target}` |",
        f"| Device OS | {device_os} |",
        f"| Audit started | {started_at} |",
        f"| Report generated | {now} |",
        f"| Trials executed | {trial_count} |",
        f"| Commands executed | {len(state.get('executed_commands', []))} |",
        f"",
        f"---",
        f"",
        f"## Executive Summary",
        f"",
        f"| Severity | Count |",
        f"|----------|-------|",
        f"| 🔴 Critical | {counts['critical']} |",
        f"| 🟠 High | {counts['high']} |",
        f"| 🟡 Medium | {counts['medium']} |",
        f"| 🟢 Low | {counts['low']} |",
        f"| **Total chains** | **{len(chains)}** |",
        f"| Confirmed chains | {confirmed_count} |",
        f"| Facts extracted | {len(facts)} |",
        f"",
        f"---",
        f"",
    ]

    # ── 可用凭证区块（纯算法解码，独立于 LLM Fact） ──────────────────────────
    decoded_creds = _extract_decoded_credentials(state.get("command_history", []))
    if decoded_creds:
        sections += [
            f"## Recovered Credentials",
            f"",
            f"> **Note**: Type 7 is NOT encryption. "
            f"Any attacker with config access can decode these instantly.",
            f"",
            f"| Account / Context | Plaintext | Ciphertext | Found In |",
            f"|-------------------|-----------|------------|----------|",
        ]
        for c in decoded_creds:
            sections.append(
                f"| {c['account']} | `{c['plaintext']}` | `{c['ciphertext']}` | `{c['source_command']}` |"
            )
        sections += [f"", f"---", f""]

    sections += [
        f"## Attack Chains",
        f"",
    ]

    if sorted_chains:
        for chain in sorted_chains:
            sections.append(_render_chain(chain, facts_by_id))
            sections.append("")
            sections.append("---")
            sections.append("")
    else:
        sections.append("_No attack chains discovered._")
        sections.append("")

    sections += [
        f"## Facts Index",
        f"",
        f"All {len(facts)} security-relevant facts extracted during this audit.",
        f"",
    ]
    for fact in facts:
        sections.append(
            f"- **`{fact['id']}`** (trial {fact['trial']}, `{fact['source_command']}`): {fact['content']}"
        )

    report_text = "\n".join(sections) + "\n"

    # ── 写入磁盘 ────────────────────────────────────────────────────────────
    reports_dir = Path(__file__).parent.parent.parent.parent.parent / "reports"
    reports_dir.mkdir(exist_ok=True)
    safe_target = target.replace(".", "_").replace(":", "_")
    filename = f"{safe_target}_{session_id[:8]}.md"
    report_file = reports_dir / filename
    report_file.write_text(report_text, encoding="utf-8")

    logger.info("node.report.written", path=str(report_file))

    return {"report_path": str(report_file)}
