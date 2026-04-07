# Iter3：plan 节点（战略层）设计与分步实施计划

---

## 零、pentagi 核心启示（为什么这样设计）

pentagi 是目前最成熟的开源多 Agent 渗透测试系统。其架构的核心不是"多 Agent 并行"，而是**角色分工后的认知专注**：

| pentagi 组件 | 我们的对应设计 | 核心作用 |
|---|---|---|
| Generator | plan 节点 | 生成有序调查方向，解决"往哪里挖"的 BFS 决策 |
| Refiner | plan 节点（触发式更新）| 每发现 confirmed 链时重规划，适应性调整 |
| Primary Agent | think 节点 | 给定方向，选最优单条命令，DFS 执行 |
| Message chains | facts + attack_chains | 结构化跨命令记忆，替代原始文本累积 |
| Repeating detection | act 节点去重 | 代码层防止无限循环，不依赖 LLM |
| Mentor/Adviser | _MAX_TRIALS 上限 | 防止爆炸执行，强制有限探索 |

**关键启示**：pentagi 不让 Primary Agent 做规划决策。规划在 Generator/Refiner 完成，Primary 只做执行。这与我们把"BFS→plan，DFS→think"的设计完全吻合。

---

## 一、iter3 的核心目标

当前问题：think 同时承担"往哪里走（战略 BFS）"和"选哪条命令（战术 DFS）"两件事。
随着 facts 和 attack_chains 增长，这个决策空间爆炸，think 的注意力被稀释。

**目标**：引入 plan 节点，将战略层从 think 中剥离。

执行后，think 的输入极度简化：
- 来自 plan 的 1-3 个调查方向（已经过 BFS 决策）
- 来自 analyze 的 next_probes（待验证命令）
- 已执行命令列表

think 不再需要看全量 facts、不再需要看未覆盖的 checklist，注意力 100% 用在"当前方向下，哪条命令最有价值"。

---

## 二、iter3 分步实施（3 步，每步可独立验证）

### Step 1：引入 plan 节点（最小可验证单元）

**改动范围**：新增 `plan()` 节点函数 + 新增 `prompts/plan.md` + graph.py 注册
**不改动**：think、act、analyze、state.py

**plan 节点设计**：

```
触发时机：
  trial_count == 0：session 开始，无任何信息，生成初始调查方向
  analyze 产出新的 confirmed chain：重大发现，更新调查方向

输入（构建 user message）：
  - device_os（已知时）
  - 所有 facts（id + content，不含 raw_evidence）
  - 所有 attack_chains（id + title + severity + confidence）
  - 已执行命令列表
  - 当前调查方向列表（如有，供 Refiner 模式参考）

输出（JSON）：
  {
    "directions": [
      {"priority": 1, "focus": "Verify VLAN hopping via trunk native VLAN",
       "rationale": "f1-8 confirmed trunk has no native VLAN declaration"},
      {"priority": 2, "focus": "Check port security on access ports",
       "rationale": "f1-9 shows no port-security on access interfaces"}
    ],
    "reasoning": "..."
  }
  最多 3 个方向（防止爆炸）
```

**state.py 新增字段**：
```python
directions: list[dict]  # plan 节点输出的调查方向列表
                        # 每项：{"priority": int, "focus": str, "rationale": str}
```

**graph.py 改动**：
```
START → plan → think → act → analyze → [路由] → plan 或 think 或 END
```
路由逻辑（在 analyze 后）：
- 状态 != running → END
- trial_count >= _MAX_TRIALS → END
- analyze 产出新的 confirmed chain → "plan"（触发重规划）
- 否则 → "think"

**验证方法**：
- 检查 state["directions"] 非空
- 首轮 directions 包含侦察导向方向（如 "Layer 2 security coverage"）
- 发现第一个 confirmed 链后，directions 更新为更深入的验证方向

---

### Step 2：think 消费 directions（削减 think 上下文）

**改动范围**：`nodes/__init__.py` 的 `_build_think_context` 函数

**改动前**：think 看到全量 facts + 全量 attack_chains + 未覆盖 checklist
**改动后**：think 只看 directions（来自 plan）+ next_probes（来自 analyze）+ 已执行命令

```python
# 新的 _build_think_context（极度简化）
def _build_think_context(state: AuditState) -> str:
    directions = state.get("directions", [])
    next_probes = state.get("next_probes", [])
    executed = state.get("executed_commands", [])

    # 1. 已执行命令（去重用）
    # 2. 优先级 1：next_probes（来自 analyze 的验证命令，更高优先级）
    # 3. 优先级 2：directions（来自 plan 的调查方向，提供上下文和可选命令思路）
    # 4. 最近 2 条命令输出（短暂上下文，不再是 6 条）
```

**system.md 精简**：移除 Phase 1-4 固定清单（已被 plan 节点的动态方向取代），只保留：
- Role 定义
- 输出格式
- 约束（不重复 + 只用 show 命令）

**验证方法**：
- think 的 user message 字符数明显减少（从 ~3000 字符 → ~800 字符）
- think 的 reasoning 引用 directions 中的 focus，而非自行推断方向

---

### Step 3：plan 提示词精细化（Refiner 模式）

**改动范围**：`prompts/plan.md`（只改提示词，不改代码）

**目标**：让 plan 在 Refiner 模式下（已有 confirmed chains）能够：
1. 识别已确认的攻击链，不再分配资源深挖它们
2. 识别尚未探索的攻击面，主动补充方向
3. 在 directions 中反映证据驱动的优先级（而非固定 phase 顺序）

**验证方法**：
- 对比首轮 directions（宽泛侦察）和有 confirmed 链后的 directions（聚焦验证）
- 确认 Refiner 不重复生成已经有 confirmed chains 的方向

---

## 三、关键设计约束（坚决不做的事）

| 不做 | 原因 |
|---|---|
| plan 节点调用 SSH | plan 是纯 LLM 思考，不执行任何命令 |
| plan 节点超过 3 个 directions | 方向太多 = think 注意力分散，等同于没有 plan |
| directions 包含具体命令 | 具体命令由 think 选择，plan 只给方向和依据 |
| 每轮都触发 plan | plan 触发有条件（trial=0 或 confirmed 链新增），避免过度重规划 |
| think 继续携带全量 facts/chains | Step 2 改造后 think 只看 directions + next_probes |
| 引入向量数据库 | 当前规模（8-15 轮）用结构化 state 已足够，Iter 6 再加 |

---

## 四、文件改动清单

| 文件 | 改动类型 | 改动内容 |
|---|---|---|
| `switch_audit/core/langgraph/state.py` | 新增字段 | `directions: list[dict]` |
| `switch_audit/core/langgraph/nodes/__init__.py` | 新增函数 | `_build_plan_context`, `_parse_plan_response`, `plan()` |
| `switch_audit/core/langgraph/nodes/__init__.py` | 修改函数 | `_build_think_context`（消费 directions，削减全量 facts） |
| `switch_audit/core/langgraph/graph.py` | 修改拓扑 | plan 节点注册 + 条件路由（confirm 触发重规划） |
| `switch_audit/prompts/plan.md` | 新建文件 | plan 节点 system prompt |
| `switch_audit/prompts/__init__.py` | 新增函数 | `load_plan_prompt()` |
| `switch_audit/prompts/system.md` | 精简（Step 2） | 移除 Phase 1-4 固定清单 |
| `switch_audit/main.py` | 初始化 | `directions: []` 初始值 |

---

## 五、分步顺序与依赖关系

```
Step 1（plan 节点 + graph 改造）
  ↓ 验证：directions 被填充
Step 2（think 消费 directions + 上下文削减）
  ↓ 验证：think user message 变短，引用 directions
Step 3（plan 提示词精细化）
  ↓ 验证：Refiner 模式触发，directions 动态更新
```

每步独立可验证，可以在每步后重跑观察 LangSmith。

---

# Think 节点修复 + 架构方向决策（已完成，存档）

---

## 一、当前问题：think 上下文的三处歧义

### 问题 1（最严重）：next_probes 语义模糊 → think 以为这些命令已执行

`_build_think_context` 中（nodes/__init__.py:88-94）：
```python
"## Priority: verify these attack chain hypotheses first\n"
+ "\n".join(f"  - {p}" for p in next_probes)
```
没有说明这些命令**尚未执行**。LangSmith 日志证实：think 的 reasoning 写道 "We've already executed 'show mac address-table' and 'show port-security'"，然后跳开选了 `show cdp neighbors`。

### 问题 2：chains section 里的 `needs verification` 与 next_probes 重复，强化误判

```python
f"\n    needs verification: {c['verification_needed']}"
```
think 看到同一批命令出现两次（Priority 里一次，chains section 里一次），在推理时把它们合并成了"这些正在被验证中"的错误语义。

### 问题 3：system.md 的 Phase 1-4 与动态 next_probes 优先级冲突

system.md 列了固定的 Phase 1/2/3/4 侦察顺序。当 next_probes 非空时，think 在两套优先级之间摇摆，最终选了符合 Phase 4（CDP check）的命令，而不是 next_probes 里的命令。

---

## 二、修复方案（最小改动）

### 2.1 `nodes/__init__.py` — _build_think_context

**改动 1**：next_probes section 明确标注"未执行"
```python
# 改前
"## Priority: verify these attack chain hypotheses first\n"
+ "\n".join(f"  - {p}" for p in next_probes)

# 改后
"## Priority: run ONE of these next (NOT yet executed — needed to verify attack chain hypotheses):\n"
+ "\n".join(f"  - {p}" for p in next_probes)
```

**改动 2**：chains section 删除 `needs verification` 行（与 Priority 重复且造成混淆）
```python
# 改前
+ (f"\n    needs verification: {c['verification_needed']}" if c.get("verification_needed") else "")

# 改后（删除这行，verification_needed 信息已在 Priority section 体现）
```

### 2.2 `prompts/system.md` — 在 Phase 1-4 前加优先级覆盖声明

在 "## Constraints" 块中，在现有 "DO NOT repeat" 条目之后加一条：
```
- When "Priority: run ONE of these next" appears in the user message,
  you MUST choose from that list. Phase order is irrelevant when a priority probe exists.
```

---

## 三、架构方向决策

### 核心问题：单 think agent 的 DFS vs BFS 抉择，还是多 agent？

**方法论背景（Actor-Critic / HNSW / pentagi 经验）：**

单 agent 在 DFS 和 BFS 之间来回切换，本质上是在用有限的 context window 模拟两种不同的认知模式，效果必然折中。架构研究（AutoGPT、pentagi、HuggingGPT）都指向同一结论：

> **当任务可以分解为"战略规划"和"战术执行"时，分角色比单角色更有效。**

### 三种方向对比

| 方向 | 结构 | 优点 | 缺点 | 适合场景 |
|---|---|---|---|---|
| A. 单 think，改进优先级 | think 自己在 DFS/BFS 间权衡 | 简单，当前改动即可 | LLM 注意力分散，context 增长后效果退化 | 现在（iter2 修复） |
| B. 并行 agent（广度扫描 + 多条深挖线） | 多个 agent 同时从不同 Fact 向下挖 | 并行加速，每个 agent 专注 | 情报共享困难，需要 coordinator，复杂度高 | 后期（iter5+） |
| C. 两级分工：plan 负责广度，think 专注深挖 | plan 生成调查方向，think 只做 DFS | 职责清晰，兼容 iter3 计划，复杂度适中 | 需要 plan 节点写好才能发挥 | iter3（下一步） |

### 推荐方向：C（两级分工），分两步走

**现在（修复 iter2）**：只做 2.1 + 2.2，让单 think 正确执行 next_probes 的 DFS 指令。

**iter3**：引入 `plan` 节点，职责重新划分：
```
plan  → 广度：根据 Facts/AttackChains 生成调查方向列表（BFS 决策在这里做）
think → 深挖：从 plan 给的方向中选一条最有价值的继续挖（DFS 执行在这里做）
```

这样 think 的上下文变得极度简洁：
- 输入：plan 给的方向列表 + next_probes（来自 analyze） + 已执行命令
- 输出：选一条命令执行

think 不再需要在"该不该换方向"上浪费注意力。

### plan 节点 vs 并行 agent（为什么不选 B）

并行 agent 的情报共享问题本质上需要一个共享知识库（共享 state 或 vector store）。在 iter3 之前，这个基础设施还不存在。而且每次 SSH 到真实设备是有速率限制和审计风险的，不适合同时多个 agent 发命令。plan 节点是单次 LLM 调用，不增加 SSH 负担，且与现有 _RECON_CHECKLIST → Section 5 架构完全兼容。

---

### 三节点职责边界（iter3 后的目标架构）

三个节点对应人类渗透测试员同时运行但互相干扰的三种认知模式。分离它们的目的是让每个 LLM 调用处于最佳认知状态。

#### analyze — 感知层（无预判，原文接触）

**唯一工作**：把命令原始输出转化为结构化知识。

- 输入：最新命令完整原文 + 历史 Facts 摘要（id+content，无 raw_evidence）+ 现有 AttackChains 摘要
- 输出：新 Facts（带 raw_evidence）+ 更新后的 AttackChains（含置信度升级）
- **禁止做**：决定下一步执行什么命令

**为什么必须独立**：感知需要"原文接触"——带着战略预期读输出会产生确认偏误，漏掉意外发现。analyze 每轮都以全新注意力处理最新输出，没有"这台设备已经有问题了"的先入为主。

**关键设计**：置信度单调性由代码强制（_CONFIDENCE_RANK），不依赖 LLM；absence-of-controls（如无 native VLAN 声明）作为领域知识注入 Rule 1，因为这是 LLM 从通用训练中不能稳定获得的安全专业知识。

#### think — 战术层（窄专注，最优动作）

**唯一工作**：给定当前调查方向和待验证假设，选出下一条最优命令。

- 输入（iter3 后）：plan 的调查方向列表 + next_probes（来自 analyze 的 speculative 链待验证命令）+ 已执行命令列表
- 输出：`proposed_command`（单条命令）+ `reasoning`（推理过程）
- **禁止做**：判断是否应该切换攻击面，生成新的调查方向

**为什么必须独立**：战术决策需要窄专注。当 think 既要"选命令"又要"判断要不要换方向"时，它会在 DFS（挖当前假设）和 BFS（扫未覆盖面）之间摇摆。iter2 修复的根本原因就是 think 把战略判断（要不要验证 next_probes）和战术执行（选哪条命令）混在一起了。

**iter3 后 think 的上下文极度简洁**，不再携带原始命令历史（analyze 已提炼），不再携带全量 Facts（plan 已汇总成方向）。think 的注意力 100% 用在"哪条命令现在最有价值"。

#### plan — 战略层（全局视野，资源分配）

**唯一工作**：综合所有已知信息，维护一个有优先级的调查方向列表。

- 输入：所有 Facts + 所有 AttackChains + device_os + 已执行命令
- 输出：调查方向列表（每个方向带理由，如"因为 f1-8 发现 trunk 无 native VLAN，方向：确认 Gi1/0/4 的实际 VLAN 隔离效果"）
- **触发时机**：session 开始时（trial=0）；analyze 产出新的 confirmed 链时（重大发现触发重规划）

**为什么必须独立**：战略决策需要宽视野——把所有 Facts 和攻击面放在一起比较，决定哪个方向还没探索、哪个方向的收益最高。这件事不能在 think 里做，因为 think 已经专注在"当前方向的下一步"上了。同时也不能在 analyze 里做，因为 analyze 在处理单条命令输出时注意力必须集中在原文上。

**plan 替换了什么**：_RECON_CHECKLIST（硬编码的固定清单）。清单的问题是静态的，不会根据 device_os、已发现的漏洞、设备特征动态调整。plan 是 LLM 生成的，可以在发现 RESTCONF 开启时立即插入 `show running-config | include restconf`，而不是等 checklist 轮到它。

#### 信息流图

```
                    ┌─────────────────────────────────┐
                    │           AuditState             │
                    │  facts, attack_chains, device_os │
                    └──────┬──────────────────┬────────┘
                           │                  │
                    ┌──────▼──────┐    ┌──────▼──────┐
                    │    plan     │    │   analyze   │
                    │  (战略层)    │    │  (感知层)    │
                    │  全局视野    │    │  原文接触    │
                    │  方向列表    │    │  Facts提炼  │
                    └──────┬──────┘    └──────┬──────┘
                           │ directions        │ next_probes
                    ┌──────▼──────────────────▼──────┐
                    │            think               │
                    │          (战术层)               │
                    │    窄专注，选最优单条命令         │
                    └──────────────┬─────────────────┘
                                   │ proposed_command
                    ┌──────────────▼─────────────────┐
                    │             act                │
                    │          (执行层)               │
                    │         SSH 执行               │
                    └────────────────────────────────┘
```

#### 硬边界：哪些事绝不能跨层

| 禁止行为 | 原因 |
|---|---|
| analyze 提议下一条命令 | 污染感知层，产生确认偏误 |
| think 生成新 Facts 或新攻击链 | think 不接触原始输出，没有证据基础 |
| plan 执行具体命令决策 | plan 只管方向，具体命令由 think 根据当前上下文选择 |
| think 判断是否切换攻击面 | 这是战略决策，属于 plan 的职责 |

---

## 四、本次实现范围

**只做**：修复 think 上下文的三个问题，不引入 plan 节点。

改动文件：
- `switch_audit/core/langgraph/nodes/__init__.py`（_build_think_context，约 3 行）
- `switch_audit/prompts/system.md`（Constraints 块加 1 条规则）

**不做**：plan 节点、并行 agent、知识库。

---

## 五、验证方法

改完后重跑，检查 think 节点的 reasoning：
1. 当 next_probes 非空时，reasoning 中**不能出现** "We've already executed [next_probes 里的命令]"
2. `proposed_command` 必须是 next_probes 里的某一条（除非 next_probes 里的命令都已在 executed_commands 中）
3. LangSmith 的 think 节点 inputs 中，next_probes 里的命令不能出现在 executed_commands 中

---

# Iter 2：analyze 节点实现计划（历史存档）

> 当前状态：Iter 1 完成，facts/attack_chains 始终为空，Agent 与脚本无本质区别。
> Iter 2 目标：添加 analyze 节点，实现跨命令关联推理，产出结构化 AttackChain。

---

## 一、架构变化

**当前（Iter 1）**
```
think → act → [路由] → think 或 END
```

**Iter 2**
```
think → act → analyze → [路由] → think 或 END
```

路由函数从 act 后移到 analyze 后，逻辑不变（依赖 trial_count 和 status，analyze 不修改这两个字段）。

---

## 二、analyze 节点核心设计决策

| 决策 | 选择 | 理由 |
|------|------|------|
| LLM 调用次数 | **单次调用，两步推理** | Fact 提取和 AttackChain 推断在同一上下文中更自然；减少延迟和 API 成本 |
| 结构化输出 | **JSON 代码块（与 think 节点一致）** | SiliconFlow 的 function calling 可靠性未实测；现有 JSON 方案已验证 |
| 历史 Facts 传入 | **全量传入（id + source_command + content，省略 raw_evidence）** | 8 轮约 15 个 Facts，每条约 50 字符，共约 750 tokens，可控；全量保证关联不遗漏 |
| AttackChain upsert key | **LLM 显式提供 existing_chain_id** | title 字符串匹配不稳健；让 LLM 声明"更新 c1-0"比代码做语义匹配更精确 |
| confidence 单向性 | **代码层强制（_CONFIDENCE_RANK）+ prompt 声明** | 双重保证；已验证的链不因新一轮的推测性输出而降级 |
| skipped_duplicate 处理 | **跳过 LLM 调用，返回 {}** | 无新信息，节省 API 调用 |

---

## 三、文件改动清单

### 3.1 新建：`switch_audit/prompts/analyze.md`

analyze 节点的 system prompt，与 system.md 完全独立。

**关键 prompt 结构**：
- 角色定义：事实提取者 + 攻击链分析者，明确"你的唯一工作不是决定下一条命令"
- Fact 约束：一 Fact 一事、逐字引用 raw_evidence、有意义的独立陈述
- AttackChain 约束：≥2 个来自≥2 个不同 source_command 的 Facts；attack_narrative 用固定句式
- confidence 规则：confirmed/likely/speculative 的精确定义；speculative 必须填写 verification_needed
- existing_chain_id 机制：看到已有链 ID 列表时，声明是更新还是新建
- 输出格式：严格的 JSON schema，含字段示例和命名规则（f{trial}-{index}，c{trial}-{index}）

**完整输出 JSON schema**：
```json
{
  "new_facts": [
    {
      "id": "f{trial}-{index}",
      "trial": <int>,
      "source_command": "<exact command>",
      "content": "<one sentence>",
      "raw_evidence": "<verbatim 1-3 lines>"
    }
  ],
  "chain_updates": [
    {
      "existing_chain_id": "<id or null>",
      "id": "<c{trial}-{index}, only when existing_chain_id is null>",
      "title": "<one-line title>",
      "fact_ids": ["<id1>", "<id2>"],
      "attack_narrative": "Attacker can: 1)... → 2)... → 3) gain ...",
      "severity": "<critical|high|medium|low>",
      "confidence": "<confirmed|likely|speculative>",
      "verification_needed": ["<cmd1>"],
      "trial_first_seen": <int>
    }
  ],
  "device_os": "<from show version, or empty string>"
}
```

### 3.2 修改：`switch_audit/prompts/__init__.py`

添加 `load_analyze_prompt()` 函数，与 `load_system_prompt()` 完全对称：
```python
def load_analyze_prompt() -> str:
    prompt_path = Path(__file__).parent / "analyze.md"
    return prompt_path.read_text(encoding="utf-8")
```

### 3.3 修改：`switch_audit/core/langgraph/nodes/__init__.py`

在现有 `act()` 之后追加五个函数：

**`_build_analyze_context(state)`** — 构建 analyze 节点的 user message（四段结构）：
1. 最新 CommandRecord 的完整原始输出（供提取 Facts 和 raw_evidence）
2. 历史 Facts 列表：`[f{id}] (from {source_command}): {content}`（省略 raw_evidence）
3. 已有 AttackChains 列表：`[c{id}] "{title}" | facts=[...] | confidence={...}`（供 LLM 声明 existing_chain_id）
4. ID 提示段：明确当前 trial 编号和下一个可用 index（防止幻觉编号）

**`_parse_analyze_response(raw, current_trial)`** — 三层防御解析：
1. regex 提取 JSON 代码块（与 `_parse_think_response` 一致）
2. `json.loads` 解析
3. 字段级 `.get()` 带默认值，单字段失败不崩溃整体
- 返回 `(new_facts: list, chain_updates: list, device_os: str)`
- 解析完全失败 → `([], [], "")` + warning log

**`_upsert_attack_chains(existing, updates)`** — upsert 逻辑：
- `existing_chain_id` 非 None → 按 id 查找并更新：
  - confidence 只升级（_CONFIDENCE_RANK: speculative=0, likely=1, confirmed=2）
  - fact_ids 追加去重
  - verification_needed 替换为最新
  - attack_narrative 若非空则替换
- `existing_chain_id` 为 None → 追加新 AttackChain

**`_compute_next_probes(attack_chains, executed_commands)`** — 纯代码，无 LLM：
1. 筛选 confidence in ("speculative", "likely") 的链
2. 按优先级排序（speculative 优先于 likely）
3. 收集 `verification_needed` 中的命令，过滤已执行命令，去重
4. 返回有序的 `list[str]`

**`analyze(state)`** — 主函数：
- 跳过条件：无命令历史，或最新 status == "skipped_duplicate"
- 调用 `_build_analyze_context`，`_llm.invoke`，`_parse_analyze_response`
- 追加 facts，upsert attack_chains，重算 next_probes
- device_os 只在非空时更新（不覆盖已有值）
- 返回 `{"facts": [...], "attack_chains": [...], "next_probes": [...]}`（可选含 "device_os"）

同时在文件顶部导入：`from switch_audit.prompts import load_analyze_prompt`

### 3.4 修改：`switch_audit/core/langgraph/graph.py`

三处改动：
1. 导入 `analyze`：`from switch_audit.core.langgraph.nodes import act, analyze, think`
2. 注册节点：`builder.add_node("analyze", analyze)`
3. 修改边：
   - `builder.add_edge("act", "analyze")` — act 后无条件进 analyze
   - `builder.add_conditional_edges("analyze", _should_continue, ...)` — 路由从 act 后移到 analyze 后

注意：act → analyze 用直连 edge（不用条件路由），因为 skipped_duplicate 的跳过逻辑封在 analyze 函数内部，更简洁。

### 3.5 修改：`switch_audit/main.py`

修复两处遗留 bug（Iter 1 重构后未同步更新）：
- 第 66 行：`result["observations"]` → `result["command_history"]`（KeyError 会导致 run_audit 在完成后崩溃）
- 第 77 行：`hypothesis` → `reasoning`（字段已重命名，.get() 返回 None 导致 checkpoint history 无信息）

---

## 四、验收标准

运行 8 轮后，检查最终状态：
- `facts` 列表非空（至少从 running-config 和 http server status 各提取到 ≥2 个 Facts）
- `attack_chains` 列表非空（至少发现 "可逆密码 → HTTP 管理员访问" 这条 critical 链）
- 至少一条 chain 的 `confidence` 为 `speculative`，`verification_needed` 含有具体的验证命令
- `next_probes` 非空（包含 verification_needed 中未执行的命令）
- think 节点的下一轮 user message 显示 "Priority: verify these attack chain hypotheses first"

---

## 五、实现顺序（有依赖关系）

1. 新建 `prompts/analyze.md`
2. 修改 `prompts/__init__.py`（添加 load_analyze_prompt）
3. 修改 `nodes/__init__.py`（添加五个函数，顺序：_build → _parse → _upsert → _compute → analyze）
4. 修改 `graph.py`（注册节点，更新边）
5. 修改 `main.py`（bug 修复）

---

# Switch Audit → Open-Ended Pentest Agent
## 架构重规划（基于 pentagi 参考 + 慢迭代原则）

---

## 一、背景修正

**前一个计划的错误**：把目标定义为"合规清单审计"（YAML checklist），用 Nuclei 类比。

**实际目标**：开放式渗透测试（open-ended pentest），能发现已知漏洞，也能发现 0-day 逻辑问题。

**pentagi 验证了**：这类系统不能用固定 checklist 驱动，而是需要：
- **动态规划**（Generator agent 根据意图生成计划，Refiner agent 中途修正）
- **结构化记忆**（短期 message chain + 中期 pgvector + 长期知识图谱）
- **专家代理分工**（Pentester / Searcher / Coder / Memorist / Adviser）
- **每个动作都有结构化记录**（不是 `list[str]`，而是含 initiator/tool/result/timestamp 的结构）

---

## 二、当前代码的根本问题（逐字段分析）

### 当前 AuditState（存在的问题）

```python
class AuditState(TypedDict):
    messages: Annotated[list, add_messages]  # 未使用（思考没存进去）
    session_id: str         # OK
    target: str             # OK，但缺少 target_type / device_os 等元信息
    hypothesis: str         # 问题：把"下一步做什么"和"推理过程"混在一个字段
    observations: list[str] # 问题：原始字符串，无结构（命令/输出/时间混在一起）
    executed_commands: list[str]  # 刚加的，OK，但存在两份数据（observations 已含命令）
    trial_count: int        # OK
    status: str             # 太粗（只区分 running/completed/error）
```

**核心问题**：
1. `observations: list[str]` —— 把命令、输出、错误全部混成纯文本，LLM 需要自己解析；pentagi 里每条记录都有类型、发起者、执行者
2. `hypothesis: str` —— 把"当前猜测"和"下一步动作"混在一起，没有分离推理与行动
3. 没有 `findings`（发现的漏洞是第一等对象，不能埋在 observation 文本里）
4. 没有 `plan`（调查计划是状态的一部分，应该可以被修改和追踪）
5. `messages` 字段从未被真正使用（think() 每次重建 system+user 消息，没有利用 LangGraph 的 message accumulation）

### 当前 nodes（存在的问题）

- `think()` 把所有 observations 拼成文本扔给 LLM —— 没有利用结构
- `act()` 没有 analyze 步骤 —— 命令输出直接进 observations，没有提炼
- 没有节点负责生成/维护调查计划
- 整个循环只有两个节点：太平

---

## 三、设计原则（来自 pentagi + 工程经验）

1. **State is the audit log** —— 状态的每个字段都应该是可审计的事实，而不是 debug 字符串
2. **结构先于文本** —— 能用 TypedDict 表达的就不用 str
3. **推理与行动分离** —— LLM 的 reasoning 和 proposed_action 是两个不同字段
4. **发现是第一等对象** —— `Finding` 不能藏在 observation 文本里
5. **计划是可变的** —— 调查计划不是硬编码的，是 LLM 生成并可以被 LLM 修正的
6. **记忆有层次** —— session 内的 message chain，session 间的向量检索（后期）
7. **工具是可注册的** —— 不能永远只有 ssh_exec，工具系统要能扩展

---

## 四、迭代路线（6 步，每步可独立验证）

---

### Iteration 0：稳定当前可运行状态（本次）

**目标**：不改架构，只解决"无限循环"问题，让现有框架能完整跑完一轮。

**改动**：
- `act()` 加去重保护（command in executed_commands → skip SSH，返回 SKIPPED 观察）
- `think()` user message 显式列出 executed_commands 和剩余未检查项（临时 _AUDIT_CHECKLIST）
- 模型升级到 72B（已完成）

**验收**：8 轮内不重复命令，能覆盖 6+ 个不同命令类别。

**注意**：这一步的 `_AUDIT_CHECKLIST` 是临时的，Iteration 2 后会被动态计划取代。

---

### Iteration 1：State Schema 重设计（最关键的基础）

**目标**：把 state 从"随便一写的字符串集合"变成"有语义的审计记录"。

**核心新增**：

```python
class CommandRecord(TypedDict):
    """单次命令执行的完整记录。"""
    trial: int
    command: str
    output: str           # 原始输出
    status: str           # "ok" | "error" | "skipped_duplicate" | "ssh_error"
    timestamp: str        # ISO 8601

class Finding(TypedDict):
    """发现的安全问题（第一等对象）。"""
    id: str               # 唯一 ID，如 "stp-bpdu-001"
    trial: int            # 在第几轮发现的
    severity: str         # "critical" | "high" | "medium" | "low" | "info"
    title: str            # 简短标题
    description: str      # 详细描述，含影响范围
    evidence_command: str # 证明该漏洞的命令
    evidence_output: str  # 对应输出片段（不是全部，只是相关部分）
    recommendation: str   # 修复建议

class AuditState(TypedDict):
    # ── 会话标识 ────────────────────────────────────────
    session_id: str
    target: str
    target_os: str        # "cisco_xe" | "cisco_nxos" | ...（从 show version 更新）
    started_at: str       # ISO 8601

    # ── LangGraph managed ──────────────────────────────
    messages: Annotated[list, add_messages]

    # ── 动态调查计划 ─────────────────────────────────────
    plan: list[str]       # 当前待执行的调查方向（LLM 生成，可被修改）
    current_focus: str    # 当前正在调查的具体问题

    # ── LLM 推理（与行动分离）────────────────────────────
    reasoning: str        # 本轮的推理过程（为什么选这个命令）
    proposed_command: str # 下一步要执行的命令（干净的字段，不混入文本）

    # ── 执行日志 ─────────────────────────────────────────
    command_history: list[CommandRecord]  # 结构化执行记录
    executed_commands: list[str]          # 去重用 set（冗余但高效）

    # ── 发现 ─────────────────────────────────────────────
    findings: list[Finding]  # 发现的安全问题（由 analyze 节点填充）

    # ── 控制 ─────────────────────────────────────────────
    trial_count: int
    status: str           # "running" | "completed" | "error"
```

**关键设计决策**：
- `observations: list[str]` → `command_history: list[CommandRecord]`（结构化）
- `hypothesis: str` → 拆分为 `reasoning: str` + `proposed_command: str`
- 新增 `findings: list[Finding]`（漏洞不能再藏在文本里）
- 新增 `plan: list[str]` + `current_focus: str`（调查方向可追踪）
- `target_os` 从 `show version` 输出中提取并持久化（后续命令可以根据 OS 类型调整）

**文件改动**：`state.py`（完全重写），`main.py`（初始化新字段），`nodes/__init__.py`（适配新字段）

---

### Iteration 2：三节点循环（think → act → analyze）

**目标**：从 pentagi 的"执行后有结果分析"模式中学习，在 act 后加 analyze 节点。

**当前**：`think → act → [loop]`
**改后**：`think → act → analyze → [loop or done]`

```
think:   生成 reasoning + proposed_command（LLM 调用）
act:     执行 proposed_command，记录到 command_history（SSH 调用）
analyze: 分析 command_history[-1].output，提取 Finding，更新 plan（LLM 调用）
```

**analyze 节点职责**：
1. 分析最新的命令输出
2. 如果发现漏洞 → 创建 Finding，加入 findings
3. 更新 plan（从计划中移除已完成的调查方向，添加新发现引出的调查方向）
4. 更新 current_focus

**Pydantic 结构化输出（analyze 节点用）**：
```python
class AnalysisResult(BaseModel):
    finding: Optional[FindingCreate]  # None 表示没发现问题
    plan_update: list[str]            # 更新后的调查计划
    current_focus: str                # 下一步聚焦点
    reasoning: str                    # 分析推理
```

**文件改动**：`nodes/__init__.py`（新增 analyze()），`graph.py`（更新拓扑）

---

### Iteration 3：动态规划（Generator 模式）

**目标**：从 pentagi 的 Generator agent 学习，在审计开始时生成动态调查计划，而不是依赖 system.md 里的固定 phase 1-4。

**新增 `plan` 节点**（只在 trial_count == 0 时调用，或 findings 有重大变化时重调用）：

```
START → plan → think → act → analyze → [loop] → report
```

`plan` 节点：
- 输入：target, target_os（如果已知）, findings（已发现的），当前 plan
- 输出：新的 plan（调查方向列表）
- 使用结构化输出：`class InvestigationPlan(BaseModel): directions: list[str]`

**为什么优于 YAML checklist**：
- 计划可以根据设备型号、IOS 版本、已发现漏洞动态调整
- 发现 `show version` 结果是某个有已知漏洞的版本，plan 可以立即插入针对该 CVE 的探测
- 不受限于预定义的 15-20 条检查

**文件改动**：`nodes/__init__.py`（新增 plan()），`graph.py`（更新条件路由），`prompts/` 目录（新增 planning 专用 prompt）

---

### Iteration 4：Session 内记忆管理

**目标**：解决长 session 下 context window 溢出问题。参考 pentagi 的 summarizer agent。

**问题**：command_history 随 trial 增长，8 轮后已经很长，30+ 轮就会溢出。

**解法**：
- 在 `think` 节点构建 user message 时，不再把所有 command_history 原文贴入
- 而是：
  1. 最近 3 条 CommandRecord 贴原文（近期上下文）
  2. 较早的 CommandRecord 用摘要替代（对应 pentagi 的 summarizer）
  3. findings 始终完整贴入（结构化，不长）
  4. plan + current_focus 始终完整贴入

**实现**：`_build_context_for_llm(state: AuditState) -> str`

**文件改动**：`nodes/__init__.py`（新增 context builder 函数）

---

### Iteration 5：工具扩展（tool registry 模式）

**目标**：从 pentagi 的 40+ 工具体系学习，建立可扩展的工具注册机制。

**当前**：只有 `ssh_exec()`，硬编码在 `act()` 里。

**工具候选（按优先级）**：

| 工具 | 用途 | 优先级 |
|------|------|------|
| `ssh_exec` | 现有，执行 Cisco 命令 | 已有 |
| `web_search` | 查询 CVE 数据库、查设备 advisory | 高 |
| `ssh_exec_raw` | 发送原始 Telnet/SSH 序列（测试 Telnet 开启） | 中 |
| `snmp_walk` | SNMP 枚举（社区字符串猜测、MIB 读取） | 中 |
| `packet_probe` | 发送特制数据包（CDP/LLDP 探测、ARP 测试） | 低 |

**工具注册模式（轻量版 pentagi）**：

```python
# tools/registry.py
@dataclass
class Tool:
    name: str
    description: str
    handler: Callable[[ToolArgs], str]
    requires_confirmation: bool = False

REGISTRY: dict[str, Tool] = {}

def register(name: str, description: str, ...):
    def decorator(fn):
        REGISTRY[name] = Tool(name=name, description=description, handler=fn)
        return fn
    return decorator
```

**think/analyze 节点向 LLM 提供工具列表**，LLM 选择使用哪个工具，act 节点执行。

**文件改动**：新建 `tools/registry.py`，重构 `tools/__init__.py`，更新 `nodes/__init__.py` 和 `state.py`

---

### Iteration 6：跨 Session 记忆（pgvector）

**目标**：参考 pentagi 的 pgvector layer，实现跨 session 的语义记忆。

**存什么**：
- 成功发现漏洞的命令+分析（"这条命令在某设备上找到了 BPDU guard 缺失"）
- 失败的探测路径（"这个型号不支持 SNMP v3"）
- 设备特征（"IOS XE 17.x 的 `show ip ssh` 输出格式"）

**检索时机**：在 `plan` 节点或 `think` 节点，先查向量库，再让 LLM 基于历史经验规划

**实现**：`chromadb`（本地向量库，无需 PostgreSQL）+ embedding 模型

**文件改动**：新建 `memory/` 目录，`state.py` 加 `retrieved_knowledge: list[str]`

---

## 五、每步验收标准

| 迭代 | 验收方法 | 通过标准 |
|------|--------|--------|
| Iter 0 | 跑 8 轮 | 无重复命令，SKIPPED 日志 ≤ 1 条 |
| Iter 1 | 检查 state 输出 | command_history 有 timestamp，findings 是空列表（合法） |
| Iter 2 | 跑 8 轮 + 看 findings | findings 中有至少 1 条结构化漏洞记录 |
| Iter 3 | 检查 plan 字段 | plan 在不同设备/发现上有差异（不是固定的） |
| Iter 4 | 跑 30 轮 | 无 context window 错误 |
| Iter 5 | 加 web_search，跑含 CVE 查询的 session | web_search 被调用，结果进入 findings |
| Iter 6 | 两次 session 用同一目标 | 第二次 session 的 plan 基于第一次的记忆 |

---

## 六、不做什么（明确边界）

- **不做 Go 重写** —— 我们保持 Python/LangGraph 技术栈
- **不做 Web UI** —— CLI 优先，但 state 设计应为后期 API 化预留
- **不做 PostgreSQL** —— Iter 6 用 chromadb，不引入重型基础设施
- **不做 YAML checklist** —— 固定清单和开放式渗透测试相矛盾
- **Iter 0 的 _AUDIT_CHECKLIST** —— 是临时脚手架，Iter 3 后删除

---

## 七、文件变动总览

```
switch_audit/
├── core/langgraph/
│   ├── state.py          ← Iter 1 完全重写
│   ├── graph.py          ← Iter 2、3 更新拓扑
│   └── nodes/
│       └── __init__.py   ← 每步都有改动
├── tools/
│   ├── __init__.py       ← Iter 5 重构
│   └── registry.py       ← Iter 5 新增
├── prompts/
│   ├── system.md         ← 持续调整
│   ├── plan.md           ← Iter 3 新增
│   └── analyze.md        ← Iter 2 新增
└── memory/               ← Iter 6 新增目录
    └── __init__.py
```
