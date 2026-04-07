# 科学分析：你的设计 vs PentAGI，以及下一步路线图

> 2026-04-07（更新：知识层解耦 + 多设备兼容方向）  
> 目标：不偏颇地评估两个设计的优劣，给出有理论依据的下一步计划

---

## 一、科学分析：你的设计哪里确实更好

### 1.1 证据质量（Evidence Epistemics）

你的 Fact 结构有三个硬约束：

| 约束 | 作用 |
|------|------|
| `raw_evidence` 必须逐字引自命令输出 | 防止 LLM 幻觉出不存在的发现 |
| `source_command` 单命令归因 | 每个 Fact 可溯源，人工复核路径完整 |
| ≥2 个不同 `source_command` 才能构成 AttackChain | 防止单一命令的误报传导到链级别 |

PentAGI 的 Pentester 没有这套机制。它的发现是 LLM 从对话历史中"认为自己看到的"——在长会话中存在误忆和混淆风险。

**结论：你的证据质量优于 PentAGI，适合出具审计级报告。**

### 1.2 有向搜索效率（Directed Search）

你的 `verification_needed → next_probes` 回路做的事情，在信息论里叫 **greedy information gain maximization**：

```
当前状态：AttackChain "Type7→HTTP" 为 speculative
verification_needed: ["show ip http authentication"]
next_probes: ["show ip http authentication"]   ← think 节点优先选这条

目的：这条命令的信息增益最高——它能把 speculative 升为 likely/confirmed 或直接否定这条链
```

PentAGI 的 Refiner 是**计划层**的修正（删除/增加整个子任务），不是**命令层**的信息增益优化。

**结论：你的 next_probes 机制在侦查阶段的探测效率优于 PentAGI。**

### 1.3 可解释性与可审计性（Auditability）

完整的溯源链：

```
AttackChain c2-0 "可逆密码→HTTP管理员访问"
  └─ fact_ids: [f1-0, f2-1]
       f1-0: source_command="show running-config"
             raw_evidence="enable password 7 013057175804575D72181B"
       f2-1: source_command="show ip http server status"
             raw_evidence="HTTP server status: Enabled"
```

PentAGI 的等价信息散落在 `msglogs` 的自然语言文本里，无法程序化验证。

**结论：你的设计适合出具可被独立验证的审计报告；PentAGI 更适合快速渗透交付物。**

---

## 二、科学分析：你的设计哪里不如 PentAGI

### 2.1 "Confirmed" 是被动确认，不是攻击确认

当前语义：
```
confidence = "confirmed"
  含义：所有 Fact 直接从设备输出读取，verification_needed = []
```

实际上这是**被动确认（passive confirmation）**，不是**利用确认（exploitation confirmation）**。PentAGI 的 Pentester 在类似情况下会运行 hydra/curl 得到二元结果。在渗透测试语境中，"前提条件全部成立"≠"攻击成功"。这是你的设计目前最大的科学缺口。

### 2.2 单调置信度假设（Monotone Confidence）违反贝叶斯原理

Rule 4：置信度只能升，不能降。这是保守主义工程决策（防止 LLM 幻觉撤销真实发现），但在数学上是错误的：

```
Case A：
  Chain "Type7→HTTP" 为 likely
  新命令 "show ip http authentication" 输出："HTTP server authentication: RADIUS"
  贝叶斯更新：P(chain exploitable | RADIUS auth) ≈ 0
  但系统依然显示 likely，继续为它生成 next_probes → 浪费 trial
```

### 2.3 知识与逻辑的错误耦合（Architecture Coupling）

`_RECON_CHECKLIST` 把两件独立的事耦合在了一起：

- **命令合法性知识**：这个设备上有哪些合法命令
- **探测策略逻辑**：当前应该看哪个方向

这不只是"30% 覆盖率"的性能问题，而是架构问题：换一种设备，整个知识层都要重写，且逻辑层不可复用。

PentAGI 通过让 LLM 自己决定运行什么来绕开这个问题——代价是错误成本转移到了运行时（在 Docker 里试错）。你的场景不允许随意试错，但解法不是把知识写死，而是**把知识层与逻辑层分离**。

固定命令列表的本质是**对模型能力不足的临时补偿**，不是设计原则。随着模型能力提升，这个补偿应该逐渐撤离。

### 2.4 Token 成本随 Trial 数二次增长

```
Trial T 时的 analyze 输入大小：
  O(T) facts + O(T/4) chains + latest_output

总 Token 成本 ≈ Σ(t=1,T) O(t) = O(T²)
```

T=20 时可控；扩展到 60-100 trial，成本变成 9-25 倍。

---

## 三、综合评分

| 维度 | 你的设计 | PentAGI | 备注 |
|------|---------|---------|------|
| 证据质量（不可篡改性） | ★★★★★ | ★★★☆☆ | raw_evidence 约束是核心优势 |
| 被动侦查精度 | ★★★★☆ | ★★★☆☆ | Chain + Fact 结构减少误报 |
| 主动攻击确认 | ★☆☆☆☆ | ★★★★★ | 你目前完全没有 |
| 动态规划能力 | ★★☆☆☆ | ★★★★☆ | 静态列表 vs Refiner |
| 可解释性/可审计 | ★★★★★ | ★★☆☆☆ | 溯源链完整 |
| 矛盾证据处理 | ★★☆☆☆ | ★★★☆☆ | 单调假设有理论缺陷 |
| 扩展性（trial>50） | ★★☆☆☆ | ★★★★☆ | Token 二次增长 |
| 设备兼容性 | ★☆☆☆☆ | ★★★★☆ | 知识硬编码 vs LLM 通用知识 |
| 工具多样性 | ★★☆☆☆ | ★★★★★ | SSH show 命令 vs 50+ 工具 |

**理想架构**：你的 Fact/Chain/Evidence 结构 + PentAGI 的主动验证工具 + 解耦的可组装知识层。

---

## 四、长期架构愿景

在开始具体 Stage 之前，先明确目标架构的三层分离：

```
┌─────────────────────────────────────────────────────────┐
│  Layer 1：通用逻辑层（永远不变，设备无关）               │
│    think → act → analyze → verify 图结构                │
│    Fact / AttackChain / confidence 数据结构              │
│    Rule 1-N 通用分析规则                                 │
│    错误恢复逻辑（失败 → 换方向，不是报错停止）           │
├─────────────────────────────────────────────────────────┤
│  Layer 2：知识层（RAG 检索，按设备/场景可替换）          │
│    命令向量库：什么命令能看什么信息（含设备类型标签）    │
│    攻击模式库：什么 Fact 组合形成什么链的先验知识        │
│    历史审计库：过去审计积累的成功探测路径                │
│    算法工具：decode_type7 / decode_juniper9 / ...        │
├─────────────────────────────────────────────────────────┤
│  Layer 3：主动工具层（按场景注册，按需调用）             │
│    http_login / vlan_hop_probe / run_yersinia / ...      │
│    function calling schema 驱动，LLM 自主选择            │
└─────────────────────────────────────────────────────────┘
```

**核心原则**：
- Layer 1 里没有任何设备名称、命令名称、协议名称
- Layer 2 可以是 Cisco IOS XE 的向量库，也可以是 Juniper JunOS 的，或者混合的
- Layer 3 的工具是通用的（HTTP 登录对任何设备都一样），不是设备专属的

**命令列表的演进方向**：

```
现在（Phase 1）：
  固定列表注入 → 模型从中选 → 可靠但僵化

中期（Phase 2）：
  RAG 检索 top-k 相关命令 → 模型从 hint 里选或提出新命令 → 灵活但有护栏

长期（Phase 3，更好的模型）：
  知识库作为参考 → 模型自主决定运行什么 → 错误时自动重试 → 和 PentAGI 一致
```

Phase 1 → Phase 2 → Phase 3 是模型能力提升驱动的自然演进，不是重构。

---

## 五、路线图：分阶段实施

### Stage 1：Type 7 离线解码（现在，1-2天）

**目的**：补齐"passive confirmed"到"可操作凭证"的最后一步。Type 7 解码是纯算法，法律无争议。

**具体做什么**：

1. 在 `switch_audit/tools/crypto.py` 实现 `decode_type7(ciphertext: str) -> str`
2. 在 `analyze` 节点的 `_build_analyze_context` 里加 `_precompute` 调用：
   ```python
   def _precompute(command_output: str) -> str:
       """纯算法计算，结果注入 LLM 上下文作为 ground truth。"""
       lines = []
       for m in re.finditer(r'(?:password|key)\s+7\s+([0-9A-Fa-f]+)', command_output):
           decoded = decode_type7(m.group(1))
           lines.append(f"  {m.group(0)}  →  plaintext: {decoded}")
       if lines:
           return "\n\n## Pre-decoded (algorithmically verified, treat as ground truth):\n" + "\n".join(lines)
       return ""
   ```
3. LLM 在分析时看到解码结果，可以直接在 Fact 里写明文密码，AttackChain 的 confidence 据此更新
4. 在 `report` 节点加"可用凭证"专属区块

**验证**：
- 用已知明文对照表验证算法正确性（离线）
- 跑一次审计，看 Fact 里是否出现明文密码，Chain confidence 是否提升

---

### Stage 2：矛盾证据降级（Stage 1 之后，1天）

**目的**：修复单调置信度的数学错误，防止矛盾证据出现后系统还在浪费 trial 验证已死的链。

**具体做什么**：

修改 `analyze.md` 的 Rule 4：

```
Rule 4 修订：
  置信度通常只升不降。
  例外：当新 Fact 明确否定某条链的关键前提时（不是质疑，而是直接反驳），
  可将该链的 confidence 降为 "refuted"，verification_needed 清空。
  
  降级条件（需同时满足）：
  1. 新 Fact 来自实际命令输出（非推断）
  2. 新 Fact 直接否定链中某步骤（如"HTTP auth 为 RADIUS"否定"enable password 可用于 HTTP 登录"）
  3. 该步骤是链的关键路径（不是可选前提）
```

在 `AttackChain` 结构里增加 `"refuted"` confidence 值。report 节点单独列出 refuted 链（"以下路径已被后续证据排除"）。

**验证**：构造矛盾场景（Type 7 密码存在但 HTTP auth 为 RADIUS），验证对应 Chain 变为 `refuted`，next_probes 不再包含它的 verification_needed。

---

### Stage 3：主动验证 + verify 节点（GNS3 就绪后，3-5天）

**目的**：从"passive confirmed"跨越到"exploitation confirmed"，填补最大科学缺口。

**具体做什么**：

**3a：主动验证工具**（Layer 3，通用，非设备专属）

```python
# switch_audit/tools/active.py

def http_login(host: str, port: int, username: str, password: str,
               timeout: int = 10) -> dict:
    """HTTP Basic Auth 登录尝试。设备无关。"""
    # returns {"success": bool, "status_code": int, "evidence": str}

def vlan_hop_probe(interface: str, target_vlan: int, native_vlan: int = 1) -> dict:
    """双标签 VLAN 帧注入。设备无关。"""
    # returns {"success": bool, "frames_received": int, "evidence": str}
```

**3b：图拓扑更新**

```python
think → act → analyze → (有 confirmed 链且 VERIFY_ENABLED?) → verify → report
                       → (否)                                → think
```

verify 节点：LLM 读取 confirmed 链 + 可用工具列表（function calling schema），自主选择工具执行，结果写为新 Fact，confidence 升为 `confirmed_exploited` 或降为 `likely`。

**3c：AttackChain 增加 `confirmed_exploited` 级别**

```python
confidence: str  # "confirmed_exploited"|"confirmed"|"likely"|"speculative"|"refuted"
```

**验证**：GNS3 靶机上跑端到端：侦查 → confirmed 链 → http_login 成功 → `confirmed_exploited`；负向：密码改掉后 → `likely`。

---

### Stage 4：知识层解耦（RAG 命令库）（Stage 3 稳定后，1周）

**目的**：把命令知识从 prompt 里撤出，改为 RAG 检索。这是实现多设备兼容的核心架构变化，也是向 PentAGI 的"模型自主选择"演进的第一步。

**为什么现在做**：Stage 3 完成后，verify 节点开始执行主动探测，侦查阶段需要覆盖更多命令（尤其是发现新攻击面后），固定列表的 30% 覆盖率瓶颈会真正暴露。

**具体做什么**：

**4a：命令向量库**

把 `ios_xe_commands.yaml` 转换为向量库（每条命令 + 描述 + 安全分类 embedding）：

```python
# knowledge/store.py
class KnowledgeStore:
    def search_commands(self, query: str, device_type: str, top_k: int = 10) -> list[str]:
        """根据当前探测目标语义检索最相关命令。"""
        # e.g. query="HTTP 管理认证方式" → ["show ip http authentication", ...]

    def add_command(self, command: str, description: str, device_type: str):
        """新发现有效的命令后写入知识库（无需重启）。"""
```

**4b：think 节点改为 RAG 辅助**

```python
def _build_think_context(state, knowledge_store):
    # 1. 基于当前 AttackChains 生成查询意图
    query = _derive_search_intent(state["attack_chains"], state["next_probes"])
    
    # 2. 检索最相关的 top-10 命令作为 hint
    relevant_commands = knowledge_store.search_commands(
        query=query,
        device_type=state["device_type"],   # 新增字段
        top_k=10
    )
    
    # 3. 移除"只能从列表选"的约束，改为"优先参考这些命令"
    guidance = f"## Suggested commands (retrieved by relevance, not exhaustive):\n"
    guidance += "\n".join(f"  - {c}" for c in relevant_commands)
    guidance += "\n\nYou may also propose commands not in this list if they serve the investigation."
```

**4c：错误恢复（Error Recovery）**

在 think 的 system prompt 里加：

```markdown
## Error Recovery
If the last command returned `% Invalid input`, `% Ambiguous command`, or ssh_error:
- Do NOT retry the same command
- Diagnose from the error: was it a syntax issue, unsupported feature, or connectivity?
- Propose an alternative that achieves the same information goal
```

**4d：知识库自增长**

analyze 节点发现 dynamic_probe 命令产生了有效 Fact 后，自动写入向量库（标记为"待 review"）。

**验证**：
- 同一目标，关闭 RAG（用固定列表）vs 开启 RAG，比较 trial 利用率和 Fact 质量
- 换一台路由器（不同 device_type），验证向量库能返回相关但不同的命令
- 验证错误命令后系统能自动换方向，不卡死

---

### Stage 5：工具注册表 + 知识积累（产品化，2周）

**目的**：借鉴 PentAGI 的 Tool Registry + Graphiti（知识图谱），让系统能跨次审计积累知识，以及让攻击手完全由 LLM 驱动。

**具体做什么**：

**5a：工具注册表**（Layer 3 统一接口）

```python
# switch_audit/tools/registry.py
TOOL_REGISTRY = {
    "http_login":       {"fn": http_login,       "schema": {...}},
    "vlan_hop_probe":   {"fn": vlan_hop_probe,   "schema": {...}},
    "run_yersinia":     {"fn": run_yersinia,     "schema": {...}},
    "run_macof":        {"fn": run_macof,         "schema": {...}},
    # 新工具：append 一行，verify 节点自动可用
}
```

**5b：审计知识积累**（类 Graphiti，但简化版）

每次审计结束后，把成功路径（confirmed_exploited 的 AttackChain + 对应的 Fact sequence）存入向量库的"历史审计"分区：

```python
# 下次审计同类目标时，knowledge_store.search_commands() 能检索到历史成功路径
# think 节点看到"上次在类似目标上，这条命令序列发现了高危链"
```

这是 PentAGI Graphiti 的简化版——不需要图数据库，向量库就够，因为你需要的是"相似场景"检索，不是"实体关系"查询。

**5c：verify 节点完全 LLM 驱动**

verify 节点变成类似 PentAGI Pentester 的小型 ReAct agent：
- 输入：confirmed AttackChains + TOOL_REGISTRY 的 function calling schema
- LLM 自主决定用哪个工具，以什么参数
- 上限：10 次工具调用
- 结果写回 Fact + 更新 Chain confidence

**验证**：
- GNS3 完整流程：侦查 → RAG 辅助探测 → confirmed → verify（LLM 自选工具）→ `confirmed_exploited` → 报告
- 换 device_type，验证知识库自动切换，逻辑层代码不改
- 跑第二次同类审计，验证历史知识是否提升了 Fact 发现速度

---

## 六、依赖关系与优先级

```
Stage 1（Type 7 解码）           ← 现在，无依赖
Stage 2（矛盾降级）              ← 与 Stage 1 并行
Stage 3（verify 节点）           ← GNS3 就绪后
Stage 4（RAG 知识层）            ← Stage 3 完成后（trial 瓶颈暴露时）
Stage 5（工具注册表 + 知识积累） ← Stage 4 稳定后
```

**什么时候 Phase 2（RAG）→ Phase 3（完全自主）**：
取决于模型能力，不是时间节点。当 Phase 2 的错误率（invalid command rate）低于 5%，且 trial 利用率（每 trial 产出有效 Fact 的比例）高于当前固定列表时，可以逐步放开约束，向 Phase 3 演进。

---

## 七、不要丢的东西

这些设计在整个演进过程中保持不变：

1. **raw_evidence 逐字引用约束**：永远不放松，这是假阳性防线
2. **≥2 source_command 成链约束**：攻击工具结果（http_login_attempt）可作为第三个 source，但链的初始成立仍需 ≥2 个被动观察 Fact
3. **verification_needed 驱动 next_probes**：RAG 检索和动态探测都是次级优先，confirmed chain 的 verification 始终最高优先
4. **每次工具调用的理由显式记录**：verify 节点选工具的原因写进日志，不能是黑盒
5. **Fact 只追加，不修改**：已写入的 Fact 是不可变的历史记录，confidence 变化只通过新 Fact + chain_patch 表达
