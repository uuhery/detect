# 下一步方向 Plan

## Context

当前项目处于 Iter 2 完成状态：think → act → analyze 三节点循环，能发现复合攻击链。
Iter 3（plan 节点）已放弃，原因是战略层和战术层的触发时机无法协调，引入了复杂性但效果回退。

用户现在的困惑：有多个方向可以走（并行 thinker、记忆机制、攻击手验证），不知道优先级和顺序。

---

## 当前真实问题（按严重程度排序）

### P0：analyze 的 Fact/Chain 质量问题（已部分修复）
- Rule 1 / Rule 2 刚刚改好：Fact 不含推断，每步需要 Fact 支撑
- **但还没有跑过验证**，需要一次真实运行确认改动有效

### P1：trial 数量只有 8，太少
- 8 次 trial 里 `show running-config` 就占了 1 次且输出极长
- 知识库有 61 条命令，8 次根本跑不完关键的
- 没有任何"哪些命令是必须跑的"保障

### P2：没有报告输出
- 审计结束后 state 里有 facts 和 attack_chains，但没有任何可读的报告
- 现在只能靠看 JSON log 理解结果

### P3：验证（攻击手）机制——用户提出的方向
- 对 `confirmed` 链进行主动验证（实际尝试利用）
- 这是正确方向，但依赖 P0 先解决，否则验证的是错误的链

---

## 推荐顺序

### Step 1：先跑一次，验证 Rule 1/2 改动效果（1天）
直接用 devnetsandbox 目标跑，看新的 analyze 输出：
- Fact 是否不再含推断
- confidence 是否更保守
- `show ip http server status` 是否被正确加入 verification_needed

**判断标准**：之前被错标为 confirmed 的 c1-0（HTTP 链）现在应该是 `likely` 或 `speculative`。

### Step 2：加报告节点（2-3天）
在 analyze 后、END 前加一个 `report` 节点，只在 `_should_continue` 路由到 END 时触发。
- 输入：最终 state 的 facts + attack_chains
- 输出：Markdown 报告文件（按 severity 排序的攻击链 + 每条链的证据引用）
- 不调用 LLM，纯代码生成

这解决了"审计完了看不到结果"的问题，对用户最直接有价值。

### Step 3：增加 trial 数量 + 必跑命令保障（1天）
- `_MAX_TRIALS` 从 8 改到 20
- 在 `_build_think_context` 里加"必跑命令"优先级（show version、show running-config 必须最先跑）
- 或者直接在 `main.py` 里预执行这两条，作为 initial_state 的一部分

### Step 4：攻击手验证节点（用户提出，之后再做）
触发时机：所有 next_probes 耗尽 且 存在 confirmed 链
做法：对每条 confirmed 链，根据 attack_narrative 生成一个验证动作（如尝试 HTTP 登录、发 VLAN-tagged 包）
这需要 act 节点支持除 show 命令之外的操作，是较大的架构扩展。

---

## 不推荐做的

### 并行 thinker
你的瓶颈不是命令执行速度，是 trial 数量上限和 analyze 质量。
并行 thinker 会引入命令冲突（两个 thinker 同时执行互相依赖的命令）和状态合并复杂性，收益低风险高。

### 记忆机制（跨 session）
当前单次 session 内的 8 个 trial 都还没跑好，跨 session 记忆是过度设计。
等报告输出做好、单次审计质量稳定后再考虑。

### 重写为纯 openai SDK
现有 LangGraph 的 MemorySaver 确实没用上太多特性，但重写成本高、风险高，收益仅是代码更简洁。
`report` 节点和攻击手节点都能在现有 LangGraph 框架下干净地加进去。

---

## 关键文件

- `switch_audit/prompts/analyze.md` — 刚改完 Rule 1/2，需要验证
- `switch_audit/core/langgraph/graph.py` — 加 report 节点和触发逻辑
- `switch_audit/core/langgraph/nodes/__init__.py` — 实现 report 节点函数
- `switch_audit/core/langgraph/state.py` — 可能需要加 `report_path` 字段

---

## 验证方式

```bash
uv run python -m switch_audit.main --target devnetsandboxiosxec9k.cisco.com
```

看输出：
1. c1-0（HTTP 链）的 confidence 是否不再是 confirmed
2. 审计结束后是否生成 Markdown 报告文件
3. trial 数量是否足够覆盖关键命令
