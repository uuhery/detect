# Iter 3 修复方案：消除 plan 与 next_probes 的驱动冲突

---

## 一、问题的本质（从第一性出发）

### 原始设计意图（harmonic-growing-wand.md）

```
next_probes（analyze产出）→ think Priority 1  ← 链式深挖（DFS）
directions（plan产出）   → think Priority 2  ← 攻击面探索（BFS）
```

两个机制设计为**互补**：next_probes 非空时 think 专注深挖，next_probes 空时 think 用 directions 转向新面。

### 实际运行中断裂的原因

**问题 1（已修复）**：analyze 在 trial=1 就对单 Fact 链报 `confirmed`，导致 next_probes 从一开始就是空的，directions 从第一轮就接管了全部驱动。
→ 已在 analyze.md Rule 2 中加入硬约束：单 Fact 或同源 Fact 的链不得为 confirmed。

**问题 2（未修复，是本次核心）**：plan 重规划触发条件是 `confirmed_count > snapshot`。这意味着：
- 每产出一条新 confirmed 链 → plan 重写 directions
- directions 完全替换，新方向可能与旧的 speculative 链的 next_probes 无关
- think 下一轮看到的是新 directions，而不是"继续深挖旧的 speculative 链"
- 旧的 speculative 链的 next_probes 还在，但 think 可能忽略它（因为 directions 也在叫）

**实际表现（iter3 新 run 数据）**：
- 修复后 next_probes 恢复了（rule 2 起作用）
- 但 12 轮全部跑完后，链比 iter2（8轮）还少（5条 vs 7条）
- 命令覆盖面更广，但没有深挖出 iter2 里的 VLAN 1 ARP 链、CDP 拓扑链

**根本原因**：plan 重规划的频率与"链式深挖完成"的时机不同步。plan 在第一个 confirmed 链出现时就重规划，但此时还有多个 speculative 链需要验证。重规划后 directions 变了，think 被拉向新方向，speculative 链的 next_probes 还在但竞争不过新的 directions。

### 哲学层面的矛盾

原始设计的 Priority 1 > Priority 2 是正确的，但 **plan 重规划的时机打断了这个优先级链条**。每次重规划都是一次"战略层强行插手战术层正在进行的深挖任务"，即使 think 名义上 Priority 1 更高，但：
1. directions 每次重规划后都换了，think 对当前深挖任务的"惯性"被重置
2. plan 生成的新 directions 是面向"新发现的 confirmed 链之后的未探索面"，不是"当前 speculative 链的验证"——这与 next_probes 重叠但不完全一致

---

## 二、修复方案：plan 只在 next_probes 耗尽后才重规划

### 核心改动：修改 `_should_continue` 的路由逻辑

**现状（graph.py）**：
```python
if current_confirmed > snapshot:
    return "plan"  # 有新 confirmed 链就重规划
return "think"
```

**修改后**：
```python
# 有新 confirmed 链，但 next_probes 非空 → 先让 think 继续深挖
# 只有 next_probes 也空了，才触发重规划
if current_confirmed > snapshot:
    next_probes = state.get("next_probes", [])
    if next_probes:
        # 有待验证的链，先让 think 去验证，plan 的重规划等一下
        return "think"
    else:
        return "plan"  # 没有待验证命令了，此时重规划才有意义
return "think"
```

### 语义解释

这个改动的含义是：**plan 重规划的时机从"发现新 confirmed 链时"改为"发现新 confirmed 链 AND 当前没有待验证命令时"**。

- confirmed 链增加 + next_probes 非空：说明 analyze 已经在追踪新的 speculative 链了，think 继续执行 next_probes，等 speculative 链也被验证完
- confirmed 链增加 + next_probes 空：说明当前所有已知链都已确认或无法继续验证，此时才让 plan 重新看全局、补充新方向

这保证了 **链式深挖不会被 plan 的重规划打断**。

### 同时需要更新 `_plan_confirmed_count` 快照的时机

当前逻辑：plan 执行时记录 confirmed 快照。
修改后：如果因为"next_probes 非空"而跳过了 plan，confirmed 快照不会更新，下一轮还会再次判断"confirmed > snapshot"，还会再次路由到 think（如果 next_probes 还不空）。

这是**正确行为**：plan 触发条件一直成立，但只要 next_probes 不空就一直不执行，直到 next_probes 清空时才执行 plan 并更新快照。不需要额外改动。

---

## 三、文件改动（最小化）

### 唯一改动：`switch_audit/core/langgraph/graph.py`

修改 `_should_continue` 函数，在路由到 "plan" 之前增加一个判断：

```python
if current_confirmed > snapshot:
    # 有新 confirmed 链，但先检查是否还有待验证的 speculative/likely 链
    if state.get("next_probes"):
        # next_probes 非空：think 继续深挖，plan 重规划延迟
        return "think"
    # next_probes 空：此时重规划才有意义
    logger.info(
        "audit.replan_triggered",
        confirmed_now=current_confirmed,
        confirmed_at_last_plan=snapshot,
        reason="next_probes_exhausted",
    )
    return "plan"
```

**注释更新**：同时更新函数 docstring，说明新的路由逻辑。

### 不需要改动的文件

- `analyze.md`：Rule 2 硬约束已经修复了单 Fact confirmed 问题，保留
- `nodes/__init__.py`：think/analyze/plan 节点逻辑不变
- `state.py`、`main.py`、`system.md`、`plan.md`：不需要修改

---

## 四、预期效果

修复后的信息流：

```
Trial 1: analyze → confirmed 链增加（如 c1-0 HTTP 链），同时产出 speculative 链（如 c1-3 VLAN Hopping）
         → next_probes = ["show interfaces trunk"]
         → _should_continue: confirmed > snapshot BUT next_probes 非空 → think
Trial 2: think → Priority 1 执行 show interfaces trunk（来自 next_probes）
         → analyze → c1-3 升为 confirmed，新 speculative 链...
         → _should_continue: confirmed > snapshot BUT next_probes 非空 → think
... （继续深挖直到 next_probes 空）
Trial N: next_probes 空了
         → _should_continue: confirmed > snapshot AND next_probes 空 → plan
         → plan 重规划，directions 指向还未探索的攻击面
```

这样 plan 和 next_probes 不再竞争，而是严格串行：next_probes 主导时 plan 等待，next_probes 耗尽时 plan 接管。

---

## 五、验证方法

跑一次新的 session，检查最终 state：

1. `next_probes` 的命令是否都被执行了（不再被 directions 抢占）
2. attack_chains 里 speculative/likely 链是否在后续 trial 中被验证（不再"中途断链"）
3. 链的总数是否接近或超过 iter2 的 7 条
4. LangSmith 里查看 plan 节点的触发时机——是否只在 next_probes 空时才触发

---

## 六、关键文件路径

- 主要修改：`switch_audit/core/langgraph/graph.py`（`_should_continue` 函数，约 +5 行）
- 已有修复：`switch_audit/prompts/analyze.md`（Rule 2 硬约束，已生效）
- 参考：历史计划 `C:/Users/marimo/.claude/plans/harmonic-growing-wand.md`
