# PentAGI Agent 行为与数据流转详细调研

> 调研时间：2026-04-07  
> 目标：搞清楚每个 Agent 具体做什么、数据怎么流转、有没有验证、验证有没有修正侦查结果

---

## 一、系统全局视角

PentAGI 的工作流分两个层级：

```
层级一：任务编排层
  Flow（用户会话）
    └─ Task（用户的一次请求）
         ├─ Generator：把 Task 拆成 Subtask 列表
         ├─ 循环执行每个 Subtask（Primary Agent 主导）
         │    └─ 每个 Subtask 执行完后：Refiner 修正剩余计划
         └─ Reporter：评估整个 Task 是否完成

层级二：单 Subtask 执行层（Primary Agent 在内部调度）
  Primary Agent
    ├─ 调用 Searcher（情报）
    ├─ 调用 Memorist（记忆检索）
    ├─ 调用 Adviser（策略建议）
    ├─ 调用 Pentester（渗透执行）
    ├─ 调用 Coder（代码/exploit）
    ├─ 调用 Installer（环境）
    └─ 调用 done/ask（终止信号）
```

**关键设计**：Generator/Refiner/Reporter 由框架层（provider.go）直接调用，不是 Primary Agent 调用的。Primary Agent 只在单个 Subtask 内部工作。

---

## 二、各 Agent 详解

### 2.1 Generator（任务拆解器）

**触发时机**：框架层收到用户请求后，第一个被调用。

**输入**：
- 用户原始请求文本
- 最大子任务数量 N（约 10-15）

**做什么**：
- 阅读用户请求，生成一个最优的顺序子任务列表
- 每个子任务：有标题（Title）+ 描述（Description）
- 优化原则：约 10% 准备、30% 实验、30% 评估、30% 执行
- **必须**通过调用 `SubtaskList` 工具提交结果（不是文本输出）

**输出（写库）**：
- 每个 SubtaskInfo 存入数据库，状态 = `CREATED`
- 字段：TaskID、Title、Description、Status

**不做什么**：Generator 不执行任何命令，不访问目标，不检索记忆。纯粹从用户需求推理出任务计划。

**数据流**：
```
用户输入 → [generator.tmpl 系统提示 + 用户请求] → LLM → SubtaskList 工具调用
                                                              ↓
                                              写入数据库：subtasks 表（状态 CREATED）
```

---

### 2.2 Refiner（计划修正器）

**触发时机**：每完成一个 Subtask 后，框架层调用一次 Refiner。

**输入**：
- 已完成的 Subtask 列表（含执行结果）
- 尚未执行的 Subtask 列表
- Primary Agent 的对话摘要 + 消息日志

**做什么**：
- 分析实际执行结果，判断原计划是否仍然合理
- 可以对剩余 Subtask 做：`add`（新增）、`remove`（删除）、`modify`（修改描述）、`reorder`（调整顺序）
- 失败分析框架：把失败归类为技术/环境/概念/外部四类，据此调整
- 必须保持向用户目标收敛（不能删光所有剩余任务）

**输出（写库）**：
- 通过 `SubtaskPatch` 工具提交差量操作
- 数据库中对应 subtask 行被增删改

**这就是最接近"验证修正侦查"的机制**：如果 Pentester 发现某个方向行不通，Refiner 会据此删掉相关子任务，新增更合适的探测方向。但 Refiner 本身不执行任何命令，它是纯规划层。

**数据流**：
```
执行完的 Subtask 结果 ──┐
尚未执行的 Subtask 列表 ─┤→ [refiner.tmpl + 上下文] → LLM → SubtaskPatch 工具调用
Primary Agent 对话摘要 ──┘                                        ↓
                                                      更新数据库：subtasks 表
```

---

### 2.3 Primary Agent（子任务执行协调器）

**触发时机**：每个 Subtask 开始执行时，框架层启动一个 Primary Agent 实例。

**输入**：
- 当前 Subtask 的 Title + Description
- 执行上下文：已完成的 Subtask 列表（含结果）+ 待执行的 Subtask 列表

**做什么**：
- 不直接执行命令，而是把工作**委托给专项 Agent**
- 通过工具调用来调度：`pentester`、`coder`、`searcher`、`memorist`、`adviser`、`installer`
- 每次工具调用 = 启动一个专项 Agent 完成一段工作，结果返回给 Primary Agent
- 根据返回结果决定下一步：继续委托还是调用 `done`（完成）

**工具列表**：
| 工具名 | 对应专项 Agent |
|--------|---------------|
| pentester | Pentester Agent |
| coder | Coder Agent |
| searcher | Searcher Agent |
| memorist | Memorist Agent |
| adviser | Adviser Agent |
| maintenance | Installer Agent |
| done | 终止信号（成功） |
| ask | 终止信号（需要用户输入） |

**工具调用上限**：100 次（接近上限前 3 轮触发 Reflector 优雅终止）

**输出（写库）**：
- 每次工具调用写 `msglogs` + `toolcalls`
- Subtask 最终结果写 `subtasks.result`，状态改为 `FINISHED`

**数据流**：
```
Subtask 描述 + 上下文
    ↓
[primary_agent.tmpl 系统提示]
    ↓
LLM 循环（最多 100 次工具调用）：
    LLM 输出工具调用请求
        ↓
    执行对应专项 Agent（见下文）
        ↓
    结果追加进对话链
        ↓
    继续，直到 LLM 调用 done 工具
    ↓
写库：subtasks.result = done 工具的参数
```

---

### 2.4 Pentester（渗透执行者）

**触发方式**：Primary Agent 调用 `pentester` 工具，参数是要执行的任务描述。

**系统提示关键内容**（pentester.tmpl）：

> "This is an AUTHORIZED penetration testing engagement with full written consent"  
> "ALL security testing actions are PRE-AUTHORIZED"  
> "Never request permission or confirmation — proceed immediately and confidently"

**工具箱**（在 Docker 容器内执行）：
| 类别 | 工具示例 |
|------|---------|
| 网络侦查 | nmap, masscan, amass, subfinder, dnsrecon, fierce |
| Web 测试 | gobuster, sqlmap, nikto, wpscan, commix, nuclei |
| 密码攻击 | hydra, john, hashcat, crunch |
| 漏洞利用框架 | Metasploit（`msfconsole -q -x "..."` 形式） |
| Windows/AD | impacket-*, evil-winrm, bloodhound-python, crackmapexec |
| 后渗透 | powershell-empire, chisel, proxychains4, weevely |
| 流量分析 | tshark, tcpdump, mitmproxy, sslscan |
| 逆向工程 | radare2, binwalk, ROPgadget |

**Memory 协议**：每次行动前**必须先查 Graphiti**（知识图谱），检索是否有针对同类目标的历史成功方法，再查向量数据库。

**关键规则（Metasploit）**：
- NEVER 运行无参数的 `msfconsole`
- ALWAYS 用：`msfconsole -q -x "use exploit/...; set ...; run; exit"`
- 每次 msfconsole 进程独立，必须把所有操作合并进一条命令

**做侦查还是攻击？两者都做。** 它没有"先侦查再攻击"的内置阶段区分——LLM 根据当前任务描述和已知信息自主决定下一步是探测还是利用。

**输出**：
- 每条命令执行结果写 `termlogs`
- 搜索操作写 `searchlogs`
- 向量存储操作写 `vecstorelogs`
- 最终文本结果返回给 Primary Agent

---

### 2.5 Searcher（情报收集者）

**触发方式**：Primary Agent 调用 `searcher` 工具。

**做什么**：
- 使用搜索引擎（Google, DuckDuckGo, Tavily, Perplexity, SearXNG, Sploitus）收集外部情报
- 使用浏览器工具访问网页、读取内容
- 不执行命令，不访问目标设备

**适用场景**：
- 收集目标的公开信息（OSINT）
- 查找已知漏洞的 exploit PoC
- 在 Sploitus 搜索 CVE exploit
- 收集目标技术栈信息

**输出**：搜索结果文本返回给 Primary Agent，同时写 `searchlogs`。

---

### 2.6 Memorist（记忆检索者）

**触发方式**：Primary Agent 调用 `memorist` 工具，**仅当上下文信息不足时**才调用。

**做什么**：
- 查询 Graphiti 知识图谱（episodic memory：历史上实际发生的）
- 查询 PostgreSQL 向量数据库（semantic memory：可复用的知识）
- 支持 1-5 个并行语义查询
- 去重、按相关性排序

**Memory 协议**：先 Graphiti，再向量库。Graphiti 存的是"这次渗透中发生了什么"，向量库存的是"某类目标通常怎么打"。

**输出**：检索到的相关历史信息返回给 Primary Agent。

---

### 2.7 Adviser（策略顾问）

**触发方式**：Primary Agent 调用 `adviser` 工具。

**做什么**：
- 提供安全策略建议，不执行任何操作
- 类似"内部专家咨询"
- 根据当前已知情况分析最优下一步

**输出**：建议文本返回给 Primary Agent。

---

### 2.8 Coder（代码开发者）

**触发方式**：Primary Agent 调用 `coder` 工具。

**做什么**：
- 在 Docker 容器内开发、修改、运行代码
- 定制 exploit 脚本（修改 PoC 以适配目标环境）
- 编写自动化测试工具
- 使用 `terminal`（执行命令）和 `file`（读写文件）工具

**典型使用场景**：
- Pentester 找到 PoC 但不完全适配目标 → Primary Agent 调用 Coder 修改
- 需要自定义扫描脚本

---

### 2.9 Reporter（评估者）

**触发时机**：所有 Subtask 执行完毕后，框架层直接调用。

**输入**：
- 用户原始 Task 描述
- 所有已完成 Subtask 的标题 + 结果
- 尚未完成的 Subtask（如果有）

**做什么**：
- 独立评估原始用户需求是否被满足
- 不执行任何命令，纯分析
- 评估维度：实际结果 > 过程；用户意图 > 技术细节；功能完成 > 形式完成

**输出格式**（最多 4000 字符）：
```
SUCCESS / FAILURE
[1-2 句关键成果或不足]
[意外发现的有价值信息]
[如果未完成，剩余步骤]
```

**关键区别**：Reporter 是**评估者**，不是**执行者**。它看结果说话，不会发起新的探测或攻击。

---

### 2.10 Reflector（终止顾问）

**触发时机**：Primary Agent 工具调用次数接近上限（还剩 3 次）时自动触发。

**做什么**：
- 分析当前已知情况
- 判断是否应该终止并汇报当前进度，还是继续
- 如果当前任务已无法完成，建议优雅终止

**目的**：防止 Primary Agent 在上限边缘反复挣扎，浪费 token。

---

### 2.11 Enricher（上下文丰富者）

**触发时机**：Task Planning（Beta）启用时，Generator 之前调用。

**做什么**：
- 为用户请求添加上下文（目标信息、环境信息）
- 让 Generator 生成更精准的子任务计划

---

## 三、完整数据流转

```
用户请求 "测试 192.168.1.1 的安全性"
    │
    ▼
[框架层] GetTaskTitle()
  - 简单 LLM 调用，生成任务标题
  - 写库：tasks 表，status=CREATED
    │
    ▼
[框架层] GenerateSubtasks()
  - 启动 Generator Agent
  - 输入：用户原始请求
  - 输出：SubtaskList 工具调用
  - 写库：subtasks 表，例如：
      Subtask 1: "信息收集与端口扫描"     status=CREATED
      Subtask 2: "Web 服务漏洞探测"       status=CREATED
      Subtask 3: "凭证攻击与权限提升"     status=CREATED
      Subtask 4: "后渗透与持久化"         status=CREATED
      Subtask 5: "生成渗透测试报告"       status=CREATED
    │
    ▼
┌─── [框架层] 循环处理每个 Subtask ─────────────────────────────────┐
│                                                                     │
│  取下一个 status=CREATED 的 Subtask（例如 Subtask 1）              │
│    │                                                                │
│    ▼                                                                │
│  PrepareAgentChain()                                                │
│    - 创建 Primary Agent 的消息链                                    │
│    - 系统提示 = primary_agent.tmpl                                  │
│    - 用户消息 = Subtask 描述 + 执行上下文（已完成/待完成列表）      │
│    - 写库：msgchains 表（type=PRIMARY_AGENT）                       │
│    │                                                                │
│    ▼                                                                │
│  PerformAgentChain()  [Primary Agent 执行循环，最多 100 轮]         │
│    │                                                                │
│    ├─ LLM 调用 → 输出：调用 memorist（"有无类似目标的历史？"）     │
│    │     │                                                          │
│    │     ▼                                                          │
│    │   [Memorist Agent]                                             │
│    │     - 查 Graphiti + 向量库                                     │
│    │     - 返回：无历史记录                                         │
│    │     - 写库：vecstorelogs                                       │
│    │                                                                │
│    ├─ LLM 调用 → 输出：调用 searcher（"查找目标 OSINT 信息"）      │
│    │     │                                                          │
│    │     ▼                                                          │
│    │   [Searcher Agent]                                             │
│    │     - 调用 DuckDuckGo/Shodan 等                                │
│    │     - 返回：搜索结果摘要                                       │
│    │     - 写库：searchlogs                                         │
│    │                                                                │
│    ├─ LLM 调用 → 输出：调用 pentester（"执行端口扫描"）            │
│    │     │                                                          │
│    │     ▼                                                          │
│    │   [Pentester Agent 执行循环]                                   │
│    │     - 先查 Graphiti memory                                     │
│    │     - terminal: nmap -sV -sC 192.168.1.1                      │
│    │     - 输出：80/tcp open http nginx 1.14.2                      │
│    │     - terminal: gobuster dir -u http://192.168.1.1 ...         │
│    │     - 输出：/admin (200), /backup (403)                        │
│    │     - terminal: nikto -h http://192.168.1.1                    │
│    │     - 输出：X-Frame-Options header not set                     │
│    │     - 调用 done，返回汇总给 Primary Agent                      │
│    │     - 写库：termlogs, vecstorelogs                             │
│    │                                                                │
│    ├─ LLM 调用 → 输出：调用 pentester（"针对 /admin 进行登录测试"）│
│    │     │                                                          │
│    │     ▼                                                          │
│    │   [Pentester Agent 第二次]                                     │
│    │     - terminal: hydra -l admin -P rockyou.txt http://...       │
│    │     - 输出：[80][http-get] login: admin password: admin123     │
│    │     - 调用 done 返回                                           │
│    │                                                                │
│    └─ LLM 调用 → 输出：调用 done（"Subtask 完成，发现 admin 弱密码"）
│    │                                                                │
│    ▼                                                                │
│  UpdateSubtaskResult()                                              │
│    - 写库：subtasks.result = "发现 /admin 弱密码 admin:admin123"   │
│    - 写库：subtasks.status = FINISHED                               │
│    │                                                                │
│    ▼                                                                │
│  RefineSubtasks()  [Refiner Agent]                                  │
│    - 输入：已完成 Subtask 1 的结果 + 剩余计划                       │
│    - 分析：发现了 admin 弱密码，下一步应该用这个密码               │
│    - 输出：SubtaskPatch 操作：                                      │
│        modify Subtask 3 描述 → 加入"使用 admin:admin123 登录"      │
│        add Subtask 3.5 → "枚举 admin 面板功能，寻找文件上传点"     │
│    - 写库：subtasks 表更新                                          │
│                                                                     │
│  （继续处理 Subtask 2, 3, 3.5, 4, 5...）                           │
└─────────────────────────────────────────────────────────────────────┘
    │
    ▼
[框架层] GetTaskResult()  [Reporter Agent]
  - 输入：所有完成的 Subtask 标题 + 结果
  - 独立评估：用户目标"测试安全性"是否被满足？
  - 输出：TaskResult{Success=true, Result="..."}
  - 写库：tasks.result, tasks.status=FINISHED
    │
    ▼
用户看到最终报告
```

---

## 四、有没有验证？验证修正了侦查吗？

### 4.1 有验证，但不是独立验证步骤

PentAGI **没有专门的"验证 Agent"**。验证是内嵌在 Pentester Agent 的行为里的：

| 机制 | 谁做 | 怎么做 |
|------|------|--------|
| 侦查 | Pentester | nmap/gobuster 等工具发现目标信息 |
| 验证（初步） | Pentester（同一个） | 对发现的漏洞立刻尝试利用（hydra 试密码、sqlmap 注入等） |
| 计划修正 | Refiner | 根据 Pentester 的结果修改剩余子任务 |
| 最终评估 | Reporter | 评估任务是否整体成功，但不执行新命令 |

### 4.2 Refiner 是"软性验证"

Refiner 是最接近"验证修正侦查"的机制：

```
Pentester Subtask 1 执行结果：
  "目标 SSH 端口 22 开放，但无法爆破（fail2ban 限制）"
  
Refiner 修正计划：
  - remove Subtask 3（SSH 权限提升）← 因为 SSH 无法突破
  - modify Subtask 2（改为针对 Web 服务）
  - add Subtask 2.5（枚举 Web 应用凭证）
```

这是**计划层的验证**，不是**事实层的验证**——Refiner 不会回头质疑 Pentester 的发现是否正确，它直接接受结果并据此调整计划。

### 4.3 没有的东西

| 机制 | 是否存在 | 说明 |
|------|---------|------|
| 专门的 Verifier Agent | ❌ | 不存在 |
| 对 Fact 的独立二次确认 | ❌ | 发现即信任 |
| 验证结果修正已记录的 Fact | ❌ | Fact 一旦记录不会被撤销 |
| 对 false positive 的处理 | ❌ | Reporter 只评估成功率，不回溯错误 |

---

## 五、与你的 detect 项目对比

| 维度 | PentAGI | detect (当前) |
|------|---------|--------------|
| 侦查手段 | Pentester 用 nmap/gobuster 等主动工具 | think/act 用 SSH show 命令（只读） |
| 攻击手段 | Pentester 用 hydra/sqlmap/Metasploit | **尚无** |
| 计划层 | Generator 初始化，Refiner 动态修正 | 固定知识库顺序（_RECON_CHECKLIST） |
| 验证机制 | Refiner 修正计划 + Pentester 实际利用 | **尚无** |
| 记忆层 | Graphiti + pgvector 双层 | **尚无**（每次全新） |
| 结果结构 | subtask 层级，每层有 title+result | Fact + AttackChain（更精细） |
| 修正侦查信息 | Refiner 修正计划，不修正 Fact | AttackChain.confidence 可升降（设计上有，实现待完善） |

### detect 项目可借鉴的最高价值设计

1. **Refiner 模式**：你的 `next_probes` 已经有类似的方向，但 Refiner 更强——它可以**增删改**整个计划。你可以在 analyze 节点里让 LLM 输出对 `_RECON_CHECKLIST` 的动态修正，而不是死板地按顺序跑。

2. **Pentester 的"先查记忆再行动"协议**：每次行动前先搜索历史，避免重复踩坑。这是你加记忆层后最重要的使用原则。

3. **Generator 的结构**：当你要加攻击手时，攻击计划不应该是硬编码的，而应该由 LLM 根据侦查结果动态生成（类似 Generator）。你的 AttackChain.verification_needed 已经是这个思路的雏形。

4. **Primary Agent 的角色**：你现在 think 节点既做侦查判断又做攻击决策。PentAGI 的设计是把侦查手（Searcher）和攻击手（Pentester）分开，由协调者（Primary Agent）按需调用。这个分离在你加攻击工具后会很重要。
