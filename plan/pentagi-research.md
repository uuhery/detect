# PentAGI 技术方案调研

> 调研时间：2026-04-07  
> 源码路径：~/Projects/PentAGI

---

## 一、整体架构

PentAGI 是一个**多智能体自动化渗透测试系统**，采用 Go 后端（REST + GraphQL）+ React TypeScript 前端的 monolith 架构。

### 技术栈

| 层次 | 技术 |
|------|------|
| 后端语言 | Go 1.24.1 + Gin Web Framework |
| 前端 | React + TypeScript + Apollo GraphQL Client |
| 主数据库 | PostgreSQL（pgvector 扩展） |
| 知识图谱 | Neo4j（通过 Graphiti 访问） |
| 容器运行时 | Docker SDK |
| LLM 框架 | langchaingo（vxcontrol fork） |
| 可观测性 | OpenTelemetry + Langfuse + Grafana/Prometheus/Jaeger/Loki |
| GraphQL | gqlgen（代码生成） |
| DB 查询 | SQLC（类型安全生成） |
| 迁移工具 | Goose |
| 前端状态 | Zustand |
| 前端组件 | @radix-ui |

### 组件拓扑

```
User HTTP/GraphQL
        ↓
  Gin Router (server/router.go)
        ↓
  Flow Controller / Assistant Controller
        ↓
  Provider Layer (LLM providers)
        ↓
  Performer (Agent执行引擎)
        ↓
  Tool Executor (工具执行)
        ↓
  Docker Containers (沙箱执行环境)
        +
  PostgreSQL (主存储 + 向量存储)
  Neo4j / Graphiti (知识图谱)
```

### 主入口

`backend/cmd/pentagi/main.go`：初始化配置、数据库、Docker 客户端、LLM 提供者、订阅控制器、Flow 控制器，启动 HTTP(S) 服务器。

---

## 二、Agent 设计

### Agent 类型（15种）

| 名称 | 职责 |
|------|------|
| Primary Agent | 顶层编排，分解和调度子任务 |
| Assistant | 交互式用户对话 |
| Pentester | 安全测试与漏洞扫描 |
| Coder | 利用代码开发 |
| Installer | 环境安装配置 |
| Searcher | 网络情报收集 |
| Memorist | 从记忆库检索知识 |
| Adviser | 安全策略建议 |
| Generator | 子任务拆解规划 |
| Refiner | 任务计划优化 |
| Reporter | 报告生成 |
| Reflector | 错误分析与恢复 |
| Enricher | 上下文信息丰富 |
| Tool Call Fixer | 修复格式错误的工具调用 |
| Summarizer | 上下文压缩 |

关键文件：`backend/pkg/providers/provider/agents.go`，`backend/pkg/database/models.go`

### 执行模型（performer.go）

- Agent 以顺序或委派链方式执行
- 每个 Agent 对应一个 `ExecutorHandler` 函数
- 工具调用上限：通用 Agent 100次，受限 Agent 20次
- 接近上限前 3 轮触发 Reflector 进行优雅终止
- 通过 `done`/`ask` 工具发出终止信号

### 监督机制（Beta）

**Execution Monitor**（`EXECUTION_MONITOR_ENABLED`）：
- 监控连续相同工具调用（阈值：5次）
- 进度停滞检测，防止死循环
- 触发 mentor agent 介入

**Task Planning**（`AGENT_PLANNING_STEP_ENABLED`）：
- 执行前先通过 Enricher + Generator 自动分解为 3-7 步
- 结构化任务分配给专项 Agent

### Agent 协调流程

```
Primary Agent
    ├─→ Generator (拆解子任务)
    ├─→ Refiner (优化计划)
    └─→ SubTask 循环:
            ├─→ Searcher (情报)
            ├─→ Memorist (记忆检索)
            ├─→ Adviser (策略)
            ├─→ Pentester (执行渗透)
            ├─→ Coder (开发工具)
            └─→ Reporter (生成报告)
```

---

## 三、数据设计

### 数据库结构（PostgreSQL）

```
flows          顶层渗透测试工作流
  └─ tasks     具体测试目标
       └─ subtasks   细粒度任务单元
            └─ msglogs    消息历史（含thinking和结果）
            └─ toolcalls  工具调用记录
            └─ agentlogs  Agent行为日志
            └─ termlogs   终端命令执行记录
            └─ vecstorelogs  向量存储操作记录

msgchains      LLM对话链（按Agent类型分别维护）
searchlogs     搜索引擎查询/结果
screenshots    浏览器截图
assistants     交互式助手会话
containers     Docker容器元数据
providers      LLM提供者配置
api_tokens     Bearer Token认证
users          用户账号与角色
user_preferences  用户设置
```

### 实体关系

```
Flow → Task → SubTask → Action → Artifact
                 |
                 +→ Memory（向量嵌入）
```

### 数据访问

- SQLC 生成类型安全查询（`*.sql.go`）
- Goose 管理迁移脚本（`migrations/sql/`）
- 连接池：最大20，空闲5，超时1小时

---

## 四、记忆设计

文件：`backend/pkg/tools/memory.go`

### 三层记忆架构

**长期记忆（Long-Term Memory）**：
- 存储：PostgreSQL pgvector 向量数据库
- 内容：领域专业知识、工具使用模式
- 检索：语义相似度搜索（相似度阈值 0.2，最多返回3条）

**工作记忆（Working Memory）**：
- 当前上下文、活跃目标
- 可用资源和容器状态

**情节记忆（Episodic Memory）**：
- 历史命令执行记录
- 成功/失败结果
- 有效攻击模式

### 记忆操作工具

| 工具名 | 操作 |
|--------|------|
| `SearchInMemory` | 自然语言查询（支持1-5个并行查询） |
| `StoreGuide` | 持久化安全指南 |
| `StoreAnswer` | 存储问答对 |
| `StoreCode` | 归档代码片段 |

### 检索策略

1. 支持 task/subtask 范围过滤
2. 无结果时自动回退到全局过滤
3. 敏感数据自动匿名化（IP、域名、凭证）
4. 去重并按相关性打分排序

---

## 五、知识设计

### 双层知识体系

**第一层：向量嵌入（Vector Store）**
- 提供者：可配置（默认 OpenAI）
- 批大小：512（可配置）
- 存储于 PostgreSQL pgvector
- 文件：`backend/pkg/providers/embeddings/`

**第二层：知识图谱（Graphiti + Neo4j）**
- 文件：`backend/pkg/graphiti/client.go`
- 启用条件：`GRAPHITI_ENABLED=true`

知识图谱搜索类型：

| 搜索类型 | 用途 |
|---------|------|
| TemporalWindowSearch | 时间窗口查询 |
| EntityRelationshipsSearch | 实体关系查询 |
| DiverseResultsSearch | 非冗余多样结果 |
| EpisodeContextSearch | Agent响应/工具执行上下文 |
| SuccessfulToolsSearch | 成功攻击模式 |
| RecentContextSearch | 最近相关信息 |
| EntityByLabelSearch | 按类型查找实体 |

### 提示模板知识

- 位置：`backend/pkg/templates/prompts/*.tmpl`
- 40+ 专用提示模板
- 动态变量注入，按 Agent 类型定制

### 知识集成流程

```
Agent 查询
    → 向量存储语义搜索
    → 知识图谱关系查询
    → 提示模板上下文注入
    → LLM 调用
```

---

## 六、工具设计

文件：`backend/pkg/tools/tools.go`，`backend/pkg/tools/registry.go`

### 工具分类（8类）

| 类别 | 工具示例 |
|------|---------|
| 环境操作 | terminal, file |
| 网络搜索 | Google, DuckDuckGo, Tavily, Traversaal, Perplexity, SearXNG, Sploitus, Browser |
| 向量库搜索 | memory search, guide search, answer search, code search |
| Agent委派 | pentester, coder, installer, maintenance, memorist, advice, search |
| 结果存储 | store task result, store code, store hack result |
| 向量库存储 | store guide, store answer, store code |
| 终止信号 | done, ask |
| 自定义 | 外部 HTTP 端点 |

总计 40+ 内置工具。

### 工具注册机制

- `GetToolType(name)` 映射工具名到类型
- JSON Schema 自动反射生成工具描述
- 支持通过 URL 配置外部自定义工具

### 工具执行器（FlowToolsExecutor）

每种 Agent 类型对应专属执行器：

```go
GetAssistantExecutor  // 用户交互
GetPrimaryExecutor    // Flow 编排
GetPentesterExecutor  // 安全测试
GetCoderExecutor      // 代码开发
GetSearcherExecutor   // 情报收集
GetMemoristExecutor   // 记忆检索
GetGeneratorExecutor  // 任务规划
GetReporterExecutor   // 报告生成
```

### 关键工具实现

**Terminal Tool**（`backend/pkg/tools/terminal.go`）：
- 阻塞式执行，硬限制 1200s
- 建议超时 60s
- 单次单命令，完整输出捕获 + 流式传输

**搜索工具差异化**：

| 工具 | 适用场景 |
|------|---------|
| Tavily/Traversaal | 复杂详细查询 |
| Perplexity | LLM 增强研究 |
| SearXNG | 隐私优先元搜索 |
| Sploitus | Exploit 数据库聚合 |
| Google/DuckDuckGo | 快速公开链接 |

---

## 七、LLM 集成

文件：`backend/pkg/providers/provider/provider.go`

### 支持的 Provider（10种）

| Provider | 说明 |
|---------|------|
| OpenAI | GPT 系列 |
| Anthropic | Claude Haiku/Sonnet/Opus |
| Google Gemini | Vertex AI |
| AWS Bedrock | 多模型家族 |
| Ollama | 本地/远程推理 |
| DeepSeek | 深度推理模型 |
| GLM (Zhipu) | 中文模型 |
| Kimi (Moonshot) | 中文模型 |
| Qwen (Alibaba) | 中文模型 |
| Custom | 自托管/OpenAI 兼容 |

### 核心接口

```go
Call(ctx, opt, prompt) (string, error)
CallEx(ctx, opt, chain []MessageContent, streamCb) (*ContentResponse, error)
CallWithTools(ctx, opt, chain, tools, streamCb) (*ContentResponse, error)
```

### 推理支持

- Extended Thinking（扩展思考）模式
- 可按 Agent 类型配置 token 预算
- Reasoning 内容保留在对话链中

### 工具调用 ID 检测

- 自动识别各 Provider 的工具调用格式
- 5次并行采样 + AI 推断 + 规则回退
- 结果按 Provider 类型缓存

### 对话链压缩（csum）

文件：`backend/pkg/csum/`

- 防止超出 token 上限
- 分段摘要策略
- 问答对摘要
- 保留最后 50KB（可配置）
- 12个 `SUMMARIZER_*` 环境变量控制

---

## 八、工作流与编排

文件：`backend/pkg/controller/flow.go`，`backend/pkg/providers/performer.go`

### 主执行流程

```
用户输入
    ↓
创建 Flow（DB记录）
    ↓
初始化 Primary Agent 对话链
    ↓
准备消息链（系统提示 + 上下文）
    ↓
Agent 执行循环:
  ├─ LLM 调用（含工具）
  ├─ 工具执行（并行或顺序）
  ├─ 结果集成到对话链
  ├─ 对话链压缩（必要时）
  └─ 终止检测（done/ask）
    ↓
任务完成 → Reporter 生成报告
    ↓
Flow 标记完成
```

### 子任务管理

```go
GenerateSubtasks(taskID)  // Generator Agent 拆解
RefineSubtasks(taskID)    // Refiner Agent 优化
GetTaskResult(taskID)     // Reporter Agent 输出
```

### 渗透测试完整示例

1. 用户输入目标（如"对目标应用进行SQL注入测试"）
2. 创建 Flow，Primary Agent 分析任务
3. Generator 制定计划（侦察→扫描→利用）
4. Searcher 收集情报（搜索工具、浏览器）
5. Memorist 检索历史类似攻击
6. Adviser 推荐策略
7. Pentester 执行扫描（nmap, sqlmap等）
8. Coder 开发定制 exploit（如需要）
9. 结果写入向量存储 + 知识图谱
10. Reporter 生成漏洞报告

---

## 九、关键文件索引

| 文件 | 职责 |
|------|------|
| `backend/cmd/pentagi/main.go` | 服务启动入口 |
| `backend/pkg/config/config.go` | 配置解析 |
| `backend/pkg/server/router.go` | Gin 路由 |
| `backend/pkg/controller/flow.go` | Flow 编排控制器 |
| `backend/pkg/controller/assistant.go` | 助手会话控制器 |
| `backend/pkg/providers/performer.go` | Agent 执行引擎 |
| `backend/pkg/providers/provider/provider.go` | LLM Provider 接口 |
| `backend/pkg/providers/provider/agents.go` | Agent类型 + 工具调用检测 |
| `backend/pkg/tools/tools.go` | 工具定义 |
| `backend/pkg/tools/registry.go` | 工具注册表 |
| `backend/pkg/tools/memory.go` | 记忆工具实现 |
| `backend/pkg/tools/terminal.go` | 终端工具 |
| `backend/pkg/tools/executor.go` | 工具执行器 |
| `backend/pkg/database/models.go` | SQLC 生成数据模型 |
| `backend/pkg/graphiti/client.go` | 知识图谱客户端 |
| `backend/pkg/templates/templates.go` | 提示模板系统 |
| `backend/pkg/csum/` | 对话链压缩 |

---

## 十、可借鉴要点

针对 detect 项目的参考价值：

1. **多 Agent 分工**：将侦察、执行、记忆、报告分离为专职 Agent，职责单一
2. **三层记忆架构**：长期（向量）+ 工作（上下文）+ 情节（历史），按需检索
3. **对话链压缩**：防止长对话超出 token 限制，保留最近关键段落
4. **工具调用监控**：检测重复调用和死循环，触发 Reflector/Mentor 介入
5. **Provider 抽象**：统一接口屏蔽多 LLM 差异，支持 10 种提供者
6. **沙箱执行**：工具命令在 Docker 容器内运行，隔离风险
7. **知识图谱**：用 Graphiti + Neo4j 记录攻击路径和实体关系，超越纯向量检索
8. **规划 → 执行分离**：Generator/Refiner 先规划，Pentester/Coder 后执行
