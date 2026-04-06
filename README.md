# Switch Audit Agent

基于 LangGraph 的 Cisco IOS XE 交换机安全审计 Agent。通过链式漏洞分析，自动发现需要多个配置缺陷组合才能构成的攻击路径。

## 工作原理

```
think → act → analyze → think → ...
```

- **think**：根据已知事实和攻击链假设，从命令知识库中选择下一条最有价值的探测命令
- **act**：通过 SSH 在目标设备上执行命令
- **analyze**：从输出中提取安全事实，推断/更新攻击链，生成下一轮优先探测方向

## 快速开始

### 环境要求

- Python 3.13+
- [uv](https://docs.astral.sh/uv/)

### 安装

```bash
git clone <repo>
cd detection
uv sync
```

### 配置

```bash
cp .env.example .env
```

编辑 `.env`，至少填写：

```env
OPENAI_API_KEY=your-key-here
OPENAI_BASE_URL=          # 使用第三方或本地兼容接口时填写，否则留空
DEFAULT_LLM_MODEL=gpt-4o

SSH_USERNAME=admin
SSH_PASSWORD=admin
SSH_PORT=22
```

### 运行

```bash
# 审计指定设备
uv run python -m switch_audit.main --target devnetsandboxiosxec9k.cisco.com

# 指定 session ID（用于恢复或复现）
uv run python -m switch_audit.main --target devnetsandboxiosxec9k.cisco.com --session-id my-session
```

## 配置项说明

| 变量 | 默认值 | 说明 |
|------|--------|------|
| `OPENAI_API_KEY` | — | LLM API 密钥 |
| `OPENAI_BASE_URL` | 空（OpenAI 官方） | 自定义兼容端点 |
| `DEFAULT_LLM_MODEL` | `gpt-4o-mini` | 模型名称 |
| `DEFAULT_LLM_TEMPERATURE` | `0.1` | 温度，建议保持低值 |
| `SSH_PORT` | `22` | 目标设备 SSH 端口 |
| `SSH_USERNAME` | `admin` | 登录用户名 |
| `SSH_PASSWORD` | `admin` | 登录密码 |
| `SSH_TIMEOUT` | `10` | SSH 超时秒数 |
| `SSH_DEVICE_TYPE` | `cisco_xe` | netmiko 设备类型 |
| `LANGCHAIN_TRACING_V2` | `false` | 开启 LangSmith 追踪 |
| `LOG_FORMAT` | `console` | `console`（开发）/ `json`（生产） |

## 命令知识库

审计命令的唯一来源是 [`switch_audit/knowledge/ios_xe_commands.yaml`](switch_audit/knowledge/ios_xe_commands.yaml)，覆盖 11 个类别、61 条只读命令：

- 设备身份与全局配置
- 二层网络 / VLAN / STP
- 接口状态与计数
- 访问控制与认证（SSH、VTY、AAA）
- 端口安全（port-security、dot1x）
- 管理协议（CDP、LLDP、HTTP、SNMP）
- 时间同步（NTP）
- ACL 与路由
- DHCP Snooping / ARP Inspection
- 加密与证书
- 日志与审计

新增命令直接编辑 YAML 文件，两个 Agent 节点（think / analyze）会自动获取更新。

## 项目结构

```
switch_audit/
├── main.py                     # 入口，CLI 参数解析
├── knowledge/
│   └── ios_xe_commands.yaml    # 命令知识库（SSOT）
├── prompts/
│   ├── __init__.py             # 加载 YAML 并注入两个 prompt
│   ├── system.md               # think 节点 system prompt
│   └── analyze.md              # analyze 节点 system prompt
├── core/
│   └── langgraph/
│       ├── graph.py            # LangGraph 图定义
│       ├── state.py            # AuditState 类型定义
│       └── nodes/
│           └── __init__.py     # think / act / analyze 节点实现
└── tools/
    └── __init__.py             # ssh_exec（netmiko 封装）
```

## 可选：LangSmith 追踪

开启后可在 [smith.langchain.com](https://smith.langchain.com) 查看每轮推理的完整链路：

```env
LANGCHAIN_TRACING_V2=true
LANGCHAIN_API_KEY=your-langsmith-key
LANGCHAIN_PROJECT=switch-audit
```
