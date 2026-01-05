# 基于 ABAC 的多智能体安全网关

这是一个硕士论文 MVP 系统，实现了 **Task-MCP Token 凭证机制** 和 **全链路安全网关**。

## 核心特性

1. **Task-MCP Token 机制**：实现 User身份 与 Agent意图 的绑定验证
2. **安全网关 (PEP)**：拦截、验签、绑定校验、ABAC 策略执行
3. **Agent 注册中心**：管理 Agent 公钥和元数据
4. **ABAC 策略引擎**：基于 PyCasbin 的访问控制

## 项目结构

```
project_root/
├── config/
│   ├── abac_model.conf         # Casbin 模型配置
│   └── policy.csv              # ABAC 策略文件
├── core/
│   ├── crypto.py               # 签名/验签工具 (KeyPair, Sign, Verify)
│   └── token_manager.py        # Task-MCP Token 生成和解析
├── services/
│   ├── registry.py             # Agent 注册中心
│   ├── mcp_tool_server.py      # 模拟 MCP 服务器 (JSON-RPC)
│   └── gateway.py              # 安全网关 (PEP)
├── agents/
│   ├── base_agent.py           # Agent 基类
│   └── finance_agent.py        # 财务 Agent
├── workflow_simulation.py      # 工作流模拟（合规和攻击场景）
└── requirements.txt
```

## Token 规范

### 1. User Identity Token (JWT)

用于标识用户的静态身份。

```json
{
  "uid": "User_C",
  "role": "Director",
  "dept": "Finance",
  "exp": 1712349278
}
```

### 2. Task-MCP Token (核心创新)

由 Agent 使用私钥签发，用于证明 "Agent 代表 User 调用了 Tool"。

**Payload 结构**:
```json
{
  "iss": "did:agent:fin_analyst",  # Agent DID
  "sub": "User_C",                 # 绑定的用户 ID (关键！身份绑定)
  "target_tool": "urn:mcp:audit",  # 调用的目标工具
  "nonce": "r8s9d7",               # 防重放随机数
  "timestamp": 1712345678          # 时间戳
}
```

**传输格式**: Header 中分别传递 `X-Task-Token-Payload` 和 `X-Task-Token-Signature`

## 安装依赖

### 1. 创建虚拟环境（推荐）

**Windows:**
```bash
python -m venv venv
.\venv\Scripts\Activate.ps1
```

**Linux/Mac:**
```bash
python -m venv venv
source venv/bin/activate
```

### 2. 安装依赖包

```bash
pip install -r requirements.txt
```

**注意**: 项目使用 Python 3.10+，已测试兼容 Python 3.13。

## 运行系统

**重要**: 运行服务前，必须先激活虚拟环境！

**Windows PowerShell:**
```powershell
# 激活虚拟环境
.\venv\Scripts\Activate.ps1

# 终端1: 启动 MCP Tool Server
python -m services.mcp_tool_server
# 服务运行在 http://localhost:8001

# 终端2: 启动安全网关
python -m services.gateway
# 服务运行在 http://localhost:8000
```

**Windows CMD:**
```cmd
venv\Scripts\activate.bat
python -m services.mcp_tool_server
```

**Linux/Mac:**
```bash
source venv/bin/activate
python -m services.mcp_tool_server
```

### 3. 运行真实系统测试

**启动网关服务**（在终端1）：
```bash
python -m services.gateway
```

**运行客户端测试**（在终端2）：
```bash
python client_test.py
```

这将执行真实的系统测试，验证网关的身份鉴别和权限控制功能：
- ✅ 测试1：合规请求 - 用户正确调用 Agent（应该通过）
- 🛡️ 测试2：身份绑定不匹配攻击（应该被拦截）
- 🛡️ 测试3：未授权工具访问（应该被拦截）
- 🛡️ 测试4：Token 篡改攻击（应该被拦截）

**注意**：`client_test.py` 使用网关的 `/gateway/test/` 端点，只进行验证不转发到 MCP，专门用于测试身份鉴别和权限控制功能。

## 安全网关工作流程

网关实现了以下 5 个步骤的验证流程：

1. **拦截 (Intercept)**: 获取 Header 中的 `X-User-Token` 和 `X-Task-Token-*`
2. **验签 (Verify Signature)**: 从注册中心获取 Agent 公钥，验证 Task-Token 签名
3. **绑定校验 (Binding Check)**: **关键逻辑** - 检查 `X-User-Token.uid` 是否等于 `X-Task-Token.sub`
4. **ABAC 策略判定**: 使用 Casbin 引擎评估访问策略
5. **转发 (Forward)**: 通过后转发 JSON-RPC 请求到 MCP Tool Server

## 示例：合规请求

```python
# 1. 用户登录，获得 user_jwt
user_jwt = create_user_jwt("User_C", "Director", "Finance")

# 2. Agent 创建 Task-MCP Token
finance_agent = FinanceAgent()
token_data = finance_agent.create_task_token_for_user("User_C", "urn:mcp:audit")

# 3. 发送请求到网关
headers = {
    "X-User-Token": user_jwt,
    "X-Task-Token-Payload": token_data["payload"],
    "X-Task-Token-Signature": token_data["signature"]
}
# 请求将被转发到 MCP Tool Server
```

## 安全防护

系统防护以下攻击场景：

1. **Token 篡改攻击**: 修改 Token payload 后，签名验证失败，请求被拦截
2. **身份伪造攻击**: User Token 中的 uid 与 Task Token 中的 sub 不一致时，绑定校验失败
3. **未授权工具访问**: ABAC 策略检查确保 Agent 只能访问被授权的工具

## 技术栈

- **Python 3.10+**
- **FastAPI**: Web 框架
- **PyCasbin**: ABAC 策略引擎
- **Cryptography**: ECC 签名/验签（模拟 SM2）
- **Httpx**: 异步 HTTP 客户端
- **PyJWT**: JWT Token 处理

## 许可证

本项目为硕士论文研究用途。

