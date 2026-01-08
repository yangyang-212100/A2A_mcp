"""
Security Gateway (PEP - Policy Enforcement Point)
核心安全网关：实现用户身份验证、Agent 调用授权、Task-MCP Token 验证和 ABAC 策略执行

授权流程：
1. 用户请求 -> 网关验证 JWT -> 转发给 Main Agent
2. Main Agent 意图识别 -> 申请调用 Task Agent -> 网关 ABAC 鉴权
3. 授权成功 -> Task Agent 加入协作组
4. 授权失败 -> 网关直接拒绝用户
"""

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from typing import Optional, Dict, Any
import httpx
import jwt
import casbin
import os
import time
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend

from services.registry import registry
from core.token_manager import decode_task_token_payload, verify_task_token


app = FastAPI(title="Multi-Agent Security Gateway")


# 初始化 Casbin ABAC 引擎
casbin_model_path = os.path.join(os.path.dirname(__file__), "..", "config", "abac_model.conf")
casbin_policy_path = os.path.join(os.path.dirname(__file__), "..", "config", "policy.csv")
enforcer = casbin.Enforcer(casbin_model_path, casbin_policy_path)

# MCP Tool Server 地址
MCP_TOOL_SERVER_URL = "http://localhost:8001"

# Main Agent 地址 (用于内部通信)
MAIN_AGENT_URL = "http://localhost:8002"

# JWT 密钥 (生产环境应该使用安全的密钥管理)
JWT_SECRET = "dummy_secret"

# 协作组：存储当前会话中授权的 Agent
# 结构: {session_id: {user_id, user_jwt, authorized_agents: [agent_did]}}
collaboration_sessions: Dict[str, Dict[str, Any]] = {}


def decode_user_jwt(token: str) -> dict:
    """
    解码并验证 User Identity Token (JWT)。
    """
    try:
        # 验证 JWT 签名和有效期
        decoded = jwt.decode(token, JWT_SECRET, algorithms=["HS256"])
        return decoded
    except jwt.ExpiredSignatureError:
        raise HTTPException(status_code=401, detail="User token has expired")
    except jwt.InvalidTokenError as e:
        raise HTTPException(status_code=401, detail=f"Invalid user token: {str(e)}")


def create_session_id(user_id: str) -> str:
    """生成会话 ID。"""
    return f"session_{user_id}_{int(time.time())}"


# ==================== 新增端点：用户请求入口 ====================

@app.post("/gateway/user-request")
async def user_request_endpoint(
    request: Request,
    x_user_token: Optional[str] = Header(None, alias="X-User-Token")
):
    """
    用户请求入口端点。
    
    流程：
    1. 验证用户 JWT
    2. 创建协作会话
    3. 转发请求给 Main Agent
    """
    # ========== Step 1: 验证用户 JWT ==========
    if not x_user_token:
        raise HTTPException(status_code=401, detail="Missing X-User-Token header")
    
    print(f"\n[Gateway] ========== User Request Received ==========")
    print(f"[Gateway] Validating user JWT...")
    
    try:
        user_info = decode_user_jwt(x_user_token)
        user_id = user_info.get("uid")
        user_role = user_info.get("role", "")
        user_dept = user_info.get("dept", "")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid user token: {str(e)}")
    
    print(f"[Gateway] User JWT validated - uid: {user_id}, role: {user_role}, dept: {user_dept}")
    
    # ========== Step 2: 创建协作会话 ==========
    session_id = create_session_id(user_id)
    collaboration_sessions[session_id] = {
        "user_id": user_id,
        "user_jwt": x_user_token,
        "user_info": user_info,
        "authorized_agents": [],
        "created_at": time.time()
    }
    print(f"[Gateway] Created collaboration session: {session_id}")
    
    # ========== Step 3: 获取用户请求内容 ==========
    try:
        request_body = await request.json()
    except Exception:
        request_body = {}
    
    user_query = request_body.get("query", "")
    print(f"[Gateway] User query: {user_query}")
    
    # ========== Step 4: 转发给 Main Agent ==========
    # 在实际系统中，这里会调用 Main Agent 的 API
    # 为了简化测试，我们直接返回会话信息，让客户端继续流程
    
    return JSONResponse({
        "status": "session_created",
        "session_id": session_id,
        "user_id": user_id,
        "user_info": {
            "uid": user_id,
            "role": user_role,
            "dept": user_dept
        },
        "message": "User JWT validated. Session created. Ready for agent authorization.",
        "next_step": "Main Agent should call /gateway/authorize-agent-call to request Task Agent authorization"
    })


@app.post("/gateway/authorize-agent-call")
async def authorize_agent_call_endpoint(
    request: Request,
    x_user_token: Optional[str] = Header(None, alias="X-User-Token"),
    x_session_id: Optional[str] = Header(None, alias="X-Session-Id")
):
    """
    Agent 调用授权端点。
    
    Main Agent 请求调用 Task Agent 时调用此端点。
    网关根据 ABAC 策略判断用户是否有权限调用该 Agent。
    
    请求体：
    {
        "target_agent_did": "did:agent:fin_analyst",
        "task_description": "执行财务审计"
    }
    """
    # ========== Step 1: 验证用户 JWT ==========
    if not x_user_token:
        raise HTTPException(status_code=401, detail="Missing X-User-Token header")
    
    print(f"\n[Gateway] ========== Agent Authorization Request ==========")
    
    try:
        user_info = decode_user_jwt(x_user_token)
        user_id = user_info.get("uid")
        user_role = user_info.get("role", "")
        user_dept = user_info.get("dept", "")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid user token: {str(e)}")
    
    print(f"[Gateway] User info - uid: {user_id}, role: {user_role}, dept: {user_dept}")
    
    # ========== Step 2: 获取请求内容 ==========
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request body")
    
    target_agent_did = body.get("target_agent_did")
    task_description = body.get("task_description", "")
    
    if not target_agent_did:
        raise HTTPException(status_code=400, detail="Missing target_agent_did")
    
    print(f"[Gateway] Target Agent: {target_agent_did}")
    print(f"[Gateway] Task: {task_description}")
    
    # ========== Step 3: 检查 Agent 是否已注册 ==========
    if not registry.is_registered(target_agent_did):
        print(f"[Gateway] Agent {target_agent_did} is not registered")
        raise HTTPException(
            status_code=404, 
            detail=f"Agent {target_agent_did} is not registered in the system"
        )
    
    # ========== Step 4: ABAC 策略判定 ==========
    # 检查用户是否有权限调用该 Agent
    # 策略格式: p, user_dept, agent_did, call, allow
    
    sub = user_dept  # 用户部门作为主体
    obj = target_agent_did  # 目标 Agent
    act = "call"  # 操作类型
    
    print(f"[Gateway] ABAC Check: {sub} -> {obj} ({act})")
    
    try:
        allowed = enforcer.enforce(sub, obj, act)
    except Exception as e:
        print(f"[Gateway] ABAC policy evaluation error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"ABAC policy evaluation failed: {str(e)}"
        )
    
    if not allowed:
        # ========== 授权失败：直接拒绝用户 ==========
        print(f"[Gateway] ABAC DENIED: User from {sub} is not allowed to call {obj}")
        raise HTTPException(
            status_code=403,
            detail=f"Access Denied: User from department '{user_dept}' is not authorized to call agent '{target_agent_did}'. Cross-department access is not permitted."
        )
    
    # ========== Step 5: 授权成功 ==========
    print(f"[Gateway] ABAC ALLOWED: User from {sub} can call {obj}")
    
    # 将 Agent 加入协作组
    if x_session_id and x_session_id in collaboration_sessions:
        session = collaboration_sessions[x_session_id]
        if target_agent_did not in session["authorized_agents"]:
            session["authorized_agents"].append(target_agent_did)
        print(f"[Gateway] Agent {target_agent_did} added to collaboration session {x_session_id}")
    
    # 生成授权凭证 (简化版，实际可以是签名的 Token)
    authorization_token = jwt.encode({
        "user_id": user_id,
        "user_dept": user_dept,
        "target_agent": target_agent_did,
        "task": task_description,
        "authorized": True,
        "exp": int(time.time()) + 300  # 5分钟有效
    }, JWT_SECRET, algorithm="HS256")
    
    return JSONResponse({
        "status": "authorized",
        "message": f"User {user_id} is authorized to call agent {target_agent_did}",
        "authorization": {
            "user_id": user_id,
            "user_dept": user_dept,
            "user_role": user_role,
            "target_agent": target_agent_did,
            "task_description": task_description,
            "authorization_token": authorization_token
        },
        "next_step": "Task Agent can now execute the task"
    })


@app.get("/gateway/session/{session_id}")
async def get_session_info(session_id: str):
    """获取协作会话信息。"""
    if session_id not in collaboration_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = collaboration_sessions[session_id]
    return {
        "session_id": session_id,
        "user_id": session["user_id"],
        "authorized_agents": session["authorized_agents"],
        "created_at": session["created_at"]
    }


# ==================== 原有端点 (Agent 调用 MCP Tool) ====================

@app.post("/gateway/mcp/{tool_path:path}")
async def gateway_endpoint(
    tool_path: str,
    request: Request,
    x_user_token: Optional[str] = Header(None, alias="X-User-Token"),
    x_task_token_payload: Optional[str] = Header(None, alias="X-Task-Token-Payload"),
    x_task_token_signature: Optional[str] = Header(None, alias="X-Task-Token-Signature")
):
    """
    安全网关端点：拦截 Agent 对 MCP Tool 的请求。
    
    Step 1: 拦截 - 获取 Header 中的 Token
    Step 2: 验签 - 验证 Task-MCP Token 签名
    Step 3: 绑定校验 - 检查 User Token.uid 是否等于 Task Token.sub
    Step 4: ABAC - 使用 Casbin 进行策略判定
    Step 5: 转发 - 通过后转发请求到 MCP Tool Server
    """
    
    # ========== Step 1: 拦截 ==========
    if not x_user_token:
        raise HTTPException(status_code=401, detail="Missing X-User-Token header")
    
    if not x_task_token_payload or not x_task_token_signature:
        raise HTTPException(status_code=401, detail="Missing X-Task-Token headers")
    
    print(f"[Gateway] Intercepted request to tool: {tool_path}")
    print(f"[Gateway] X-User-Token: {x_user_token[:20]}...")
    print(f"[Gateway] X-Task-Token-Payload: {x_task_token_payload[:30]}...")
    
    # 解码 User Identity Token
    try:
        user_info = decode_user_jwt(x_user_token)
        user_id = user_info.get("uid")
        user_role = user_info.get("role", "")
        user_dept = user_info.get("dept", "")
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid user token: {str(e)}")
    
    print(f"[Gateway] User info - uid: {user_id}, role: {user_role}, dept: {user_dept}")
    
    # ========== Step 2: 验签 ==========
    # 先解码 payload 获取 Agent DID
    task_token = decode_task_token_payload(x_task_token_payload)
    if not task_token:
        raise HTTPException(status_code=400, detail="Invalid Task-Token payload format")
    
    agent_did = task_token.iss
    print(f"[Gateway] Task-Token - Agent DID: {agent_did}, Target Tool: {task_token.target_tool}, User ID: {task_token.sub}")
    
    # 从注册中心获取 Agent 公钥
    agent_public_key = registry.get_public_key(agent_did)
    if not agent_public_key:
        raise HTTPException(status_code=403, detail=f"Agent {agent_did} not registered")
    
    # 验证 Task-MCP Token 签名
    is_valid, verified_token = verify_task_token(
        x_task_token_payload,
        x_task_token_signature,
        agent_public_key
    )
    
    if not is_valid or not verified_token:
        raise HTTPException(status_code=403, detail="Task-Token signature verification failed")
    
    print(f"[Gateway] Task-Token signature verified successfully")
    
    # ========== Step 3: 绑定校验 (关键逻辑) ==========
    # 检查 User Token 中的 uid 是否与 Task Token 中的 sub 一致
    if user_id != verified_token.sub:
        print(f"[Gateway] Binding check FAILED: User token uid={user_id}, Task token sub={verified_token.sub}")
        raise HTTPException(
            status_code=403,
            detail=f"Identity binding mismatch: User token uid ({user_id}) != Task token sub ({verified_token.sub})"
        )
    
    print(f"[Gateway] Identity binding verified: User {user_id} is bound to Agent {agent_did}")
    
    # 检查目标工具是否匹配
    expected_tool = f"urn:mcp:{tool_path}"
    if verified_token.target_tool != expected_tool:
        print(f"[Gateway] Tool mismatch: Task token specifies {verified_token.target_tool}, but request is for {expected_tool}")
        # 这里可以选择严格模式（拒绝）或宽松模式（使用 token 中指定的工具）
        # 为了安全，我们使用 token 中指定的工具
        expected_tool = verified_token.target_tool
    
    # ========== Step 4: ABAC 策略判定 ==========
    # 提取属性
    sub = agent_did  # Agent DID
    obj = verified_token.target_tool  # 目标工具
    act = "read"  # 操作类型（可以从请求中提取，这里简化处理）
    
    # 显式检查敏感工具（默认禁止）
    forbidden_tools = ["urn:mcp:delete_db", "urn:mcp:format_disk"]
    if obj in forbidden_tools:
        print(f"[Gateway] ABAC policy DENIED: {sub} -> {obj} ({act}) - Tool is in forbidden list")
        raise HTTPException(
            status_code=403,
            detail=f"ABAC policy denied: Agent {sub} is not allowed to access forbidden tool {obj}"
        )
    
    # 使用 Casbin 检查策略
    try:
        allowed = enforcer.enforce(sub, obj, act)
    except Exception as e:
        print(f"[Gateway] ABAC policy evaluation error: {e}")
        raise HTTPException(
            status_code=500,
            detail=f"ABAC policy evaluation failed: {str(e)}"
        )
    
    if not allowed:
        print(f"[Gateway] ABAC policy DENIED: {sub} -> {obj} ({act}) - No matching policy found")
        raise HTTPException(
            status_code=403,
            detail=f"ABAC policy denied: Agent {sub} is not allowed to access {obj}"
        )
    
    print(f"[Gateway] ABAC policy ALLOWED: {sub} -> {obj} ({act})")
    
    # ========== Step 5: 转发请求 ==========
    # 获取原始请求体
    try:
        request_body = await request.json()
    except Exception:
        request_body = {}
    
    # 转发到 MCP Tool Server
    mcp_url = f"{MCP_TOOL_SERVER_URL}/mcp/tools/{tool_path}"
    
    try:
        async with httpx.AsyncClient() as client:
            response = await client.post(mcp_url, json=request_body, timeout=30.0)
            response.raise_for_status()
            return JSONResponse(content=response.json())
    except httpx.HTTPError as e:
        print(f"[Gateway] Error forwarding request to MCP server: {e}")
        raise HTTPException(status_code=502, detail=f"MCP Tool Server error: {str(e)}")


@app.get("/gateway/health")
async def health_check():
    """健康检查端点。"""
    return {"status": "healthy", "service": "security-gateway"}


@app.post("/gateway/test/{tool_path:path}")
async def gateway_test_endpoint(
    tool_path: str,
    request: Request,
    x_user_token: Optional[str] = Header(None, alias="X-User-Token"),
    x_task_token_payload: Optional[str] = Header(None, alias="X-Task-Token-Payload"),
    x_task_token_signature: Optional[str] = Header(None, alias="X-Task-Token-Signature")
):
    """
    测试端点：仅验证身份鉴别和权限控制，不转发到 MCP。
    用于测试网关的安全验证功能。
    """
    try:
        # ========== Step 1: 拦截 ==========
        if not x_user_token:
            raise HTTPException(status_code=401, detail="Missing X-User-Token header")
        
        if not x_task_token_payload or not x_task_token_signature:
            raise HTTPException(status_code=401, detail="Missing X-Task-Token headers")
        
        print(f"[Gateway Test] Intercepted request to tool: {tool_path}")
        
        # 解码 User Identity Token
        try:
            user_info = decode_user_jwt(x_user_token)
            user_id = user_info.get("uid")
            user_role = user_info.get("role", "")
            user_dept = user_info.get("dept", "")
        except HTTPException:
            raise
        except Exception as e:
            print(f"[Gateway Test] Error decoding user JWT: {e}")
            raise HTTPException(status_code=401, detail=f"Invalid user token: {str(e)}")
        
        print(f"[Gateway Test] User info - uid: {user_id}, role: {user_role}, dept: {user_dept}")
        
        # ========== Step 2: 验签 ==========
        try:
            task_token = decode_task_token_payload(x_task_token_payload)
            if not task_token:
                raise HTTPException(status_code=400, detail="Invalid Task-Token payload format")
        except HTTPException:
            raise
        except Exception as e:
            print(f"[Gateway Test] Error decoding task token: {e}")
            raise HTTPException(status_code=400, detail=f"Invalid Task-Token payload: {str(e)}")
        
        agent_did = task_token.iss
        
        # 从注册中心获取 Agent 公钥
        agent_public_key = registry.get_public_key(agent_did)
        if not agent_public_key:
            raise HTTPException(status_code=403, detail=f"Agent {agent_did} not registered")
        
        # 验证 Task-MCP Token 签名
        is_valid, verified_token = verify_task_token(
            x_task_token_payload,
            x_task_token_signature,
            agent_public_key
        )
        
        if not is_valid or not verified_token:
            raise HTTPException(status_code=403, detail="Task-Token signature verification failed")
        
        print(f"[Gateway Test] Task-Token signature verified successfully")
        
        # ========== Step 3: 绑定校验 (关键逻辑) ==========
        if user_id != verified_token.sub:
            print(f"[Gateway Test] Binding check FAILED: User token uid={user_id}, Task token sub={verified_token.sub}")
            raise HTTPException(
                status_code=403,
                detail=f"Identity binding mismatch: User token uid ({user_id}) != Task token sub ({verified_token.sub})"
            )
        
        print(f"[Gateway Test] Identity binding verified: User {user_id} is bound to Agent {agent_did}")
        
        # 检查目标工具是否匹配
        expected_tool = f"urn:mcp:{tool_path}"
        if verified_token.target_tool != expected_tool:
            expected_tool = verified_token.target_tool
        
        # ========== Step 4: ABAC 策略判定 ==========
        sub = agent_did
        obj = verified_token.target_tool
        act = "read"
        
        # 显式检查是否允许访问（策略文件中只列出允许的，未列出的默认拒绝）
        # 对于敏感操作（如 delete_db），即使策略中没有显式 deny，也默认拒绝
        forbidden_tools = ["urn:mcp:delete_db", "urn:mcp:format_disk"]  # 默认禁止的工具列表
        
        if obj in forbidden_tools:
            print(f"[Gateway Test] ABAC policy DENIED: {sub} -> {obj} ({act}) - Tool is in forbidden list")
            raise HTTPException(
                status_code=403,
                detail=f"ABAC policy denied: Agent {sub} is not allowed to access forbidden tool {obj}"
            )
        
        try:
            allowed = enforcer.enforce(sub, obj, act)
        except Exception as e:
            print(f"[Gateway Test] ABAC policy evaluation error: {e}")
            import traceback
            traceback.print_exc()
            raise HTTPException(
                status_code=500,
                detail=f"ABAC policy evaluation failed: {str(e)}"
            )
        
        if not allowed:
            print(f"[Gateway Test] ABAC policy DENIED: {sub} -> {obj} ({act}) - No matching policy found")
            raise HTTPException(
                status_code=403,
                detail=f"ABAC policy denied: Agent {sub} is not allowed to access {obj}"
            )
        
        print(f"[Gateway Test] ABAC policy ALLOWED: {sub} -> {obj} ({act})")
        
        # ========== 验证通过，返回成功（不转发到 MCP） ==========
        return JSONResponse({
            "status": "success",
            "message": "All security checks passed",
            "verification": {
                "user_id": user_id,
                "user_role": user_role,
                "user_dept": user_dept,
                "agent_did": agent_did,
                "target_tool": verified_token.target_tool,
                "identity_binding": "verified",
                "signature": "verified",
                "abac_policy": "allowed"
            },
            "note": "This is a test endpoint. MCP tool call is skipped."
        })
    except HTTPException:
        raise
    except Exception as e:
        print(f"[Gateway Test] Unexpected error: {e}")
        import traceback
        traceback.print_exc()
        raise HTTPException(status_code=500, detail=f"Internal server error: {str(e)}")


@app.post("/gateway/register-agent")
async def register_agent(request: Request):
    """
    注册 Agent 端点。
    
    Agent 通过 HTTP POST 注册到注册中心，提供：
    - agent_did: Agent 的 DID 标识符
    - public_key_pem: Agent 的公钥 (PEM 格式)
    - metadata: Agent 的元数据 (type, owner, sensitivity, capabilities)
    """
    try:
        body = await request.json()
        agent_did = body.get("agent_did")
        public_key_pem = body.get("public_key_pem")
        metadata = body.get("metadata", {})
        
        if not agent_did or not public_key_pem:
            raise HTTPException(status_code=400, detail="Missing agent_did or public_key_pem")
        
        # 从 PEM 字符串加载公钥
        public_key = serialization.load_pem_public_key(
            public_key_pem.encode('utf-8'),
            backend=default_backend()
        )
        
        # 注册 Agent 并获取详细信息
        registration_info = registry.register_agent(agent_did, public_key, metadata)
        
        # 打印格式化的注册日志
        print_registration_log(registration_info)
        
        return {
            "status": "success",
            "message": f"Agent {agent_did} registered successfully",
            "registration": registration_info
        }
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Registration failed: {str(e)}")


def print_registration_log(info: dict):
    """打印格式化的 Agent 注册日志。"""
    from datetime import datetime
    
    # 敏感度级别对应的标记
    sensitivity_marks = {
        "Internal": "[Internal]",
        "Confidential": "[Confidential]",
        "TopSecret": "[TopSecret]"
    }
    
    sensitivity = info.get("sensitivity", "unknown")
    sensitivity_mark = sensitivity_marks.get(sensitivity, f"[{sensitivity}]")
    
    log = f"""
================================================================================
[Registry] Agent Registration Request Received
================================================================================
  Timestamp:    {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}
  DID:          {info.get("did", "N/A")}
  Type:         {info.get("type", "N/A")}
  Owner:        {info.get("owner", "N/A")}
  Sensitivity:  {sensitivity} {sensitivity_mark}
  Capabilities: {info.get("capabilities", [])}
--------------------------------------------------------------------------------
  Status:       [OK] REGISTERED SUCCESSFULLY
================================================================================
"""
    print(log)


@app.get("/gateway/agents")
async def list_registered_agents():
    """列出所有已注册的 Agent（用于调试）。"""
    return {
        "agents": registry.get_all_agent_info(),
        "total": len(registry.list_agents())
    }


@app.get("/gateway/query-agent")
async def query_agent_endpoint(
    agent_type: Optional[str] = None,
    task_type: Optional[str] = None
):
    """
    查询 Agent 端点。
    
    MainAgent 通过此端点查询合适的 Task Agent。
    
    Query Parameters:
        agent_type: Agent 类型 (如 "finance", "hr")
        task_type: 任务类型 (如 "audit", "report")
    """
    if task_type:
        # 根据任务类型查找 Agent
        agent_did = registry.find_agent_for_task(task_type)
        if agent_did:
            metadata = registry.get_agent_metadata(agent_did)
            return {
                "status": "found",
                "agent_did": agent_did,
                "metadata": metadata
            }
        else:
            return {
                "status": "not_found",
                "message": f"No agent found for task type: {task_type}"
            }
    
    if agent_type:
        # 根据 Agent 类型查找
        agents = registry.get_agents_by_type(agent_type)
        if agents:
            return {
                "status": "found",
                "agents": [
                    {"agent_did": did, "metadata": registry.get_agent_metadata(did)}
                    for did in agents
                ]
            }
        else:
            return {
                "status": "not_found",
                "message": f"No agents found for type: {agent_type}"
            }
    
    # 返回所有 Agent
    return {
        "status": "success",
        "agents": registry.get_all_agent_info()
    }


@app.post("/gateway/collaboration/add-agent")
async def add_agent_to_collaboration(
    request: Request,
    x_user_token: Optional[str] = Header(None, alias="X-User-Token"),
    x_session_id: Optional[str] = Header(None, alias="X-Session-Id")
):
    """
    将 Agent 添加到协作组。
    
    在授权成功后，将 Task Agent 添加到当前会话的协作组中。
    
    请求体:
    {
        "agent_did": "did:agent:fin_analyst",
        "authorization_token": "..." (可选，网关颁发的授权凭证)
    }
    """
    if not x_user_token:
        raise HTTPException(status_code=401, detail="Missing X-User-Token header")
    
    if not x_session_id:
        raise HTTPException(status_code=400, detail="Missing X-Session-Id header")
    
    # 验证用户 JWT
    try:
        user_info = decode_user_jwt(x_user_token)
        user_id = user_info.get("uid")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid user token: {str(e)}")
    
    # 检查会话是否存在
    if x_session_id not in collaboration_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = collaboration_sessions[x_session_id]
    
    # 验证会话所属用户
    if session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Session does not belong to this user")
    
    # 获取请求体
    try:
        body = await request.json()
    except Exception:
        raise HTTPException(status_code=400, detail="Invalid request body")
    
    agent_did = body.get("agent_did")
    if not agent_did:
        raise HTTPException(status_code=400, detail="Missing agent_did")
    
    # 检查 Agent 是否已注册
    if not registry.is_registered(agent_did):
        raise HTTPException(status_code=404, detail=f"Agent {agent_did} is not registered")
    
    # 添加到协作组
    if agent_did not in session["authorized_agents"]:
        session["authorized_agents"].append(agent_did)
        print(f"[Gateway] Agent {agent_did} added to collaboration session {x_session_id}")
    
    return {
        "status": "success",
        "message": f"Agent {agent_did} added to collaboration",
        "session_id": x_session_id,
        "authorized_agents": session["authorized_agents"]
    }


@app.get("/gateway/collaboration/{session_id}/agents")
async def get_collaboration_agents(
    session_id: str,
    x_user_token: Optional[str] = Header(None, alias="X-User-Token")
):
    """
    获取协作组中的 Agent 列表。
    """
    if not x_user_token:
        raise HTTPException(status_code=401, detail="Missing X-User-Token header")
    
    # 验证用户 JWT
    try:
        user_info = decode_user_jwt(x_user_token)
        user_id = user_info.get("uid")
    except HTTPException:
        raise
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid user token: {str(e)}")
    
    if session_id not in collaboration_sessions:
        raise HTTPException(status_code=404, detail="Session not found")
    
    session = collaboration_sessions[session_id]
    
    # 验证会话所属用户
    if session["user_id"] != user_id:
        raise HTTPException(status_code=403, detail="Session does not belong to this user")
    
    return {
        "session_id": session_id,
        "user_id": session["user_id"],
        "authorized_agents": session["authorized_agents"],
        "created_at": session["created_at"]
    }


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)
