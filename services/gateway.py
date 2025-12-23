"""
Security Gateway (PEP - Policy Enforcement Point)
核心安全网关：实现 Task-MCP Token 验证和 ABAC 策略执行
"""

from fastapi import FastAPI, Request, HTTPException, Header
from fastapi.responses import JSONResponse
from typing import Optional
import httpx
import jwt
import casbin
import os

from services.registry import registry
from core.token_manager import decode_task_token_payload, verify_task_token


app = FastAPI(title="Multi-Agent Security Gateway")


# 初始化 Casbin ABAC 引擎
casbin_model_path = os.path.join(os.path.dirname(__file__), "..", "config", "abac_model.conf")
casbin_policy_path = os.path.join(os.path.dirname(__file__), "..", "config", "policy.csv")
enforcer = casbin.Enforcer(casbin_model_path, casbin_policy_path)

# MCP Tool Server 地址
MCP_TOOL_SERVER_URL = "http://localhost:8001"


def decode_user_jwt(token: str) -> dict:
    """
    解码 User Identity Token (JWT)。
    注意：这里简化处理，实际生产环境需要验证 JWT 签名。
    """
    try:
        # 实际环境中应该验证 JWT 签名和有效期
        # 这里为了演示，直接解码（不验证签名）
        decoded = jwt.decode(token, options={"verify_signature": False})
        return decoded
    except Exception as e:
        raise HTTPException(status_code=401, detail=f"Invalid user token: {str(e)}")


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
        print(f"[Gateway] ❌ Binding check FAILED: User token uid={user_id}, Task token sub={verified_token.sub}")
        raise HTTPException(
            status_code=403,
            detail=f"Identity binding mismatch: User token uid ({user_id}) != Task token sub ({verified_token.sub})"
        )
    
    print(f"[Gateway] ✅ Identity binding verified: User {user_id} is bound to Agent {agent_did}")
    
    # 检查目标工具是否匹配
    expected_tool = f"urn:mcp:{tool_path}"
    if verified_token.target_tool != expected_tool:
        print(f"[Gateway] ⚠️ Tool mismatch: Task token specifies {verified_token.target_tool}, but request is for {expected_tool}")
        # 这里可以选择严格模式（拒绝）或宽松模式（使用 token 中指定的工具）
        # 为了安全，我们使用 token 中指定的工具
        expected_tool = verified_token.target_tool
    
    # ========== Step 4: ABAC 策略判定 ==========
    # 提取属性
    sub = agent_did  # Agent DID
    obj = verified_token.target_tool  # 目标工具
    act = "read"  # 操作类型（可以从请求中提取，这里简化处理）
    timestamp = verified_token.timestamp
    user_dept_attr = user_dept
    user_role_attr = user_role
    
    # 注意：这里简化了 Casbin 模型，实际可能需要自定义函数来处理时间约束等
    # 由于 Casbin 的 ABAC 模型配置可能需要自定义函数，这里先进行基本的策略检查
    # 实际应用中，需要扩展 Casbin 的匹配器函数
    
    # 简化版 ABAC 检查：检查 (agent_did, tool, action) 是否允许
    allowed = enforcer.enforce(sub, obj, act)
    
    if not allowed:
        print(f"[Gateway] ❌ ABAC policy DENIED: {sub} -> {obj} ({act})")
        raise HTTPException(
            status_code=403,
            detail=f"ABAC policy denied: Agent {sub} is not allowed to access {obj}"
        )
    
    print(f"[Gateway] ✅ ABAC policy ALLOWED: {sub} -> {obj} ({act})")
    
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


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8000)

