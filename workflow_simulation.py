"""
Workflow Simulation (Deprecated)
此文件已被 client_test.py 替代
请使用 client_test.py 进行真实的系统测试
"""

import asyncio
import jwt
import time
from datetime import datetime, timedelta

from agents.finance_agent import FinanceAgent
from services.registry import registry
from core.token_manager import decode_task_token_payload, create_task_token, TaskMCPToken
from core.crypto import KeyPair


# 模拟用户身份 Token 生成
def create_user_jwt(uid: str, role: str, dept: str) -> str:
    """
    创建用户身份 JWT Token（模拟）。
    实际环境中应该使用安全的密钥和算法。
    """
    payload = {
        "uid": uid,
        "role": role,
        "dept": dept,
        "exp": int(time.time()) + 3600,  # 1小时过期
        "iat": int(time.time())
    }
    # 注意：这里为了演示，使用未签名的 JWT
    # 实际环境中应该使用 HS256 或 RS256 等算法签名
    token = jwt.encode(payload, "dummy_secret", algorithm="HS256")
    return token


async def setup_registry():
    """设置注册中心：注册 Finance Agent。"""
    print("\n" + "="*60)
    print("Setting up Agent Registry")
    print("="*60)
    
    finance_agent = FinanceAgent()
    registry.register_agent(
        agent_did=finance_agent.agent_did,
        public_key=finance_agent.public_key,
        metadata={"type": "finance", "version": "1.0"}
    )
    
    print(f"✅ Registered agent: {finance_agent.agent_did}")
    return finance_agent


async def simulate_compliant_workflow():
    """
    模拟合规流程：
    1. User_C 登录，获得 user_jwt
    2. 调度 Finance_Agent
    3. Agent 内部调用 create_task_token(..., user_id='User_C', ...)
    4. 发送请求给网关
    5. 网关通过，MCP 返回数据
    """
    print("\n" + "="*60)
    print("Simulation 1: Compliant Workflow")
    print("="*60)
    
    # Step 1: User_C 登录，获得 user_jwt
    user_id = "User_C"
    user_role = "Director"
    user_dept = "Finance"
    user_jwt = create_user_jwt(user_id, user_role, user_dept)
    print(f"\n[Step 1] User {user_id} logged in")
    print(f"         Role: {user_role}, Dept: {user_dept}")
    print(f"         User JWT: {user_jwt[:50]}...")
    
    # Step 2: 调度 Finance_Agent
    finance_agent = FinanceAgent()
    print(f"\n[Step 2] Finance Agent initialized: {finance_agent.agent_did}")
    
    # Step 3: Agent 创建 Task-MCP Token
    tool_name = "urn:mcp:audit"
    token_data = finance_agent.create_task_token_for_user(user_id, tool_name)
    print(f"\n[Step 3] Agent created Task-MCP Token")
    print(f"         Target Tool: {tool_name}")
    print(f"         Payload: {token_data['payload'][:50]}...")
    print(f"         Signature: {token_data['signature'][:50]}...")
    
    # 解码 token 查看内容
    task_token = decode_task_token_payload(token_data["payload"])
    print(f"         Token content:")
    print(f"           - Agent DID (iss): {task_token.iss}")
    print(f"           - User ID (sub): {task_token.sub}")
    print(f"           - Target Tool: {task_token.target_tool}")
    print(f"           - Timestamp: {task_token.timestamp}")
    
    # Step 4 & 5: 发送请求给网关（这里模拟，实际需要网关服务运行）
    print(f"\n[Step 4-5] Request would be sent to gateway with:")
    print(f"          X-User-Token: {user_jwt[:30]}...")
    print(f"          X-Task-Token-Payload: {token_data['payload'][:30]}...")
    print(f"          X-Task-Token-Signature: {token_data['signature'][:30]}...")
    print(f"\n✅ Compliant workflow simulation completed")
    print("   (Gateway would verify signature, check binding, evaluate ABAC policy, and forward to MCP)")


async def simulate_attack_workflow():
    """
    模拟攻击流程（篡改）：
    - 攻击者截获 Token，修改 target_tool 为 "urn:mcp:delete_db"
    - 网关验签失败，拦截请求
    """
    print("\n" + "="*60)
    print("Simulation 2: Attack Workflow (Token Tampering)")
    print("="*60)
    
    # Step 1: 正常创建 Token
    finance_agent = FinanceAgent()
    user_id = "User_C"
    original_tool = "urn:mcp:audit"
    token_data = finance_agent.create_task_token_for_user(user_id, original_tool)
    
    print(f"\n[Step 1] Original Token created:")
    print(f"         Target Tool: {original_tool}")
    print(f"         Payload: {token_data['payload'][:50]}...")
    print(f"         Signature: {token_data['signature'][:50]}...")
    
    # Step 2: 攻击者尝试篡改 Token
    print(f"\n[Step 2] 🚨 Attacker intercepts and tampers with token")
    
    # 解码原始 payload
    original_token = decode_task_token_payload(token_data["payload"])
    print(f"         Original token content:")
    print(f"           - Target Tool: {original_token.target_tool}")
    
    # 攻击者修改 target_tool
    malicious_tool = "urn:mcp:delete_db"
    tampered_token = TaskMCPToken(
        iss=original_token.iss,
        sub=original_token.sub,
        target_tool=malicious_tool,  # 篡改目标工具
        nonce=original_token.nonce,
        timestamp=original_token.timestamp
    )
    
    # 生成新的 payload（但没有重新签名，使用旧签名）
    import base64
    tampered_payload_json = tampered_token.to_json()
    tampered_payload_encoded = base64.b64encode(tampered_payload_json.encode('utf-8')).decode('utf-8')
    
    print(f"         Tampered token content:")
    print(f"           - Target Tool: {tampered_token.target_tool} ⚠️ (CHANGED!)")
    print(f"           - Using OLD signature (not re-signed)")
    
    # Step 3: 网关验签（应该失败）
    print(f"\n[Step 3] 🔒 Gateway verifies signature...")
    
    agent_public_key = registry.get_public_key(finance_agent.agent_did)
    if agent_public_key:
        from core.token_manager import verify_task_token
        is_valid, _ = verify_task_token(
            tampered_payload_encoded,
            token_data["signature"],  # 使用原始签名
            agent_public_key
        )
        
        if not is_valid:
            print(f"         ❌ Signature verification FAILED")
            print(f"         🛡️ Gateway BLOCKS the request")
            print(f"\n✅ Attack simulation completed - Gateway successfully prevented tampering")
        else:
            print(f"         ⚠️ WARNING: Signature verification passed (should not happen!)")
    else:
        print(f"         ❌ Agent not registered (simulation issue)")


async def simulate_binding_mismatch_attack():
    """
    模拟身份绑定不匹配攻击：
    - Agent 尝试使用其他用户的身份
    - 网关检测到 User Token.uid != Task Token.sub，拒绝请求
    """
    print("\n" + "="*60)
    print("Simulation 3: Identity Binding Mismatch Attack")
    print("="*60)
    
    # Step 1: User_A 登录
    user_a_id = "User_A"
    user_a_jwt = create_user_jwt(user_a_id, "Employee", "IT")
    print(f"\n[Step 1] User_A logged in: {user_a_id}")
    
    # Step 2: 攻击者（Agent）尝试使用 User_C 的身份
    finance_agent = FinanceAgent()
    malicious_user_id = "User_C"  # Agent 声称代表 User_C
    tool_name = "urn:mcp:audit"
    
    token_data = finance_agent.create_task_token_for_user(malicious_user_id, tool_name)
    print(f"\n[Step 2] 🚨 Agent creates Task-Token with malicious user_id: {malicious_user_id}")
    
    task_token = decode_task_token_payload(token_data["payload"])
    print(f"         Task-Token.sub (claimed user): {task_token.sub}")
    
    # Step 3: 网关检测绑定不匹配
    print(f"\n[Step 3] 🔒 Gateway checks identity binding...")
    print(f"         User Token.uid: {user_a_id}")
    print(f"         Task Token.sub: {task_token.sub}")
    
    if user_a_id != task_token.sub:
        print(f"         ❌ Identity binding MISMATCH")
        print(f"         🛡️ Gateway BLOCKS the request")
        print(f"\n✅ Binding check simulation completed - Gateway successfully prevented identity spoofing")
    else:
        print(f"         ⚠️ WARNING: Binding check passed (should not happen!)")


async def main():
    """主函数：运行所有模拟。"""
    print("\n" + "="*60)
    print("Multi-Agent Security Gateway - Workflow Simulation")
    print("="*60)
    
    # 设置注册中心
    finance_agent = await setup_registry()
    
    # 模拟合规流程
    await simulate_compliant_workflow()
    
    # 模拟攻击流程
    await simulate_attack_workflow()
    
    # 模拟身份绑定不匹配攻击
    await simulate_binding_mismatch_attack()
    
    print("\n" + "="*60)
    print("All simulations completed")
    print("="*60)
    print("\nTo test with actual gateway server:")
    print("1. Start MCP Tool Server: python -m services.mcp_tool_server")
    print("2. Start Gateway: python -m services.gateway")
    print("3. Run this simulation with gateway endpoints")


if __name__ == "__main__":
    asyncio.run(main())

