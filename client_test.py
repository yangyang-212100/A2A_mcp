"""
Client Test - 完整授权流程测试
测试完整的用户 -> 网关 -> Main Agent -> 网关(ABAC) -> Task Agent 授权流程
"""

import asyncio
import jwt
import time
import httpx

from agents.main_agent import MainAgent
from agents.finance_agent import FinanceAgent, HRAgent
from services.registry import registry


GATEWAY_URL = "http://localhost:8000"
JWT_SECRET = "dummy_secret"


def create_user_jwt(uid: str, role: str, dept: str) -> str:
    """
    创建用户身份 JWT Token。
    模拟身份认证中心颁发的 JWT。
    """
    payload = {
        "uid": uid,
        "role": role,
        "dept": dept,
        "exp": int(time.time()) + 3600,  # 1小时过期
        "iat": int(time.time())
    }
    token = jwt.encode(payload, JWT_SECRET, algorithm="HS256")
    return token


async def register_agents_to_gateway():
    """将所有 Agent 注册到网关的注册中心和本地注册中心。"""
    print("\n[Setup] Registering agents to gateway and local registry...")
    
    # 创建 Agent 实例
    finance_agent = FinanceAgent()
    hr_agent = HRAgent()
    
    agents = [
        (finance_agent, finance_agent.get_metadata()),
        (hr_agent, hr_agent.get_metadata())
    ]
    
    for agent, metadata in agents:
        # 注册到本地 registry (供 MainAgent 查找)
        registry.register_agent(agent.agent_did, agent.public_key, metadata)
        
        # 注册到网关的 registry
        try:
            async with httpx.AsyncClient(timeout=5.0) as client:
                response = await client.post(
                    f"{GATEWAY_URL}/gateway/register-agent",
                    json={
                        "agent_did": agent.agent_did,
                        "public_key_pem": agent.key_pair.public_key_pem(),
                        "metadata": metadata
                    }
                )
                if response.status_code == 200:
                    print(f"[Setup] Registered: {agent.agent_did}")
                else:
                    print(f"[Setup] Failed to register {agent.agent_did}: {response.text}")
        except Exception as e:
            print(f"[Setup] Error registering {agent.agent_did}: {e}")
            return False
    
    return True


# ==================== 完整授权流程测试 ====================

async def test_full_authorization_flow_success():
    """
    测试完整授权流程 - 成功场景
    
    用户 (Finance Director) -> 网关验证JWT -> Main Agent 意图识别 
    -> 网关ABAC授权(Finance部门调用Finance Agent) -> 成功
    """
    print("\n" + "="*70)
    print("Test: Full Authorization Flow - SUCCESS (Finance User -> Finance Agent)")
    print("="*70)
    
    # Step 1: 用户登录（模拟身份认证中心）
    user_id = "User_C"
    user_role = "Director"
    user_dept = "Finance"  # Finance 部门
    user_jwt = create_user_jwt(user_id, user_role, user_dept)
    print(f"\n[Step 1] User logged in at Identity Center")
    print(f"         uid: {user_id}, role: {user_role}, dept: {user_dept}")
    
    # Step 2: 用户发送请求到网关
    print(f"\n[Step 2] User sends request to Gateway with JWT")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/user-request",
                json={"query": "请执行财务审计"},
                headers={"X-User-Token": user_jwt}
            )
            
            if response.status_code != 200:
                print(f"[FAILED] Gateway rejected user request: {response.status_code}")
                print(f"         Response: {response.text}")
                return False
            
            session_data = response.json()
            session_id = session_data.get("session_id")
            print(f"         Gateway validated JWT")
            print(f"         Session created: {session_id}")
    except Exception as e:
        print(f"[ERROR] Failed to connect to gateway: {e}")
        return False
    
    # Step 3: Main Agent 处理请求（意图识别 + 向网关申请授权）
    print(f"\n[Step 3] Main Agent processes request")
    main_agent = MainAgent()
    
    result = await main_agent.process_user_request(
        user_jwt=user_jwt,
        user_query="请执行财务审计",
        session_id=session_id
    )
    
    # Step 4: 检查结果
    print(f"\n[Step 4] Authorization Result")
    if result["status"] == "completed" or result["status"] == "authorized":
        print(f"[SUCCESS] Authorization granted!")
        print(f"         Authorized agents: {result['authorized_agents']}")
        print(f"         Message: {result['message']}")
        return True
    elif result["status"] == "partial":
        print(f"[PARTIAL] Some agents authorized")
        print(f"         Authorized: {result['authorized_agents']}")
        print(f"         Denied: {result['denied_agents']}")
        return len(result['authorized_agents']) > 0
    else:
        print(f"[FAILED] Authorization denied")
        print(f"         Error: {result.get('message', 'Unknown')}")
        return False


async def test_full_authorization_flow_denied():
    """
    测试完整授权流程 - 失败场景（跨部门访问）
    
    用户 (Sales Manager) -> 网关验证JWT -> Main Agent 意图识别 
    -> 网关ABAC授权(Sales部门调用Finance Agent) -> 拒绝
    """
    print("\n" + "="*70)
    print("Test: Full Authorization Flow - DENIED (Sales User -> Finance Agent)")
    print("="*70)
    
    # Step 1: 用户登录（Sales 部门）
    user_id = "User_B"
    user_role = "Manager"
    user_dept = "Sales"  # Sales 部门
    user_jwt = create_user_jwt(user_id, user_role, user_dept)
    print(f"\n[Step 1] User logged in at Identity Center")
    print(f"         uid: {user_id}, role: {user_role}, dept: {user_dept}")
    
    # Step 2: 用户发送请求到网关
    print(f"\n[Step 2] User sends request to Gateway with JWT")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/user-request",
                json={"query": "请执行财务审计"},  # Sales 用户尝试访问财务功能
                headers={"X-User-Token": user_jwt}
            )
            
            if response.status_code != 200:
                print(f"[INFO] Gateway rejected: {response.status_code}")
                return True  # JWT 验证失败也算测试通过
            
            session_data = response.json()
            session_id = session_data.get("session_id")
            print(f"         Gateway validated JWT")
            print(f"         Session created: {session_id}")
    except Exception as e:
        print(f"[ERROR] Failed to connect to gateway: {e}")
        return False
    
    # Step 3: Main Agent 处理请求（意图识别 + 向网关申请授权）
    print(f"\n[Step 3] Main Agent processes request")
    main_agent = MainAgent()
    
    result = await main_agent.process_user_request(
        user_jwt=user_jwt,
        user_query="请执行财务审计",
        session_id=session_id
    )
    
    # Step 4: 检查结果 - 应该被拒绝
    print(f"\n[Step 4] Authorization Result")
    if result["status"] == "denied":
        print(f"[SUCCESS] Access correctly DENIED!")
        print(f"         Denied agents: {result['denied_agents']}")
        if result['denied_agents']:
            print(f"         Reason: {result['denied_agents'][0].get('error', 'Unknown')}")
        return True
    else:
        print(f"[FAILED] Access should have been denied but got: {result['status']}")
        print(f"         Authorized agents: {result.get('authorized_agents', [])}")
        return False


async def test_direct_agent_authorization():
    """
    测试直接向网关申请 Agent 授权
    
    这个测试模拟 Main Agent 直接调用网关的授权端点
    """
    print("\n" + "="*70)
    print("Test: Direct Agent Authorization via Gateway")
    print("="*70)
    
    # Case A: Finance 用户调用 Finance Agent - 应该成功
    print("\n--- Case A: Finance User -> Finance Agent (should ALLOW) ---")
    user_jwt_finance = create_user_jwt("User_C", "Director", "Finance")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/authorize-agent-call",
                json={
                    "target_agent_did": "did:agent:fin_analyst",
                    "task_description": "执行财务审计"
                },
                headers={"X-User-Token": user_jwt_finance}
            )
            
            if response.status_code == 200:
                print(f"[SUCCESS] Finance user authorized to call Finance Agent")
                result = response.json()
                print(f"         Authorization: {result.get('authorization', {}).get('user_dept')} -> {result.get('authorization', {}).get('target_agent')}")
            else:
                print(f"[FAILED] Expected 200 but got {response.status_code}")
                print(f"         Response: {response.text}")
                return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    # Case B: Sales 用户调用 Finance Agent - 应该失败
    print("\n--- Case B: Sales User -> Finance Agent (should DENY) ---")
    user_jwt_sales = create_user_jwt("User_B", "Manager", "Sales")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/authorize-agent-call",
                json={
                    "target_agent_did": "did:agent:fin_analyst",
                    "task_description": "执行财务审计"
                },
                headers={"X-User-Token": user_jwt_sales}
            )
            
            if response.status_code == 403:
                print(f"[SUCCESS] Sales user correctly DENIED access to Finance Agent")
                result = response.json()
                print(f"         Reason: {result.get('detail', 'Unknown')}")
            else:
                print(f"[FAILED] Expected 403 but got {response.status_code}")
                print(f"         Response: {response.text}")
                return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    # Case C: HR 用户调用 HR Agent - 应该成功
    print("\n--- Case C: HR User -> HR Agent (should ALLOW) ---")
    user_jwt_hr = create_user_jwt("User_HR", "Manager", "HR")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/authorize-agent-call",
                json={
                    "target_agent_did": "did:agent:hr_agent",
                    "task_description": "查询员工信息"
                },
                headers={"X-User-Token": user_jwt_hr}
            )
            
            if response.status_code == 200:
                print(f"[SUCCESS] HR user authorized to call HR Agent")
            else:
                print(f"[FAILED] Expected 200 but got {response.status_code}")
                print(f"         Response: {response.text}")
                return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    # Case D: IT 用户调用 Finance Agent - 应该成功（IT 有权限调用所有 Agent）
    print("\n--- Case D: IT User -> Finance Agent (should ALLOW - IT has full access) ---")
    user_jwt_it = create_user_jwt("User_IT", "Admin", "IT")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/authorize-agent-call",
                json={
                    "target_agent_did": "did:agent:fin_analyst",
                    "task_description": "系统检查财务模块"
                },
                headers={"X-User-Token": user_jwt_it}
            )
            
            if response.status_code == 200:
                print(f"[SUCCESS] IT user authorized to call Finance Agent (full access)")
            else:
                print(f"[FAILED] Expected 200 but got {response.status_code}")
                print(f"         Response: {response.text}")
                return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    return True


async def test_user_jwt_validation():
    """
    测试用户 JWT 验证
    """
    print("\n" + "="*70)
    print("Test: User JWT Validation at Gateway")
    print("="*70)
    
    # Case A: 有效的 JWT
    print("\n--- Case A: Valid JWT ---")
    valid_jwt = create_user_jwt("User_A", "Employee", "Finance")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/user-request",
                json={"query": "测试请求"},
                headers={"X-User-Token": valid_jwt}
            )
            if response.status_code == 200:
                print(f"[SUCCESS] Valid JWT accepted")
            else:
                print(f"[FAILED] Valid JWT rejected: {response.status_code}")
                return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    # Case B: 无效的 JWT
    print("\n--- Case B: Invalid JWT ---")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/user-request",
                json={"query": "测试请求"},
                headers={"X-User-Token": "invalid.jwt.token"}
            )
            if response.status_code == 401:
                print(f"[SUCCESS] Invalid JWT correctly rejected")
            else:
                print(f"[FAILED] Invalid JWT should be rejected but got: {response.status_code}")
                return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    # Case C: 缺少 JWT
    print("\n--- Case C: Missing JWT ---")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/user-request",
                json={"query": "测试请求"}
            )
            if response.status_code == 401:
                print(f"[SUCCESS] Missing JWT correctly rejected")
            else:
                print(f"[FAILED] Missing JWT should be rejected but got: {response.status_code}")
                return False
    except Exception as e:
        print(f"[ERROR] {e}")
        return False
    
    return True


async def main():
    """运行所有测试。"""
    print("\n" + "="*70)
    print("Multi-Agent Authorization System - Complete Flow Test")
    print("="*70)
    
    print("\n[INFO] Make sure the gateway is running:")
    print("       python -m services.gateway")
    
    # 检查网关是否运行
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{GATEWAY_URL}/gateway/health")
            if response.status_code != 200:
                print(f"\n[ERROR] Gateway is not healthy")
                return
    except Exception:
        print(f"\n[ERROR] Cannot connect to gateway at {GATEWAY_URL}")
        print("        Please start the gateway first: python -m services.gateway")
        return
    
    print(f"\n[INFO] Gateway is running at {GATEWAY_URL}")
    
    # 注册 Agent
    if not await register_agents_to_gateway():
        print("[ERROR] Failed to register agents")
        return
    
    results = []
    
    # Test 1: JWT 验证
    results.append(("JWT Validation", await test_user_jwt_validation()))
    
    # Test 2: 直接授权测试
    results.append(("Direct Agent Authorization", await test_direct_agent_authorization()))
    
    # Test 3: 完整流程 - 成功
    results.append(("Full Flow - Success", await test_full_authorization_flow_success()))
    
    # Test 4: 完整流程 - 拒绝
    results.append(("Full Flow - Denied", await test_full_authorization_flow_denied()))
    
    # 总结
    print("\n" + "="*70)
    print("Test Summary")
    print("="*70)
    
    passed = sum(1 for _, result in results if result)
    total = len(results)
    
    for name, result in results:
        status = "PASS" if result else "FAIL"
        print(f"  [{status}] {name}")
    
    print(f"\nTotal: {passed}/{total} tests passed")
    
    if passed == total:
        print("\n[SUCCESS] All tests passed! Authorization system is working correctly.")
    else:
        print(f"\n[WARNING] {total - passed} test(s) failed. Check the output above.")


if __name__ == "__main__":
    asyncio.run(main())
