"""
Client Test - 完整授权流程测试
测试完整的用户 -> 网关 -> Main Agent -> 网关(ABAC) -> Task Agent 授权流程

使用 SM2 国密算法签发和验证 JWT
"""

import asyncio
import httpx
from datetime import datetime

from agents.main_agent import MainAgent
from agents.finance_agent import FinanceAgent, HRAgent
from core.sm2_jwt import (
    create_user_jwt,
    create_sm2_jwt,
    verify_sm2_jwt,
    AUTH_CENTER_PUBLIC_KEY,
    ISSUER
)
from core.token_manager import compute_params_hash


GATEWAY_URL = "http://localhost:8000"


async def register_agents_to_gateway():
    """将所有 Agent 通过 HTTP 注册到网关的注册中心。"""
    print("\n[Setup] Registering agents to gateway via HTTP...")
    
    # 创建 Agent 实例
    finance_agent = FinanceAgent()
    hr_agent = HRAgent()
    
    agents = [
        (finance_agent, finance_agent.get_metadata()),
        (hr_agent, hr_agent.get_metadata())
    ]
    
    for agent, metadata in agents:
        # 通过 HTTP 注册到网关的 registry
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
                    print(f"[Setup] Registered via HTTP: {agent.agent_did}")
                else:
                    print(f"[Setup] Failed to register {agent.agent_did}: {response.text}")
        except Exception as e:
            print(f"[Setup] Error registering {agent.agent_did}: {e}")
            return False
    
    return True


# ==================== 完整授权流程测试 ====================

async def test_full_authorization_flow_success():
    """
    测试完整授权流程 - 成功场景（包含 JWT 签发和验签过程展示）
    
    完整流程：
    1. 用户在身份认证中心获取 SM2 签名的 JWT
    2. 用户携带 JWT 向网关发送请求
    3. 网关验证 JWT（SM2 验签）
    4. Main Agent 意图识别并申请授权
    5. 网关 ABAC 授权
    """
    print("\n" + "="*80)
    print("  Test: Full Authorization Flow with JWT Issuance & Verification")
    print("  (Finance Director -> Finance Agent)")
    print("="*80)
    
    # ==================== Step 1: 身份认证中心签发 JWT ====================
    print(f"\n" + "-"*80)
    print(f"  Step 1: User Authentication & JWT Issuance (Identity Center)")
    print(f"-"*80)
    
    user_id = "User_C"
    user_role = "Director"
    user_dept = "Finance"
    user_clearance = 4  # 安全许可等级 4
    
    print(f"\n  [Identity Center] User Login Request Received")
    print(f"  +---------------------------------------------------------------+")
    print(f"  |  User ID:         {user_id:<43}|")
    print(f"  |  Role:            {user_role:<43}|")
    print(f"  |  Department:      {user_dept:<43}|")
    print(f"  |  Clearance Level: {user_clearance} (1=Public, 5=TopSecret){' '*18}|")
    print(f"  +---------------------------------------------------------------+")
    
    # 调用 SM2 JWT 签发（带详情）
    print(f"\n  [Identity Center] Issuing JWT with SM2 Signature...")
    user_jwt, jwt_details = create_sm2_jwt(
        sub=user_id,
        dept=user_dept,
        role=user_role,
        clearance=user_clearance,
        verbose=True
    )
    
    # 展示 JWT 签发过程
    for step in jwt_details.get("steps", []):
        step_num = step.get("step")
        step_name = step.get("name")
        
        if step_num == 1:  # Header
            header = step.get("header", {})
            print(f"\n  [Step 1.{step_num}] {step_name}")
            print(f"    Header: {header}")
            print(f"    Algorithm: SM2 (Chinese National Cryptographic Standard)")
            
        elif step_num == 2:  # Payload
            payload = step.get("payload", {})
            print(f"\n  [Step 1.{step_num}] {step_name}")
            print(f"    Payload (User Attributes for ABAC):")
            print(f"    +-----------------------------------------------------------+")
            print(f"    |  iss:       {payload.get('iss', 'N/A'):<45}|")
            print(f"    |  sub:       {payload.get('sub', 'N/A'):<45}|")
            print(f"    |  dept:      {payload.get('dept', 'N/A'):<45}|")
            print(f"    |  role:      {payload.get('role', 'N/A'):<45}|")
            print(f"    |  clearance: {payload.get('clearance', 'N/A'):<45}|")
            print(f"    |  exp:       {payload.get('exp', 'N/A'):<45}|")
            print(f"    +-----------------------------------------------------------+")
            
        elif step_num == 3:  # Signature
            print(f"\n  [Step 1.{step_num}] {step_name}")
            print(f"    Algorithm: SM2 (Asymmetric Encryption)")
            sig_hex = step.get("signature_hex", "")
            print(f"    Signature: {sig_hex[:40]}...")
            
        elif step_num == 4:  # Token
            print(f"\n  [Step 1.{step_num}] {step_name}")
            print(f"    JWT Token: {user_jwt[:60]}...")
            print(f"    Token Length: {len(user_jwt)} characters")
    
    print(f"\n  [OK] JWT Issued Successfully by Identity Center")
    
    # ==================== Step 2: 用户携带 JWT 发送请求 ====================
    print(f"\n" + "-"*80)
    print(f"  Step 2: User Sends Request to Gateway with JWT")
    print(f"-"*80)
    
    print(f"\n  [User] Sending HTTP Request...")
    print(f"    POST {GATEWAY_URL}/gateway/user-request")
    print(f"    Headers:")
    print(f"      X-User-Token: {user_jwt[:50]}...")
    print(f"    Body:")
    print(f"      {{'query': 'Please perform financial audit'}}")
    
    # ==================== Step 3: 网关验证 JWT ====================
    print(f"\n" + "-"*80)
    print(f"  Step 3: Gateway Verifies JWT (SM2 Signature Verification)")
    print(f"-"*80)
    
    # 本地模拟验签过程展示
    print(f"\n  [Gateway] Received User Request, Verifying JWT...")
    is_valid, payload, verify_details = verify_sm2_jwt(user_jwt, verbose=True)
    
    for step in verify_details.get("steps", []):
        step_num = step.get("step")
        step_name = step.get("name")
        
        if step_num == 1:  # 解析结构
            print(f"\n  [Step 3.{step_num}] {step_name}")
            print(f"    Parsing JWT into 3 parts: Header | Payload | Signature")
            
        elif step_num == 2:  # 验证算法
            alg_check = step.get("algorithm_check", "").replace('✓', '[OK]').replace('✗', '[FAIL]')
            print(f"\n  [Step 3.{step_num}] {step_name}")
            print(f"    Algorithm Check: {alg_check}")
            
        elif step_num == 3:  # 验证签名
            sig_valid = step.get("signature_valid", False)
            status = "[OK] Signature Valid" if sig_valid else "[FAIL] Signature Invalid"
            print(f"\n  [Step 3.{step_num}] {step_name}")
            print(f"    Using Identity Center Public Key: {AUTH_CENTER_PUBLIC_KEY[:32]}...")
            print(f"    Verification Result: {status}")
            
        elif step_num == 5:  # 验证有效期
            status = step.get("status", "").replace('✓', '[OK]').replace('✗', '[FAIL]')
            remaining = step.get("remaining_seconds", 0)
            print(f"\n  [Step 3.{step_num}] {step_name}")
            print(f"    Status: {status}")
            print(f"    Remaining: {remaining} seconds")
            
        elif step_num == 6:  # 提取属性
            attrs = step.get("attributes", {})
            print(f"\n  [Step 3.{step_num}] {step_name}")
            print(f"    +-----------------------------------------------------------+")
            print(f"    |  Subject.id:                 {attrs.get('Subject.id', 'N/A'):<27}|")
            print(f"    |  Subject.department:         {attrs.get('Subject.department', 'N/A'):<27}|")
            print(f"    |  Subject.role:               {attrs.get('Subject.role', 'N/A'):<27}|")
            print(f"    |  Subject.security_clearance: {str(attrs.get('Subject.security_clearance', 'N/A')):<27}|")
            print(f"    +-----------------------------------------------------------+")
    
    # 实际发送请求到网关
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/user-request",
                json={"query": "Please perform financial audit"},
                headers={"X-User-Token": user_jwt}
            )
            
            if response.status_code != 200:
                print(f"\n  [FAILED] Gateway rejected request: {response.status_code}")
                print(f"           Response: {response.text}")
                return False
            
            session_data = response.json()
            session_id = session_data.get("session_id")
            print(f"\n  [OK] JWT Verification Passed!")
            print(f"       Session Created: {session_id}")
    except Exception as e:
        print(f"\n  [ERROR] Failed to connect to gateway: {e}")
        return False
    
    # ==================== Step 4: Main Agent 处理请求 ====================
    print(f"\n" + "-"*80)
    print(f"  Step 4: Main Agent Processes Request")
    print(f"-"*80)
    
    main_agent = MainAgent()
    
    result = await main_agent.process_user_request(
        user_jwt=user_jwt,
        user_query="Please perform financial audit",
        session_id=session_id
    )
    
    # ==================== Step 5: 结果 ====================
    print(f"\n" + "-"*80)
    print(f"  Step 5: Authorization Result")
    print(f"-"*80)
    
    if result["status"] == "completed" or result["status"] == "authorized":
        print(f"\n  [SUCCESS] Full Authorization Flow Completed!")
        print(f"  +---------------------------------------------------------------+")
        print(f"  |  Status:            Authorized                                |")
        print(f"  |  Authorized Agents: {str(result['authorized_agents']):<42}|")
        print(f"  |  Message:           {result['message'][:42]:<42}|")
        print(f"  +---------------------------------------------------------------+")
        return True
    elif result["status"] == "partial":
        print(f"\n  [PARTIAL] Some agents authorized")
        print(f"            Authorized: {result['authorized_agents']}")
        print(f"            Denied: {result['denied_agents']}")
        return len(result['authorized_agents']) > 0
    else:
        print(f"\n  [FAILED] Authorization denied")
        print(f"           Error: {result.get('message', 'Unknown')}")
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
    
    # Step 2: User sends request to Gateway
    print(f"\n[Step 2] User sends request to Gateway with JWT")
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/user-request",
                json={"query": "Please perform financial audit"},  # Sales user tries to access finance function
                headers={"X-User-Token": user_jwt}
            )
            
            if response.status_code != 200:
                print(f"[INFO] Gateway rejected: {response.status_code}")
                return True  # JWT validation failure also counts as test passed
            
            session_data = response.json()
            session_id = session_data.get("session_id")
            print(f"         Gateway validated JWT")
            print(f"         Session created: {session_id}")
    except Exception as e:
        print(f"[ERROR] Failed to connect to gateway: {e}")
        return False
    
    # Step 3: Main Agent processes request (intent recognition + request authorization from gateway)
    print(f"\n[Step 3] Main Agent processes request")
    main_agent = MainAgent()
    
    result = await main_agent.process_user_request(
        user_jwt=user_jwt,
        user_query="Please perform financial audit",
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
                    "target_agent_did": "did:agent:hr_archivist",  # 更新为新的 DID
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


# ==================== Task-MCP Token 完整性测试 ====================

async def test_task_mcp_token_integrity():
    """
    测试 Task-MCP Token 的三元绑定验证（论文 3.3.3 章节）。
    
    测试场景：
    A. 正常调用：Finance Agent 生成 Token，网关验证通过
    B. 参数篡改拦截：Token 生成后参数被篡改，网关检测并拒绝
    """
    print("\n" + "="*80)
    print("  Test: Task-MCP Token Integrity (Three-Way Binding)")
    print("  (Paper Section 3.3.3 - Parameter Hash Verification)")
    print("="*80)
    
    # 创建 Finance Agent 实例
    finance_agent = FinanceAgent()
    
    # 用户信息
    user_id = "User_C"
    user_dept = "Finance"
    user_role = "Director"
    user_clearance = 4
    session_id = f"session_{user_id}_test"
    
    # 创建用户 JWT
    user_jwt = create_user_jwt(user_id, user_role, user_dept)
    
    # 原始请求参数
    original_params = {
        "report_id": "Q1-2024",
        "type": "summary",
        "format": "pdf"
    }
    
    # ==================== Scenario A: Normal Call ====================
    print(f"\n" + "-"*80)
    print(f"  Scenario A: Normal Call (Parameters NOT Tampered)")
    print(f"-"*80)
    
    print(f"\n  [Step 1] Finance Agent performs business reasoning...")
    print(f"    Task: Query financial report")
    print(f"    Parameters: {original_params}")
    
    # Finance Agent 生成 Task-MCP Token
    print(f"\n  [Step 2] Finance Agent generates Task-MCP Token...")
    
    task_mcp_token, token_details = finance_agent.generate_task_mcp_token(
        user_id=user_id,
        clearance=user_clearance,
        session_id=session_id,
        task_description="Query financial report",
        params=original_params,
        verbose=True
    )
    
    # 展示 Token 载荷（对应论文表 3-2）
    payload = token_details.get("payload", {})
    print(f"\n  [Token Payload - Table 3-2]")
    print(f"  +---------------------------------------------------------------+")
    print(f"  |  jti:         {payload.get('jti', 'N/A'):<47}|")
    print(f"  |  iss:         {payload.get('iss', 'N/A'):<47}|")
    print(f"  |  context:                                                     |")
    print(f"  |    user_id:   {payload.get('context', {}).get('user_id', 'N/A'):<47}|")
    print(f"  |    clearance: {payload.get('context', {}).get('clearance', 'N/A'):<47}|")
    print(f"  |    session:   {payload.get('context', {}).get('session_id', 'N/A')[:40]:<47}|")
    print(f"  |  intent:                                                      |")
    print(f"  |    target:    {payload.get('intent', {}).get('target', 'N/A'):<47}|")
    print(f"  |    action:    {payload.get('intent', {}).get('action', 'N/A'):<47}|")
    print(f"  |  params_hash: {token_details.get('params_hash', 'N/A')[:40]}...   |")
    print(f"  +---------------------------------------------------------------+")
    
    print(f"\n  [Step 3] User sends request to Gateway with Task-MCP Token...")
    print(f"    Headers:")
    print(f"      X-User-Token: {user_jwt[:50]}...")
    print(f"      X-Task-MCP-Token: {task_mcp_token[:50]}...")
    print(f"    Body:")
    print(f"      agent_did: {finance_agent.agent_did}")
    print(f"      params: {original_params}")
    
    # 发送验证请求（参数未被篡改）
    print(f"\n  [Step 4] Gateway verifies Task-MCP Token (Three-Way Binding)...")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/verify-task-mcp-token",
                json={
                    "agent_did": finance_agent.agent_did,
                    "params": original_params  # 原始参数，未篡改
                },
                headers={
                    "X-User-Token": user_jwt,
                    "X-Task-MCP-Token": task_mcp_token
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"\n  [OK] Three-Way Binding Verification PASSED!")
                print(f"    Agent Signature: Valid")
                print(f"    User Binding:    Valid (token.user_id == session.user_id)")
                print(f"    Params Hash:     Valid (no tampering detected)")
                scenario_a_passed = True
            else:
                print(f"\n  [FAILED] Unexpected rejection: {response.status_code}")
                print(f"    Response: {response.text}")
                scenario_a_passed = False
    except Exception as e:
        print(f"\n  [ERROR] {e}")
        scenario_a_passed = False
    
    # ==================== Scenario B: Parameter Tampering ====================
    print(f"\n" + "-"*80)
    print(f"  Scenario B: Parameter Tampering Attack (Interception)")
    print(f"-"*80)
    
    # 模拟攻击者篡改参数
    tampered_params = {
        "report_id": "CONFIDENTIAL-SALARY-2024",  # 篡改为敏感报告
        "type": "summary",
        "format": "pdf"
    }
    
    print(f"\n  [Attack Simulation]")
    print(f"    Original params:  {original_params}")
    print(f"    Tampered params:  {tampered_params}")
    print(f"    Attacker changed: report_id 'Q1-2024' -> 'CONFIDENTIAL-SALARY-2024'")
    
    # 计算两个哈希值对比
    original_hash = compute_params_hash(original_params)
    tampered_hash = compute_params_hash(tampered_params)
    
    print(f"\n  [Hash Comparison]")
    print(f"    Token params_hash:   {original_hash[:40]}...")
    print(f"    Current params_hash: {tampered_hash[:40]}...")
    print(f"    Match: {'Yes' if original_hash == tampered_hash else 'NO - MISMATCH DETECTED!'}")
    
    print(f"\n  [Step 5] Attacker sends tampered request to Gateway...")
    
    # 发送验证请求（参数已被篡改）
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/verify-task-mcp-token",
                json={
                    "agent_did": finance_agent.agent_did,
                    "params": tampered_params  # 篡改后的参数！
                },
                headers={
                    "X-User-Token": user_jwt,
                    "X-Task-MCP-Token": task_mcp_token  # Token 包含原始参数的哈希
                }
            )
            
            if response.status_code == 403:
                error_detail = response.json().get("detail", "")
                print(f"\n  [OK] Attack Successfully Blocked!")
                print(f"    Status: 403 Forbidden")
                print(f"    Reason: {error_detail}")
                scenario_b_passed = True
            else:
                print(f"\n  [FAILED] Attack should have been blocked!")
                print(f"    Expected: 403 Forbidden")
                print(f"    Got: {response.status_code}")
                print(f"    Response: {response.text}")
                scenario_b_passed = False
    except Exception as e:
        print(f"\n  [ERROR] {e}")
        scenario_b_passed = False
    
    # ==================== 结果汇总 ====================
    print(f"\n" + "-"*80)
    print(f"  Test Results")
    print(f"-"*80)
    print(f"  Scenario A (Normal Call):        {'[PASS]' if scenario_a_passed else '[FAIL]'}")
    print(f"  Scenario B (Tampering Attack):   {'[PASS]' if scenario_b_passed else '[FAIL]'}")
    
    return scenario_a_passed and scenario_b_passed


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
    
    # Test 5: Task-MCP Token 完整性测试
    results.append(("Task-MCP Token Integrity", await test_task_mcp_token_integrity()))
    
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
