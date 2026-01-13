"""
演示脚本 2: 用户会话 JWT 签发与验签过程展示
Demo Script 2: User Session JWT Issuance and Verification Display

本脚本演示：
1. 身份认证中心使用 SM2 算法签发用户会话 JWT
2. 网关对用户会话 JWT 进行 SM2 验签操作

JWT 结构符合 RFC 7519 标准，签名算法采用国密 SM2 非对称加密。

运行前请确保网关已启动:
    python -m services.gateway
"""

import asyncio
import httpx
from datetime import datetime
import json

from core.sm2_jwt import (
    create_sm2_jwt, 
    verify_sm2_jwt,
    AUTH_CENTER_PUBLIC_KEY,
    ISSUER
)


GATEWAY_URL = "http://localhost:8000"


def print_header():
    """打印演示标题。"""
    print("""
================================================================================
       User Session JWT Demo - SM2 Signature Algorithm (国密)
================================================================================

  本演示展示用户会话 JWT 的签发与验签过程：
  
  ┌─────────────────────────────────────────────────────────────────────┐
  │                    身份认证中心                                      │
  │              (Enterprise_Auth_Center)                               │
  │                                                                     │
  │   使用 SM2 私钥签发 JWT                                              │
  │   JWT = Header.Payload.Signature                                    │
  └───────────────────────────────┬─────────────────────────────────────┘
                                  │ JWT Token
                                  ▼
  ┌─────────────────────────────────────────────────────────────────────┐
  │                         网关                                        │
  │                      (Gateway)                                      │
  │                                                                     │
  │   使用身份认证中心公钥验证 SM2 签名                                   │
  │   提取用户属性用于 ABAC 决策                                         │
  └─────────────────────────────────────────────────────────────────────┘

================================================================================
""")


def demo_jwt_issuance():
    """演示 JWT 签发过程。"""
    print("""
================================================================================
                    Part 1: JWT 签发过程 (身份认证中心)
================================================================================
""")
    
    # 用户信息
    user_info = {
        "sub": "user_finance_director_01",
        "dept": "Finance",
        "role": "Director",
        "clearance": 4  # 安全许可等级 4 (可访问机密数据)
    }
    
    print(f"  用户信息:")
    print(f"  ┌─────────────────────────────────────────────────────────────┐")
    print(f"  │  用户ID:       {user_info['sub']:<43}│")
    print(f"  │  部门:         {user_info['dept']:<43}│")
    print(f"  │  角色:         {user_info['role']:<43}│")
    print(f"  │  安全许可等级: {user_info['clearance']} (1=公开, 5=绝密){' '*26}│")
    print(f"  └─────────────────────────────────────────────────────────────┘")
    print()
    
    # 签发 JWT
    print("  开始签发 JWT...")
    print()
    
    token, details = create_sm2_jwt(
        sub=user_info["sub"],
        dept=user_info["dept"],
        role=user_info["role"],
        clearance=user_info["clearance"],
        verbose=True
    )
    
    # 输出每个步骤
    for step in details["steps"]:
        step_num = step["step"]
        step_name = step["name"]
        
        print(f"  Step {step_num}: {step_name}")
        print(f"  {'─' * 65}")
        
        if step_num == 1:  # Header
            header = step.get("header", {})
            print(f"    Header (JSON):")
            print(f"    {{")
            print(f'      "alg": "{header.get("alg")}",    // 签名算法: 国密SM2')
            print(f'      "typ": "{header.get("typ")}"       // Token类型: JWT')
            print(f"    }}")
            print(f"    Header (Base64): {step.get('header_base64', '')}")
            
        elif step_num == 2:  # Payload
            payload = step.get("payload", {})
            print(f"    Payload (用户属性):")
            print(f"    {{")
            print(f'      "iss": "{payload.get("iss")}",')
            print(f'      "sub": "{payload.get("sub")}",')
            print(f'      "iat": {payload.get("iat")},')
            print(f'      "exp": {payload.get("exp")},')
            print(f'      "dept": "{payload.get("dept")}",      // 部门 → Subject.department')
            print(f'      "role": "{payload.get("role")}",   // 角色 → Subject.role')
            print(f'      "clearance": {payload.get("clearance")}          // 许可等级 → Subject.security_clearance')
            print(f"    }}")
            
        elif step_num == 3:  # Signature
            print(f"    算法: {step.get('algorithm', 'SM2')}")
            print(f"    待签名数据: {step.get('message_to_sign', '')[:60]}...")
            print(f"    SM2签名: {step.get('signature_hex', '')}")
            
        elif step_num == 4:  # 组装
            structure = step.get("structure", {})
            print(f"    JWT 结构:")
            print(f"    ┌─────────────────────────────────────────────────────────┐")
            print(f"    │  Header:    {structure.get('header', '')[:45]}... │")
            print(f"    │  Payload:   {structure.get('payload', '')[:45]}... │")
            print(f"    │  Signature: {structure.get('signature', '')[:45]}  │")
            print(f"    └─────────────────────────────────────────────────────────┘")
        
        print()
    
    # 显示最终 Token
    print(f"  签发完成!")
    print(f"  ┌─────────────────────────────────────────────────────────────┐")
    print(f"  │  JWT Token (完整):                                          │")
    print(f"  │  {token[:60]}...│")
    print(f"  │                                                             │")
    print(f"  │  Token 长度: {len(token)} 字符                                      │")
    print(f"  └─────────────────────────────────────────────────────────────┘")
    print()
    
    return token


def demo_jwt_verification(token: str):
    """演示 JWT 验签过程。"""
    print("""
================================================================================
                    Part 2: JWT 验签过程 (网关)
================================================================================
""")
    
    print(f"  收到的 JWT Token: {token[:50]}...")
    print()
    print(f"  使用身份认证中心公钥进行 SM2 验签...")
    print(f"  公钥: {AUTH_CENTER_PUBLIC_KEY[:32]}...")
    print()
    
    # 验证 JWT
    is_valid, payload, details = verify_sm2_jwt(token, verbose=True)
    
    # 输出每个步骤
    for step in details["steps"]:
        step_num = step["step"]
        step_name = step["name"]
        
        print(f"  Step {step_num}: {step_name}")
        print(f"  {'─' * 65}")
        
        if step_num == 1:  # 解析结构
            parts = step.get("parts", {})
            print(f"    解析 JWT 为三部分:")
            print(f"    - Header:    {parts.get('header', '')}")
            print(f"    - Payload:   {parts.get('payload', '')}")
            print(f"    - Signature: {parts.get('signature', '')}")
            
        elif step_num == 2:  # 验证算法
            header = step.get("header", {})
            print(f"    解码 Header: {header}")
            alg_check = step.get('algorithm_check', '').replace('✓', '[OK]').replace('✗', '[FAIL]')
            print(f"    算法检查: {alg_check}")
            
        elif step_num == 3:  # 验证签名
            print(f"    使用公钥: {step.get('public_key', '')}")
            sig_valid = step.get("signature_valid", False)
            status = "[OK] 签名有效" if sig_valid else "[FAILED] 签名无效"
            print(f"    签名验证结果: {status}")
            
        elif step_num == 4:  # 解码 Payload
            payload_data = step.get("payload", {})
            print(f"    解码 Payload:")
            for key, value in payload_data.items():
                print(f"      {key}: {value}")
                
        elif step_num == 5:  # 验证有效期
            current = step.get("current_time", 0)
            expiry = step.get("expiry_time", 0)
            remaining = step.get("remaining_seconds", 0)
            status = step.get("status", "").replace('✓', '[OK]').replace('✗', '[FAIL]')
            print(f"    当前时间: {current} ({datetime.fromtimestamp(current).strftime('%Y-%m-%d %H:%M:%S')})")
            print(f"    过期时间: {expiry} ({datetime.fromtimestamp(expiry).strftime('%Y-%m-%d %H:%M:%S')})")
            print(f"    剩余时间: {remaining} 秒")
            print(f"    状态: {status}")
            
        elif step_num == 6:  # 提取属性
            attrs = step.get("attributes", {})
            print(f"    提取用户属性 (用于 ABAC 决策):")
            print(f"    ┌───────────────────────────────────────────────────────┐")
            for key, value in attrs.items():
                print(f"    │  {key:30} = {str(value):20} │")
            print(f"    └───────────────────────────────────────────────────────┘")
        
        print()
    
    # 最终结果
    status = "[OK] 验证通过" if is_valid else "[FAILED] 验证失败"
    print(f"  验签结果: {status}")
    print()
    
    if is_valid:
        print(f"  用户身份已确认，可进行 ABAC 策略评估:")
        print(f"  ┌─────────────────────────────────────────────────────────────┐")
        print(f"  │  Subject.id:                 {payload.get('sub'):<30}│")
        print(f"  │  Subject.department:         {payload.get('dept'):<30}│")
        print(f"  │  Subject.role:               {payload.get('role'):<30}│")
        print(f"  │  Subject.security_clearance: {payload.get('clearance'):<30}│")
        print(f"  └─────────────────────────────────────────────────────────────┘")
    
    return is_valid


async def demo_gateway_verification(token: str):
    """演示通过网关验证 JWT。"""
    print("""
================================================================================
                    Part 3: 实际网关验证 (HTTP 请求)
================================================================================
""")
    
    print(f"  发送 HTTP 请求到网关...")
    print(f"  POST {GATEWAY_URL}/gateway/user-request")
    print(f"  Headers: X-User-Token: {token[:40]}...")
    print()
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/user-request",
                json={"query": "请执行财务审计"},
                headers={"X-User-Token": token}
            )
            
            print(f"  响应状态码: {response.status_code}")
            print()
            
            if response.status_code == 200:
                result = response.json()
                print(f"  [SUCCESS] JWT 验证通过!")
                print(f"  ┌─────────────────────────────────────────────────────────────┐")
                print(f"  │  Session ID: {result.get('session_id', 'N/A'):<46}│")
                print(f"  │  User ID:    {result.get('user_id', 'N/A'):<46}│")
                user_info = result.get('user_info', {})
                print(f"  │  Department: {user_info.get('dept', 'N/A'):<46}│")
                print(f"  │  Role:       {user_info.get('role', 'N/A'):<46}│")
                print(f"  └─────────────────────────────────────────────────────────────┘")
                return True
            else:
                print(f"  [FAILED] 网关拒绝请求")
                print(f"  响应: {response.text}")
                return False
                
    except Exception as e:
        print(f"  [ERROR] 无法连接到网关: {e}")
        print(f"  请确保网关已启动: python -m services.gateway")
        return False


def demo_invalid_jwt():
    """演示无效 JWT 的验证失败。"""
    print("""
================================================================================
                    Part 4: 无效 JWT 验证 (安全测试)
================================================================================
""")
    
    print("  测试场景: 篡改后的 JWT Token")
    print()
    
    # 创建一个有效的 JWT
    token, _ = create_sm2_jwt(
        sub="user_test",
        dept="Sales",
        role="Employee",
        clearance=2,
        verbose=False
    )
    
    # 篡改 Payload（模拟攻击者修改权限）
    parts = token.split('.')
    # 随机修改 payload 部分
    tampered_payload = parts[1][:-5] + "XXXXX"
    tampered_token = f"{parts[0]}.{tampered_payload}.{parts[2]}"
    
    print(f"  原始 Token: {token[:50]}...")
    print(f"  篡改 Token: {tampered_token[:50]}...")
    print()
    print("  验证篡改后的 Token...")
    print()
    
    is_valid, payload, details = verify_sm2_jwt(tampered_token, verbose=False)
    
    if not is_valid:
        print("  [SUCCESS] 系统正确检测到 Token 被篡改!")
        print(f"  错误信息: {details.get('errors', [])}")
    else:
        print("  [WARNING] 未能检测到篡改!")
    
    print()


async def main():
    """主函数：演示 JWT 签发和验签过程。"""
    print_header()
    
    # 检查网关是否运行
    print(f"[{datetime.now().strftime('%H:%M:%S')}] 检查网关状态...")
    gateway_running = False
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{GATEWAY_URL}/gateway/health")
            if response.status_code == 200:
                gateway_running = True
                print(f"[{datetime.now().strftime('%H:%M:%S')}] 网关运行中: {GATEWAY_URL}")
    except Exception:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] 网关未运行 (部分演示将跳过)")
    
    print()
    
    # Part 1: JWT 签发
    token = demo_jwt_issuance()
    
    # Part 2: JWT 验签 (本地)
    demo_jwt_verification(token)
    
    # Part 3: 网关验证 (如果网关运行中)
    if gateway_running:
        await demo_gateway_verification(token)
    else:
        print("""
================================================================================
                    Part 3: 实际网关验证 (已跳过)
================================================================================

  网关未运行，跳过此部分。
  启动网关后可运行完整演示: python -m services.gateway
""")
    
    # Part 4: 无效 JWT 测试
    demo_invalid_jwt()
    
    print("""
================================================================================
                              Demo Complete!
================================================================================

""")


if __name__ == "__main__":
    asyncio.run(main())

