"""
SM2 JWT 工具
基于国密 SM2 算法的 JWT 签发和验签

遵循 RFC 7519 标准，签名算法采用国密 SM2 非对称加密算法。

Payload 字段定义：
- 标准声明: iss (签发者), sub (用户ID), iat (签发时间), exp (过期时间)
- 业务属性: dept (部门), role (角色)
- 安全属性: clearance (安全许可等级, 1-5)
"""

import json
import base64
import time
from typing import Dict, Optional, Tuple
from dataclasses import dataclass
from gmssl import sm2, func


# 身份认证中心的 SM2 密钥对（演示用，生产环境应安全存储）
# 这里使用固定的密钥对，确保网关可以验证
AUTH_CENTER_PRIVATE_KEY = "00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5"
AUTH_CENTER_PUBLIC_KEY = "B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207"

# 签发者标识
ISSUER = "Enterprise_Auth_Center"


@dataclass
class UserJWTPayload:
    """用户会话 JWT Payload 结构"""
    iss: str           # 签发者标识
    sub: str           # 用户唯一标识 (Subject.id)
    iat: int           # 签发时间戳
    exp: int           # 过期时间戳 (Environment)
    dept: str          # 所属部门 (Subject.department)
    role: str          # 职能角色 (Subject.role)
    clearance: int     # 安全许可等级 1-5 (Subject.security_clearance)


def base64url_encode(data: bytes) -> str:
    """Base64 URL 安全编码（无填充）"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """Base64 URL 安全解码"""
    # 添加填充
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def create_sm2_jwt(
    sub: str,
    dept: str,
    role: str,
    clearance: int,
    expires_in: int = 3600,
    private_key: str = AUTH_CENTER_PRIVATE_KEY,
    verbose: bool = False
) -> Tuple[str, Dict]:
    """
    使用 SM2 算法签发用户会话 JWT。
    
    Args:
        sub: 用户唯一标识
        dept: 所属部门 (Sales, HR, Finance, IT, R&D)
        role: 职能角色 (Manager, Employee, Intern, Director)
        clearance: 安全许可等级 (1-5, 5为绝密)
        expires_in: 过期时间（秒），默认1小时
        private_key: SM2 私钥（十六进制字符串）
        verbose: 是否输出详细过程
        
    Returns:
        (jwt_token, details) - JWT Token 字符串和签发详情
    """
    details = {"steps": []}
    
    # Step 1: 构建 Header
    header = {
        "alg": "SM2",
        "typ": "JWT"
    }
    header_json = json.dumps(header, separators=(',', ':'))
    header_b64 = base64url_encode(header_json.encode('utf-8'))
    
    if verbose:
        details["steps"].append({
            "step": 1,
            "name": "Build JWT Header",
            "header": header,
            "header_base64": header_b64
        })
    
    # Step 2: 构建 Payload
    now = int(time.time())
    payload = {
        "iss": ISSUER,
        "sub": sub,
        "iat": now,
        "exp": now + expires_in,
        "dept": dept,
        "role": role,
        "clearance": clearance
    }
    payload_json = json.dumps(payload, separators=(',', ':'))
    payload_b64 = base64url_encode(payload_json.encode('utf-8'))
    
    if verbose:
        details["steps"].append({
            "step": 2,
            "name": "Build JWT Payload (User Attributes)",
            "payload": payload,
            "payload_base64": payload_b64,
            "abac_mapping": {
                "Subject.id": sub,
                "Subject.department": dept,
                "Subject.role": role,
                "Subject.security_clearance": clearance,
                "Environment.time": now
            }
        })
    
    # Step 3: 使用 SM2 生成签名
    message = f"{header_b64}.{payload_b64}"
    message_bytes = message.encode('utf-8')
    
    # 创建 SM2 加密机实例
    sm2_crypt = sm2.CryptSM2(public_key=AUTH_CENTER_PUBLIC_KEY, private_key=private_key)
    
    # 使用 SM2 签名
    signature = sm2_crypt.sign(message_bytes, AUTH_CENTER_PRIVATE_KEY)
    signature_b64 = base64url_encode(bytes.fromhex(signature))
    
    if verbose:
        details["steps"].append({
            "step": 3,
            "name": "Generate SM2 Signature",
            "algorithm": "SM2 (Asymmetric Encryption)",
            "message_to_sign": message,
            "signature_hex": signature[:64] + "...",  # truncated
            "signature_base64": signature_b64[:32] + "..."
        })
    
    # Step 4: 组装 JWT Token
    jwt_token = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    if verbose:
        details["steps"].append({
            "step": 4,
            "name": "Assemble JWT Token",
            "structure": {
                "header": header_b64,
                "payload": payload_b64,
                "signature": signature_b64[:32] + "..."
            },
            "token_preview": jwt_token[:80] + "..."
        })
    
    details["token"] = jwt_token
    details["payload"] = payload
    
    return jwt_token, details


def verify_sm2_jwt(
    token: str,
    public_key: str = AUTH_CENTER_PUBLIC_KEY,
    verbose: bool = False
) -> Tuple[bool, Optional[Dict], Dict]:
    """
    验证 SM2 签名的 JWT。
    
    Args:
        token: JWT Token 字符串
        public_key: SM2 公钥（十六进制字符串）
        verbose: 是否输出详细过程
        
    Returns:
        (is_valid, payload, details) - 验证结果、Payload、验证详情
    """
    details = {"steps": [], "errors": []}
    
    try:
        # Step 1: 解析 JWT 结构
        parts = token.split('.')
        if len(parts) != 3:
            details["errors"].append("Invalid JWT format: expected 3 parts")
            return False, None, details
        
        header_b64, payload_b64, signature_b64 = parts
        
        if verbose:
            details["steps"].append({
                "step": 1,
                "name": "Parse JWT Structure",
                "parts": {
                    "header": header_b64[:20] + "...",
                    "payload": payload_b64[:30] + "...",
                    "signature": signature_b64[:20] + "..."
                }
            })
        
        # Step 2: 解码并验证 Header
        header_json = base64url_decode(header_b64).decode('utf-8')
        header = json.loads(header_json)
        
        if header.get("alg") != "SM2":
            details["errors"].append(f"Unsupported algorithm: {header.get('alg')}")
            return False, None, details
        
        if verbose:
            details["steps"].append({
                "step": 2,
                "name": "Decode Header & Verify Algorithm",
                "header": header,
                "algorithm_check": "SM2 [OK]"
            })
        
        # Step 3: 验证 SM2 签名
        message = f"{header_b64}.{payload_b64}"
        message_bytes = message.encode('utf-8')
        
        signature_bytes = base64url_decode(signature_b64)
        signature_hex = signature_bytes.hex()
        
        sm2_crypt = sm2.CryptSM2(public_key=public_key, private_key="")
        
        try:
            verify_result = sm2_crypt.verify(signature_hex, message_bytes)
        except Exception as e:
            details["errors"].append(f"Signature verification error: {str(e)}")
            verify_result = False
        
        if verbose:
            details["steps"].append({
                "step": 3,
                "name": "Verify SM2 Signature",
                "public_key": public_key[:32] + "...",
                "signature_valid": verify_result
            })
        
        if not verify_result:
            details["errors"].append("Signature verification failed")
            return False, None, details
        
        # Step 4: 解码 Payload
        payload_json = base64url_decode(payload_b64).decode('utf-8')
        payload = json.loads(payload_json)
        
        if verbose:
            details["steps"].append({
                "step": 4,
                "name": "Decode Payload",
                "payload": payload
            })
        
        # Step 5: 验证有效期
        now = int(time.time())
        exp = payload.get("exp", 0)
        
        if now > exp:
            details["errors"].append(f"Token expired at {exp}, current time is {now}")
            if verbose:
                details["steps"].append({
                    "step": 5,
                    "name": "Verify Expiry",
                    "current_time": now,
                    "expiry_time": exp,
                    "status": "EXPIRED [FAIL]"
                })
            return False, None, details
        
        if verbose:
            details["steps"].append({
                "step": 5,
                "name": "Verify Expiry",
                "current_time": now,
                "expiry_time": exp,
                "remaining_seconds": exp - now,
                "status": "NOT EXPIRED [OK]"
            })
        
        # Step 6: 提取用户属性
        user_attributes = {
            "Subject.id": payload.get("sub"),
            "Subject.department": payload.get("dept"),
            "Subject.role": payload.get("role"),
            "Subject.security_clearance": payload.get("clearance")
        }
        
        if verbose:
            details["steps"].append({
                "step": 6,
                "name": "Extract User Attributes (for ABAC)",
                "attributes": user_attributes
            })
        
        details["user_attributes"] = user_attributes
        return True, payload, details
        
    except Exception as e:
        details["errors"].append(f"Verification error: {str(e)}")
        return False, None, details


def get_auth_center_public_key() -> str:
    """获取身份认证中心的公钥（供网关使用）"""
    return AUTH_CENTER_PUBLIC_KEY


# 便捷函数：兼容旧接口
def create_user_jwt(
    uid: str,
    role: str,
    dept: str,
    clearance: int = 3
) -> str:
    """
    创建用户 JWT（兼容旧接口）。
    
    Args:
        uid: 用户ID（映射到 sub）
        role: 角色
        dept: 部门
        clearance: 安全许可等级，默认 3
        
    Returns:
        JWT Token 字符串
    """
    token, _ = create_sm2_jwt(
        sub=uid,
        dept=dept,
        role=role,
        clearance=clearance,
        verbose=False
    )
    return token

