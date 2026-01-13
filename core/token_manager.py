"""
Task-MCP Token Manager
基于论文 3.3.3 章节实现 Task-MCP Token 的生成与验证。

核心功能：
- 实现"用户身份"与"细粒度执行意图（参数哈希）"的三元绑定
- 使用 SM2 签名和 SM3 哈希（国密算法）

Token 载荷结构（对应论文表 3-2）：
{
    "jti": "task-mcp-uuid-xxx",           // Token 唯一标识
    "iss": "did:agent:fin_analyst",       // 签发者（Task Agent DID）
    "iat": 1767864000,                    // 签发时间
    "exp": 1767864300,                    // 过期时间
    "context": {
        "user_id": "User_C",              // 原始用户 ID（绑定用户身份）
        "clearance": 4,                   // 用户安全许可等级
        "session_id": "session_xxx"       // 关联会话
    },
    "intent": {
        "target": "urn:finance:report:Q1-2024",  // 目标资源 URN
        "action": "read"                          // 操作类型
    },
    "params_hash": "a3f2b8c1..."          // SM3(请求参数) 的哈希值
}
"""

import json
import time
import uuid
import base64
from typing import Dict, Any, Optional, Tuple
from dataclasses import dataclass, asdict

from gmssl import sm2, sm3, func


# Task Agent 的 SM2 密钥（演示用）
# 使用 gmssl 生成有效的 SM2 密钥对
# 注意：生产环境应为每个 Agent 生成独立的密钥对并安全存储

def _generate_sm2_keypair_for_agent(seed: str):
    """
    为 Agent 生成确定性的 SM2 密钥对。
    使用 seed 确保每次运行生成相同的密钥对。
    """
    import hashlib
    # 使用 seed 生成确定性的私钥
    hash_bytes = hashlib.sha256(seed.encode()).digest()
    private_key = hash_bytes.hex()
    
    # SM2 曲线参数（国密 SM2 推荐曲线）
    # 使用 gmssl 的 sm2 模块计算公钥
    # 由于 gmssl 不直接暴露公钥计算，我们使用签名验证来确保密钥对有效
    # 这里使用预计算的有效密钥对
    return private_key

# 使用固定的、经过验证的 SM2 密钥对
# 这些密钥对已通过 gmssl 验证可以正确签名和验签
AGENT_KEYS = {}

def _init_agent_keys():
    """初始化 Agent 密钥对 - 使用动态生成确保有效性"""
    global AGENT_KEYS
    
    # 定义各 Agent 的种子
    agent_seeds = {
        "did:agent:fin_analyst": "finance_agent_seed_2024",
        "did:agent:hr_archivist": "hr_agent_seed_2024",
        "did:agent:sales_assistant": "sales_agent_seed_2024"
    }
    
    for agent_did, seed in agent_seeds.items():
        import hashlib
        # 生成私钥
        private_key = hashlib.sha256(seed.encode()).hexdigest()
        
        # 使用 gmssl 计算公钥
        # SM2 的公钥 = 私钥 * G（椭圆曲线点乘）
        # gmssl 的 CryptSM2 在签名时会自动处理
        # 我们通过签名-验签测试来验证密钥对
        
        # 为了确保公钥正确，我们使用一个简化的方法：
        # 先签名，再从签名中提取/验证公钥
        # 但由于 gmssl 的限制，我们使用预定义的有效密钥对
        
        AGENT_KEYS[agent_did] = {
            "private_key": private_key,
            "public_key": None  # 将在首次使用时计算
        }

# 使用已知有效的 SM2 密钥对
# 这些是通过 gmssl 测试验证过的密钥对
AGENT_KEYS = {
    "did:agent:fin_analyst": {
        "private_key": "00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5",
        "public_key": "B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207"
    },
    "did:agent:hr_archivist": {
        "private_key": "00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5",
        "public_key": "B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207"
    },
    "did:agent:sales_assistant": {
        "private_key": "00B9AB0B828FF68872F21A837FC303668428DEA11DCD1B24429D0C99E24EED83D5",
        "public_key": "B9C9A6E04E9C91F7BA880429273747D7EF5DDEB0BB2FF6317EB00BEF331A83081A6994B8993F3F5D6EADDDB81872266C87C018FB4162F5AF347B483E24620207"
    }
}


@dataclass
class TaskMCPTokenContext:
    """Token 上下文：用户身份信息"""
    user_id: str           # 原始用户 ID (orig_sub)
    clearance: int         # 安全许可等级
    session_id: str        # 会话 ID


@dataclass
class TaskMCPTokenIntent:
    """Token 意图：执行目标"""
    target: str            # 目标资源 URN (如 urn:finance:report:Q1-2024)
    action: str            # 操作类型 (read, write, execute)


@dataclass
class TaskMCPTokenPayload:
    """Task-MCP Token 完整载荷结构"""
    jti: str                      # Token 唯一标识
    iss: str                      # 签发者 (Agent DID)
    iat: int                      # 签发时间
    exp: int                      # 过期时间
    context: TaskMCPTokenContext  # 用户上下文
    intent: TaskMCPTokenIntent    # 执行意图
    params_hash: str              # 请求参数哈希 (SM3)
    
    def to_dict(self) -> Dict[str, Any]:
        """转换为字典"""
        return {
            "jti": self.jti,
            "iss": self.iss,
            "iat": self.iat,
            "exp": self.exp,
            "context": asdict(self.context),
            "intent": asdict(self.intent),
            "params_hash": self.params_hash
        }
    
    def to_json(self) -> str:
        """序列化为 JSON"""
        return json.dumps(self.to_dict(), separators=(',', ':'), sort_keys=True)
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TaskMCPTokenPayload':
        """从字典创建"""
        return cls(
            jti=data["jti"],
            iss=data["iss"],
            iat=data["iat"],
            exp=data["exp"],
            context=TaskMCPTokenContext(**data["context"]),
            intent=TaskMCPTokenIntent(**data["intent"]),
            params_hash=data["params_hash"]
        )


def base64url_encode(data: bytes) -> str:
    """Base64 URL 安全编码"""
    return base64.urlsafe_b64encode(data).rstrip(b'=').decode('utf-8')


def base64url_decode(data: str) -> bytes:
    """Base64 URL 安全解码"""
    padding = 4 - len(data) % 4
    if padding != 4:
        data += '=' * padding
    return base64.urlsafe_b64decode(data)


def compute_params_hash(params: Dict[str, Any]) -> str:
    """
    使用 SM3 算法计算请求参数的哈希值。
    
    Args:
        params: 请求参数字典
        
    Returns:
        SM3 哈希值（十六进制字符串）
    """
    # 将参数序列化为确定性 JSON（排序 keys）
    params_json = json.dumps(params, separators=(',', ':'), sort_keys=True)
    params_bytes = params_json.encode('utf-8')
    
    # 使用 SM3 计算哈希
    hash_bytes = sm3.sm3_hash(func.bytes_to_list(params_bytes))
    return hash_bytes


def create_task_mcp_token(
    agent_did: str,
    user_id: str,
    clearance: int,
    session_id: str,
    target: str,
    action: str,
    params: Dict[str, Any],
    expires_in: int = 300,  # 默认 5 分钟有效期
    verbose: bool = False
) -> Tuple[str, Dict[str, Any]]:
    """
    创建 Task-MCP Token。
    
    由 Task Agent 调用，将用户身份与执行意图绑定。
    
    Args:
        agent_did: Agent DID（签发者）
        user_id: 用户 ID（来自用户会话 JWT）
        clearance: 用户安全许可等级
        session_id: 会话 ID
        target: 目标资源 URN
        action: 操作类型
        params: 请求参数（用于计算哈希）
        expires_in: 有效期（秒）
        verbose: 是否输出详细信息
        
    Returns:
        (token_string, details) - Token 字符串和签发详情
    """
    details = {"steps": []}
    
    # Step 1: 计算参数哈希
    params_hash = compute_params_hash(params)
    
    if verbose:
        details["steps"].append({
            "step": 1,
            "name": "Compute Params Hash (SM3)",
            "params": params,
            "hash": params_hash[:32] + "..."
        })
    
    # Step 2: 构建 Token Payload
    now = int(time.time())
    payload = TaskMCPTokenPayload(
        jti=f"task-mcp-{uuid.uuid4().hex[:12]}",
        iss=agent_did,
        iat=now,
        exp=now + expires_in,
        context=TaskMCPTokenContext(
            user_id=user_id,
            clearance=clearance,
            session_id=session_id
        ),
        intent=TaskMCPTokenIntent(
            target=target,
            action=action
        ),
        params_hash=params_hash
    )
    
    if verbose:
        details["steps"].append({
            "step": 2,
            "name": "Build Token Payload",
            "payload": payload.to_dict()
        })
    
    # Step 3: 构建 JWT 结构
    header = {"alg": "SM2", "typ": "TaskMCP"}
    header_b64 = base64url_encode(json.dumps(header, separators=(',', ':')).encode('utf-8'))
    payload_b64 = base64url_encode(payload.to_json().encode('utf-8'))
    
    message = f"{header_b64}.{payload_b64}"
    
    if verbose:
        details["steps"].append({
            "step": 3,
            "name": "Build JWT Structure",
            "header": header
        })
    
    # Step 4: 使用 Agent 私钥签名 (SM2)
    agent_key = AGENT_KEYS.get(agent_did)
    if not agent_key:
        raise ValueError(f"Unknown agent: {agent_did}")
    
    sm2_crypt = sm2.CryptSM2(
        public_key=agent_key["public_key"],
        private_key=agent_key["private_key"]
    )
    
    signature = sm2_crypt.sign(message.encode('utf-8'), agent_key["private_key"])
    signature_b64 = base64url_encode(bytes.fromhex(signature))
    
    if verbose:
        details["steps"].append({
            "step": 4,
            "name": "Sign with Agent Private Key (SM2)",
            "agent_did": agent_did,
            "signature": signature[:40] + "..."
        })
    
    # Step 5: 组装完整 Token
    token = f"{header_b64}.{payload_b64}.{signature_b64}"
    
    if verbose:
        details["steps"].append({
            "step": 5,
            "name": "Assemble Token",
            "token_preview": token[:60] + "..."
        })
    
    details["token"] = token
    details["payload"] = payload.to_dict()
    details["params_hash"] = params_hash
    
    return token, details


def verify_task_mcp_token(
    token: str,
    agent_did: str,
    expected_user_id: str,
    current_params: Dict[str, Any],
    verbose: bool = False
) -> Tuple[bool, Optional[Dict[str, Any]], Dict[str, Any]]:
    """
    验证 Task-MCP Token（三元绑定检查）。
    
    网关调用此函数验证：
    1. Token 签名是否属于指定 Agent
    2. Token 中的 user_id 是否等于当前会话用户
    3. 当前参数哈希是否与 Token 中的 params_hash 匹配
    
    Args:
        token: Task-MCP Token 字符串
        agent_did: 预期的 Agent DID
        expected_user_id: 预期的用户 ID（从会话获取）
        current_params: 当前请求参数
        verbose: 是否输出详细信息
        
    Returns:
        (is_valid, payload_dict, details) - 验证结果、载荷、详情
    """
    details = {"steps": [], "errors": []}
    
    try:
        # Step 1: 解析 Token 结构
        parts = token.split('.')
        if len(parts) != 3:
            details["errors"].append("Invalid token format: expected 3 parts")
            return False, None, details
        
        header_b64, payload_b64, signature_b64 = parts
        
        if verbose:
            details["steps"].append({
                "step": 1,
                "name": "Parse Token Structure",
                "parts_count": 3
            })
        
        # Step 2: 解码 Header
        header = json.loads(base64url_decode(header_b64).decode('utf-8'))
        
        if header.get("alg") != "SM2" or header.get("typ") != "TaskMCP":
            details["errors"].append(f"Invalid header: {header}")
            return False, None, details
        
        if verbose:
            details["steps"].append({
                "step": 2,
                "name": "Verify Header",
                "header": header,
                "result": "[OK]"
            })
        
        # Step 3: 验证 Agent 签名 (SM2)
        agent_key = AGENT_KEYS.get(agent_did)
        if not agent_key:
            details["errors"].append(f"Unknown agent: {agent_did}")
            return False, None, details
        
        message = f"{header_b64}.{payload_b64}"
        signature_bytes = base64url_decode(signature_b64)
        signature_hex = signature_bytes.hex()
        
        sm2_crypt = sm2.CryptSM2(public_key=agent_key["public_key"], private_key="")
        
        try:
            sig_valid = sm2_crypt.verify(signature_hex, message.encode('utf-8'))
        except Exception:
            sig_valid = False
        
        if verbose:
            details["steps"].append({
                "step": 3,
                "name": "Verify Agent Signature (SM2)",
                "agent_did": agent_did,
                "result": "[OK]" if sig_valid else "[FAIL]"
            })
        
        if not sig_valid:
            details["errors"].append("Agent signature verification failed")
            return False, None, details
        
        # Step 4: 解码 Payload
        payload_json = base64url_decode(payload_b64).decode('utf-8')
        payload_dict = json.loads(payload_json)
        payload = TaskMCPTokenPayload.from_dict(payload_dict)
        
        if verbose:
            details["steps"].append({
                "step": 4,
                "name": "Decode Payload",
                "issuer": payload.iss,
                "jti": payload.jti
            })
        
        # Step 5: 验证签发者
        if payload.iss != agent_did:
            details["errors"].append(f"Issuer mismatch: expected {agent_did}, got {payload.iss}")
            return False, None, details
        
        if verbose:
            details["steps"].append({
                "step": 5,
                "name": "Verify Issuer",
                "expected": agent_did,
                "actual": payload.iss,
                "result": "[OK]"
            })
        
        # Step 6: 验证有效期
        now = int(time.time())
        if now > payload.exp:
            details["errors"].append(f"Token expired at {payload.exp}")
            return False, None, details
        
        if verbose:
            details["steps"].append({
                "step": 6,
                "name": "Verify Expiry",
                "remaining_seconds": payload.exp - now,
                "result": "[OK]"
            })
        
        # Step 7: 验证用户身份绑定 (orig_sub)
        token_user_id = payload.context.user_id
        if token_user_id != expected_user_id:
            details["errors"].append(
                f"User identity mismatch: token contains '{token_user_id}', "
                f"but session user is '{expected_user_id}'"
            )
            if verbose:
                details["steps"].append({
                    "step": 7,
                    "name": "Verify User Identity Binding",
                    "token_user": token_user_id,
                    "session_user": expected_user_id,
                    "result": "[FAIL] User Identity Mismatch"
                })
            return False, None, details
        
        if verbose:
            details["steps"].append({
                "step": 7,
                "name": "Verify User Identity Binding",
                "token_user": token_user_id,
                "session_user": expected_user_id,
                "result": "[OK]"
            })
        
        # Step 8: 验证参数完整性 (params_hash) - 关键检查！
        current_hash = compute_params_hash(current_params)
        token_hash = payload.params_hash
        
        if current_hash != token_hash:
            details["errors"].append(
                f"Parameter integrity violation: hash mismatch. "
                f"Parameters may have been tampered with."
            )
            if verbose:
                details["steps"].append({
                    "step": 8,
                    "name": "Verify Parameter Integrity (params_hash)",
                    "token_hash": token_hash[:32] + "...",
                    "current_hash": current_hash[:32] + "...",
                    "result": "[FAIL] Parameter Integrity Violation"
                })
            return False, None, details
        
        if verbose:
            details["steps"].append({
                "step": 8,
                "name": "Verify Parameter Integrity (params_hash)",
                "token_hash": token_hash[:32] + "...",
                "current_hash": current_hash[:32] + "...",
                "result": "[OK] Hashes Match"
            })
        
        # 所有检查通过
        details["verified"] = True
        details["payload"] = payload_dict
        
        return True, payload_dict, details
        
    except Exception as e:
        details["errors"].append(f"Verification error: {str(e)}")
        return False, None, details


def get_agent_public_key(agent_did: str) -> Optional[str]:
    """获取 Agent 的公钥"""
    key = AGENT_KEYS.get(agent_did)
    return key["public_key"] if key else None


def get_agent_private_key(agent_did: str) -> Optional[str]:
    """获取 Agent 的私钥（仅供 Agent 内部使用）"""
    key = AGENT_KEYS.get(agent_did)
    return key["private_key"] if key else None


# ==================== 旧版兼容接口 ====================

class TaskMCPToken:
    """旧版 Token 类（保留兼容）"""
    
    def __init__(self, iss: str, sub: str, target_tool: str, nonce: str = None, timestamp: int = None):
        import secrets
        self.iss = iss
        self.sub = sub
        self.target_tool = target_tool
        self.nonce = nonce or secrets.token_hex(8)
        self.timestamp = timestamp or int(time.time())
    
    def to_dict(self):
        return {
            "iss": self.iss,
            "sub": self.sub,
            "target_tool": self.target_tool,
            "nonce": self.nonce,
            "timestamp": self.timestamp
        }
    
    def to_json(self):
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))
    
    @classmethod
    def from_dict(cls, data):
        return cls(
            iss=data["iss"],
            sub=data["sub"],
            target_tool=data["target_tool"],
            nonce=data.get("nonce"),
            timestamp=data.get("timestamp")
        )


def create_task_token(agent_did: str, user_id: str, tool_name: str, private_key) -> Dict[str, str]:
    """旧版创建 Token 函数（保留兼容）"""
    token = TaskMCPToken(iss=agent_did, sub=user_id, target_tool=tool_name)
    payload_json = token.to_json()
    
    import base64
    payload_encoded = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')
    
    return {
        "payload": payload_encoded,
        "signature": "legacy_signature"
    }


def verify_task_token(token_payload: str, signature: str, public_key) -> Tuple[bool, Optional[TaskMCPToken]]:
    """旧版验证 Token 函数（保留兼容）"""
    try:
        import base64
        payload_json = base64.b64decode(token_payload.encode('utf-8')).decode('utf-8')
        token = TaskMCPToken.from_json(payload_json)
        return True, token
    except Exception:
        return False, None


def decode_task_token_payload(token_payload: str) -> Optional[TaskMCPToken]:
    """旧版解码函数（保留兼容）"""
    try:
        import base64
        payload_json = base64.b64decode(token_payload.encode('utf-8')).decode('utf-8')
        data = json.loads(payload_json)
        return TaskMCPToken.from_dict(data)
    except Exception:
        return None
