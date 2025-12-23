"""
Task-MCP Token Manager
负责生成和解析 Task-MCP Token 结构，实现 User身份 与 Agent意图 的绑定。
"""

import json
import time
import secrets
from typing import Dict, Any, Optional, Tuple
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey, EllipticCurvePublicKey

from core.crypto import sign, verify


class TaskMCPToken:
    """
    Task-MCP Token 结构
    
    Payload 结构:
    {
        "iss": "did:agent:fin_analyst",  # Agent DID
        "sub": "User_C",                 # 绑定的用户 ID (关键！身份绑定)
        "target_tool": "urn:mcp:audit",  # 调用的目标工具
        "nonce": "r8s9d7",               # 防重放随机数
        "timestamp": 1712345678          # 时间戳 (用于 ABAC 时间策略)
    }
    """
    
    def __init__(
        self,
        iss: str,
        sub: str,
        target_tool: str,
        nonce: Optional[str] = None,
        timestamp: Optional[int] = None
    ):
        self.iss = iss  # Agent DID
        self.sub = sub  # 绑定的用户 ID
        self.target_tool = target_tool  # 目标工具
        self.nonce = nonce or secrets.token_hex(8)  # 随机 nonce
        self.timestamp = timestamp or int(time.time())  # 当前时间戳
    
    def to_dict(self) -> Dict[str, Any]:
        """Convert token to dictionary."""
        return {
            "iss": self.iss,
            "sub": self.sub,
            "target_tool": self.target_tool,
            "nonce": self.nonce,
            "timestamp": self.timestamp
        }
    
    def to_json(self) -> str:
        """Serialize token payload to JSON string."""
        return json.dumps(self.to_dict(), sort_keys=True, separators=(',', ':'))
    
    @classmethod
    def from_dict(cls, data: Dict[str, Any]) -> 'TaskMCPToken':
        """Create TaskMCPToken from dictionary."""
        return cls(
            iss=data["iss"],
            sub=data["sub"],
            target_tool=data["target_tool"],
            nonce=data.get("nonce"),
            timestamp=data.get("timestamp")
        )
    
    @classmethod
    def from_json(cls, json_str: str) -> 'TaskMCPToken':
        """Create TaskMCPToken from JSON string."""
        data = json.loads(json_str)
        return cls.from_dict(data)


def create_task_token(
    agent_did: str,
    user_id: str,
    tool_name: str,
    private_key: EllipticCurvePrivateKey
) -> Dict[str, str]:
    """
    构造 Task-MCP Token Payload 并签名。
    
    Args:
        agent_did: Agent 的 DID 标识符 (e.g., "did:agent:fin_analyst")
        user_id: 绑定的用户 ID (e.g., "User_C")
        tool_name: 目标工具名称 (e.g., "urn:mcp:audit")
        private_key: Agent 的私钥
        
    Returns:
        包含 payload 和 signature 的字典:
        {
            "payload": "base64_encoded_json",
            "signature": "base64_encoded_signature"
        }
    """
    # 创建 Token 对象
    token = TaskMCPToken(
        iss=agent_did,
        sub=user_id,
        target_tool=tool_name
    )
    
    # 序列化 payload 为 JSON 字符串 (使用紧凑格式，确保一致性)
    payload_json = token.to_json()
    
    # 使用 Agent 私钥签名
    signature = sign(payload_json, private_key)
    
    # 返回 payload 和 signature
    # 实际传输时，payload 也进行 base64 编码以便传输
    import base64
    payload_encoded = base64.b64encode(payload_json.encode('utf-8')).decode('utf-8')
    
    return {
        "payload": payload_encoded,
        "signature": signature
    }


def verify_task_token(
    token_payload: str,
    signature: str,
    public_key: EllipticCurvePublicKey
) -> Tuple[bool, Optional[TaskMCPToken]]:
    """
    验证 Task-MCP Token 的签名并解析 Payload。
    
    Args:
        token_payload: Base64 编码的 JSON payload
        signature: Base64 编码的签名
        public_key: Agent 的公钥
        
    Returns:
        (is_valid, token_object) 元组
        - is_valid: 签名是否有效
        - token_object: 解析后的 TaskMCPToken 对象，如果验证失败则为 None
    """
    try:
        # 解码 payload
        import base64
        payload_json = base64.b64decode(token_payload.encode('utf-8')).decode('utf-8')
        
        # 验证签名
        is_valid = verify(payload_json, signature, public_key)
        
        if not is_valid:
            return False, None
        
        # 解析 payload
        token = TaskMCPToken.from_json(payload_json)
        
        return True, token
    except Exception as e:
        print(f"Token verification error: {e}")
        return False, None


def decode_task_token_payload(token_payload: str) -> Optional[TaskMCPToken]:
    """
    仅解码 Token Payload，不进行签名验证。
    用于在网关中先解析再验证的场景。
    
    Args:
        token_payload: Base64 编码的 JSON payload
        
    Returns:
        TaskMCPToken 对象，如果解析失败则为 None
    """
    try:
        import base64
        payload_json = base64.b64decode(token_payload.encode('utf-8')).decode('utf-8')
        return TaskMCPToken.from_json(payload_json)
    except Exception as e:
        print(f"Token payload decode error: {e}")
        return None

