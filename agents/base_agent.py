"""
Agent Base Class
Agent 基类，定义 Agent 的基本行为和接口
"""

from abc import ABC, abstractmethod
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePrivateKey

from core.crypto import KeyPair
from core.token_manager import create_task_token


class BaseAgent(ABC):
    """Agent 基类。"""
    
    def __init__(self, agent_did: str, key_pair: Optional[KeyPair] = None):
        """
        初始化 Agent。
        
        Args:
            agent_did: Agent 的 DID 标识符
            key_pair: 密钥对，如果为 None 则自动生成
        """
        self.agent_did = agent_did
        self.key_pair = key_pair or KeyPair()
        self._private_key = self.key_pair.private_key
    
    @property
    def public_key(self):
        """获取 Agent 的公钥。"""
        return self.key_pair.public_key
    
    def create_task_token_for_user(
        self,
        user_id: str,
        tool_name: str
    ) -> Dict[str, str]:
        """
        为用户创建 Task-MCP Token。
        
        Args:
            user_id: 用户 ID
            tool_name: 目标工具名称
            
        Returns:
            包含 payload 和 signature 的字典
        """
        return create_task_token(
            agent_did=self.agent_did,
            user_id=user_id,
            tool_name=tool_name,
            private_key=self._private_key
        )
    
    @abstractmethod
    async def execute_task(self, user_id: str, task_description: str) -> Dict[str, Any]:
        """
        执行任务（抽象方法，由子类实现）。
        
        Args:
            user_id: 用户 ID
            task_description: 任务描述
            
        Returns:
            任务执行结果
        """
        pass

