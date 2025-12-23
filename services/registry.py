"""
Agent Registry Service
注册中心：管理 Agent 的公钥和元数据
"""

from typing import Dict, Optional
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend


class AgentRegistry:
    """Agent 注册中心，存储 Agent DID 到公钥的映射。"""
    
    def __init__(self):
        # 存储 Agent DID -> public_key 的映射
        self._agents: Dict[str, EllipticCurvePublicKey] = {}
        # 存储 Agent DID -> metadata 的映射
        self._agent_metadata: Dict[str, Dict] = {}
    
    def register_agent(
        self,
        agent_did: str,
        public_key: EllipticCurvePublicKey,
        metadata: Optional[Dict] = None
    ):
        """
        注册 Agent。
        
        Args:
            agent_did: Agent 的 DID 标识符
            public_key: Agent 的公钥
            metadata: Agent 的元数据 (可选)
        """
        self._agents[agent_did] = public_key
        self._agent_metadata[agent_did] = metadata or {}
        print(f"[Registry] Registered agent: {agent_did}")
    
    def get_public_key(self, agent_did: str) -> Optional[EllipticCurvePublicKey]:
        """
        获取 Agent 的公钥。
        
        Args:
            agent_did: Agent 的 DID 标识符
            
        Returns:
            Agent 的公钥，如果不存在则返回 None
        """
        return self._agents.get(agent_did)
    
    def get_agent_metadata(self, agent_did: str) -> Optional[Dict]:
        """获取 Agent 的元数据。"""
        return self._agent_metadata.get(agent_did)
    
    def is_registered(self, agent_did: str) -> bool:
        """检查 Agent 是否已注册。"""
        return agent_did in self._agents
    
    def list_agents(self) -> list[str]:
        """列出所有已注册的 Agent DID。"""
        return list(self._agents.keys())


# 全局注册中心实例
registry = AgentRegistry()

