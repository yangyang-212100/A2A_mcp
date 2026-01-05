"""
Agent Registry Service
注册中心：管理 Agent 的公钥和元数据
"""

from typing import Dict, Optional, List
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
        # 存储 Agent 类型 -> Agent DID 的映射
        self._agent_by_type: Dict[str, List[str]] = {}
    
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
            metadata: Agent 的元数据 (可选)，包含 type, capabilities 等
        """
        self._agents[agent_did] = public_key
        self._agent_metadata[agent_did] = metadata or {}
        
        # 如果有类型信息，建立类型索引
        if metadata and "type" in metadata:
            agent_type = metadata["type"]
            if agent_type not in self._agent_by_type:
                self._agent_by_type[agent_type] = []
            if agent_did not in self._agent_by_type[agent_type]:
                self._agent_by_type[agent_type].append(agent_did)
        
        print(f"[Registry] Registered agent: {agent_did} (type: {metadata.get('type', 'unknown') if metadata else 'unknown'})")
    
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
    
    def list_agents(self) -> List[str]:
        """列出所有已注册的 Agent DID。"""
        return list(self._agents.keys())
    
    def get_agents_by_type(self, agent_type: str) -> List[str]:
        """
        根据类型获取 Agent DID 列表。
        
        Args:
            agent_type: Agent 类型 (如 "finance", "hr", "sales")
            
        Returns:
            该类型的所有 Agent DID 列表
        """
        return self._agent_by_type.get(agent_type, [])
    
    def find_agent_for_task(self, task_type: str) -> Optional[str]:
        """
        根据任务类型查找合适的 Agent。
        
        Args:
            task_type: 任务类型 (如 "finance", "audit", "report")
            
        Returns:
            最合适的 Agent DID，如果没有找到则返回 None
        """
        # 任务类型到 Agent 类型的映射
        task_to_agent_type = {
            "finance": "finance",
            "audit": "finance",
            "report": "finance",
            "hr": "hr",
            "employee": "hr",
            "sales": "sales",
        }
        
        agent_type = task_to_agent_type.get(task_type.lower())
        if agent_type:
            agents = self.get_agents_by_type(agent_type)
            if agents:
                return agents[0]  # 返回第一个可用的 Agent
        
        return None
    
    def get_all_agent_info(self) -> List[Dict]:
        """获取所有 Agent 的信息（用于调试）。"""
        result = []
        for agent_did in self._agents:
            result.append({
                "did": agent_did,
                "metadata": self._agent_metadata.get(agent_did, {}),
                "registered": True
            })
        return result


# 全局注册中心实例
registry = AgentRegistry()
