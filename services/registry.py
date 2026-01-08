"""
Agent Registry Service
注册中心：管理 Agent 的公钥、元数据和属性信息

Agent 属性包括：
- DID: 唯一标识符
- type: Agent 类型 (finance, hr, sales)
- owner: 归属部门 (Finance, HR, Sales)
- sensitivity: 敏感度/密级 (Internal, Confidential, TopSecret)
- capabilities: 能力列表
"""

from typing import Dict, Optional, List
from cryptography.hazmat.primitives.asymmetric.ec import EllipticCurvePublicKey
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.backends import default_backend
from datetime import datetime


class AgentRegistry:
    """Agent 注册中心，存储 Agent DID 到公钥的映射。"""
    
    def __init__(self):
        # 存储 Agent DID -> public_key 的映射
        self._agents: Dict[str, EllipticCurvePublicKey] = {}
        # 存储 Agent DID -> metadata 的映射
        self._agent_metadata: Dict[str, Dict] = {}
        # 存储 Agent 类型 -> Agent DID 的映射
        self._agent_by_type: Dict[str, List[str]] = {}
        # 存储 Agent 注册时间
        self._registration_time: Dict[str, datetime] = {}
    
    def register_agent(
        self,
        agent_did: str,
        public_key: EllipticCurvePublicKey,
        metadata: Optional[Dict] = None
    ) -> Dict:
        """
        注册 Agent。
        
        Args:
            agent_did: Agent 的 DID 标识符
            public_key: Agent 的公钥
            metadata: Agent 的元数据，包含 type, owner, sensitivity, capabilities 等
            
        Returns:
            注册结果信息
        """
        self._agents[agent_did] = public_key
        self._agent_metadata[agent_did] = metadata or {}
        self._registration_time[agent_did] = datetime.now()
        
        # 如果有类型信息，建立类型索引
        if metadata and "type" in metadata:
            agent_type = metadata["type"]
            if agent_type not in self._agent_by_type:
                self._agent_by_type[agent_type] = []
            if agent_did not in self._agent_by_type[agent_type]:
                self._agent_by_type[agent_type].append(agent_did)
        
        # 构建详细的注册信息
        registration_info = {
            "did": agent_did,
            "type": metadata.get("type", "unknown") if metadata else "unknown",
            "owner": metadata.get("owner", "unknown") if metadata else "unknown",
            "sensitivity": metadata.get("sensitivity", "unknown") if metadata else "unknown",
            "capabilities": metadata.get("capabilities", []) if metadata else [],
            "registered_at": self._registration_time[agent_did].isoformat()
        }
        
        return registration_info
    
    def get_public_key(self, agent_did: str) -> Optional[EllipticCurvePublicKey]:
        """获取 Agent 的公钥。"""
        return self._agents.get(agent_did)
    
    def get_agent_metadata(self, agent_did: str) -> Optional[Dict]:
        """获取 Agent 的元数据。"""
        return self._agent_metadata.get(agent_did)
    
    def get_agent_attributes(self, agent_did: str) -> Optional[Dict]:
        """
        获取 Agent 的属性信息（用于 PIP 属性检索）。
        
        Returns:
            包含 owner, sensitivity, type 等属性的字典
        """
        metadata = self._agent_metadata.get(agent_did)
        if not metadata:
            return None
        
        return {
            "did": agent_did,
            "type": metadata.get("type"),
            "owner": metadata.get("owner"),
            "sensitivity": metadata.get("sensitivity"),
            "capabilities": metadata.get("capabilities", [])
        }
    
    def is_registered(self, agent_did: str) -> bool:
        """检查 Agent 是否已注册。"""
        return agent_did in self._agents
    
    def list_agents(self) -> List[str]:
        """列出所有已注册的 Agent DID。"""
        return list(self._agents.keys())
    
    def get_agents_by_type(self, agent_type: str) -> List[str]:
        """根据类型获取 Agent DID 列表。"""
        return self._agent_by_type.get(agent_type, [])
    
    def get_agents_by_sensitivity(self, sensitivity: str) -> List[str]:
        """根据敏感度获取 Agent DID 列表。"""
        result = []
        for agent_did, metadata in self._agent_metadata.items():
            if metadata.get("sensitivity") == sensitivity:
                result.append(agent_did)
        return result
    
    def get_agents_by_owner(self, owner: str) -> List[str]:
        """根据归属部门获取 Agent DID 列表。"""
        result = []
        for agent_did, metadata in self._agent_metadata.items():
            if metadata.get("owner") == owner:
                result.append(agent_did)
        return result
    
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
            "personnel": "hr",
            "sales": "sales",
            "order": "sales",
            "customer": "sales",
        }
        
        agent_type = task_to_agent_type.get(task_type.lower())
        if agent_type:
            agents = self.get_agents_by_type(agent_type)
            if agents:
                return agents[0]  # 返回第一个可用的 Agent
        
        return None
    
    def get_all_agent_info(self) -> List[Dict]:
        """获取所有 Agent 的详细信息。"""
        result = []
        for agent_did in self._agents:
            metadata = self._agent_metadata.get(agent_did, {})
            reg_time = self._registration_time.get(agent_did)
            
            result.append({
                "did": agent_did,
                "type": metadata.get("type", "unknown"),
                "owner": metadata.get("owner", "unknown"),
                "sensitivity": metadata.get("sensitivity", "unknown"),
                "capabilities": metadata.get("capabilities", []),
                "registered_at": reg_time.isoformat() if reg_time else None
            })
        return result


# 全局注册中心实例
registry = AgentRegistry()
