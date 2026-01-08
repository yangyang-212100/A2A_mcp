"""
Task Agents
Task Agent 实现：销售助手、财务分析师、人事档案员

每个 Agent 具有以下属性：
- DID: 唯一标识符
- type: Agent 类型
- owner: 归属部门
- sensitivity: 敏感度/密级 (Internal, Confidential, TopSecret)
- capabilities: 能力列表
"""

import httpx
from typing import Dict, Any

from agents.base_agent import BaseAgent


GATEWAY_URL = "http://localhost:8000"


class FinanceAgent(BaseAgent):
    """
    财务分析师 (Task Agent)
    
    - DID: did:agent:fin_analyst
    - Owner: Finance
    - Sensitivity: Confidential (机密级)
    """
    
    def __init__(self):
        super().__init__(agent_did="did:agent:fin_analyst")
        self._agent_type = "finance"
        self._owner = "Finance"
        self._sensitivity = "Confidential"
        self._capabilities = ["audit", "report", "financial_analysis"]
    
    @property
    def agent_type(self) -> str:
        return self._agent_type
    
    @property
    def owner(self) -> str:
        return self._owner
    
    @property
    def sensitivity(self) -> str:
        return self._sensitivity
    
    @property
    def capabilities(self) -> list:
        return self._capabilities.copy()
    
    def get_metadata(self) -> Dict[str, Any]:
        """获取 Agent 元数据（用于注册）。"""
        return {
            "type": self._agent_type,
            "owner": self._owner,
            "sensitivity": self._sensitivity,
            "capabilities": self._capabilities,
            "version": "1.0"
        }
    
    async def execute_task(self, user_id: str, task_description: str) -> Dict[str, Any]:
        print(f"\n[FinanceAgent] ========== Executing Task ==========")
        print(f"[FinanceAgent] User: {user_id}")
        print(f"[FinanceAgent] Task: {task_description}")
        
        return {
            "status": "success",
            "agent_did": self.agent_did,
            "user_id": user_id,
            "task_description": task_description,
            "result_type": "financial_analysis",
            "data": {
                "summary": f"Finance task completed: {task_description}",
                "details": f"Processed by {self.agent_did}"
            }
        }


class HRAgent(BaseAgent):
    """
    人事档案员 (Task Agent)
    
    - DID: did:agent:hr_archivist
    - Owner: HR
    - Sensitivity: TopSecret (绝密级)
    """
    
    def __init__(self):
        super().__init__(agent_did="did:agent:hr_archivist")
        self._agent_type = "hr"
        self._owner = "HR"
        self._sensitivity = "TopSecret"
        self._capabilities = ["employee_data", "personnel_records", "recruitment"]
    
    @property
    def agent_type(self) -> str:
        return self._agent_type
    
    @property
    def owner(self) -> str:
        return self._owner
    
    @property
    def sensitivity(self) -> str:
        return self._sensitivity
    
    @property
    def capabilities(self) -> list:
        return self._capabilities.copy()
    
    def get_metadata(self) -> Dict[str, Any]:
        return {
            "type": self._agent_type,
            "owner": self._owner,
            "sensitivity": self._sensitivity,
            "capabilities": self._capabilities,
            "version": "1.0"
        }
    
    async def execute_task(self, user_id: str, task_description: str) -> Dict[str, Any]:
        print(f"\n[HRAgent] ========== Executing Task ==========")
        print(f"[HRAgent] User: {user_id}")
        print(f"[HRAgent] Task: {task_description}")
        
        return {
            "status": "success",
            "agent_did": self.agent_did,
            "user_id": user_id,
            "task_description": task_description,
            "result_type": "hr_task",
            "data": {
                "summary": f"HR task completed: {task_description}",
                "details": f"Processed by {self.agent_did}"
            }
        }


class SalesAgent(BaseAgent):
    """
    销售助手 (Task Agent)
    
    - DID: did:agent:sales_assistant
    - Owner: Sales
    - Sensitivity: Internal (内部级)
    """
    
    def __init__(self):
        super().__init__(agent_did="did:agent:sales_assistant")
        self._agent_type = "sales"
        self._owner = "Sales"
        self._sensitivity = "Internal"
        self._capabilities = ["sales_query", "order_management", "customer_service"]
    
    @property
    def agent_type(self) -> str:
        return self._agent_type
    
    @property
    def owner(self) -> str:
        return self._owner
    
    @property
    def sensitivity(self) -> str:
        return self._sensitivity
    
    @property
    def capabilities(self) -> list:
        return self._capabilities.copy()
    
    def get_metadata(self) -> Dict[str, Any]:
        return {
            "type": self._agent_type,
            "owner": self._owner,
            "sensitivity": self._sensitivity,
            "capabilities": self._capabilities,
            "version": "1.0"
        }
    
    async def execute_task(self, user_id: str, task_description: str) -> Dict[str, Any]:
        print(f"\n[SalesAgent] ========== Executing Task ==========")
        print(f"[SalesAgent] User: {user_id}")
        print(f"[SalesAgent] Task: {task_description}")
        
        return {
            "status": "success",
            "agent_did": self.agent_did,
            "user_id": user_id,
            "task_description": task_description,
            "result_type": "sales_task",
            "data": {
                "summary": f"Sales task completed: {task_description}",
                "details": f"Processed by {self.agent_did}"
            }
        }
