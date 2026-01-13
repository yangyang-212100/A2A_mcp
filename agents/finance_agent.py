"""
Task Agents
Task Agent 实现：销售助手、财务分析师、人事档案员

每个 Agent 具有以下属性：
- DID: 唯一标识符
- type: Agent 类型
- owner: 归属部门
- sensitivity: 敏感度/密级 (Internal, Confidential, TopSecret)
- capabilities: 能力列表

论文 3.3.3 章节实现：
- Task Agent 在处理请求时进行业务推理
- 识别出目标资源 (target URN) 和操作类型 (action)
- 签发 Task-MCP Token，绑定用户身份与执行意图
"""

import httpx
import re
from typing import Dict, Any, Tuple, Optional

from agents.base_agent import BaseAgent
from core.token_manager import create_task_mcp_token


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
    
    def analyze_intent(self, task_description: str, params: Dict[str, Any]) -> Tuple[str, str]:
        """
        业务推理：分析用户请求，识别目标资源和操作类型。
        
        论文 3.3.3 章节要求 Task Agent 识别出：
        - target: 目标资源 URN (如 urn:finance:report:Q1-2024)
        - action: 操作类型 (read, write, execute)
        
        Args:
            task_description: 任务描述
            params: 请求参数
            
        Returns:
            (target_urn, action) 元组
        """
        # 从参数中提取 report_id
        report_id = params.get("report_id", "unknown")
        
        # 根据任务描述推理操作类型
        task_lower = task_description.lower()
        
        if any(word in task_lower for word in ["read", "view", "query", "get", "fetch"]):
            action = "read"
        elif any(word in task_lower for word in ["write", "update", "modify", "edit"]):
            action = "write"
        elif any(word in task_lower for word in ["execute", "run", "perform", "audit"]):
            action = "execute"
        else:
            action = "read"  # 默认读取
        
        # 构建目标资源 URN
        target_urn = f"urn:finance:report:{report_id}"
        
        return target_urn, action
    
    def generate_task_mcp_token(
        self,
        user_id: str,
        clearance: int,
        session_id: str,
        task_description: str,
        params: Dict[str, Any],
        verbose: bool = False
    ) -> Tuple[str, Dict[str, Any]]:
        """
        生成 Task-MCP Token。
        
        论文 3.3.3 章节核心实现：
        1. 进行业务推理，识别 target 和 action
        2. 计算请求参数的 SM3 哈希
        3. 使用 Agent 私钥签发 Token
        
        Args:
            user_id: 用户 ID（来自用户会话 JWT）
            clearance: 用户安全许可等级
            session_id: 会话 ID
            task_description: 任务描述
            params: 请求参数
            verbose: 是否输出详细信息
            
        Returns:
            (token_string, details) - Token 字符串和签发详情
        """
        # Step 1: 业务推理 - 识别目标和操作
        target_urn, action = self.analyze_intent(task_description, params)
        
        if verbose:
            print(f"[FinanceAgent] Business Reasoning:")
            print(f"    Task: {task_description}")
            print(f"    Target URN: {target_urn}")
            print(f"    Action: {action}")
        
        # Step 2: 调用 token_manager 生成 Task-MCP Token
        token, details = create_task_mcp_token(
            agent_did=self.agent_did,
            user_id=user_id,
            clearance=clearance,
            session_id=session_id,
            target=target_urn,
            action=action,
            params=params,
            verbose=verbose
        )
        
        # 添加业务推理信息到详情
        details["reasoning"] = {
            "target_urn": target_urn,
            "action": action,
            "task_description": task_description
        }
        
        return token, details


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
