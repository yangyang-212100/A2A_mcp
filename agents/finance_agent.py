"""
Finance Agent (Task Agent)
财务 Agent：作为 Task Agent 执行财务相关任务

职责：
1. 接收 Main Agent 分派的任务
2. 执行具体的财务任务（审计、报表等）
3. 调用 MCP Tool 时通过网关进行授权
"""

import httpx
from typing import Dict, Any

from agents.base_agent import BaseAgent
from core.token_manager import decode_task_token_payload


GATEWAY_URL = "http://localhost:8000"


class FinanceAgent(BaseAgent):
    """
    财务 Agent (Task Agent)。
    
    作为 Task Agent，接收 Main Agent 分派的任务并执行。
    执行任务时需要通过网关调用 MCP Tool。
    """
    
    def __init__(self):
        super().__init__(agent_did="did:agent:fin_analyst")
        self._agent_type = "finance"
        self._capabilities = ["audit", "report", "financial_analysis"]
    
    @property
    def agent_type(self) -> str:
        """获取 Agent 类型。"""
        return self._agent_type
    
    @property
    def capabilities(self) -> list:
        """获取 Agent 能力列表。"""
        return self._capabilities.copy()
    
    def get_metadata(self) -> Dict[str, Any]:
        """获取 Agent 元数据（用于注册）。"""
        return {
            "type": self._agent_type,
            "capabilities": self._capabilities,
            "version": "1.0"
        }
    
    async def execute_task(self, user_id: str, task_description: str) -> Dict[str, Any]:
        """
        执行财务任务。
        
        Args:
            user_id: 用户 ID
            task_description: 任务描述
            
        Returns:
            任务执行结果
        """
        print(f"\n[FinanceAgent] ========== Executing Task ==========")
        print(f"[FinanceAgent] User: {user_id}")
        print(f"[FinanceAgent] Task: {task_description}")
        
        # 根据任务描述选择工具
        if "audit" in task_description.lower() or "审计" in task_description:
            tool_name = "urn:mcp:audit"
            tool_path = "audit"
            result_type = "audit_report"
        elif "report" in task_description.lower() or "报表" in task_description:
            tool_name = "urn:mcp:report"
            tool_path = "report"
            result_type = "financial_report"
        else:
            tool_name = "urn:mcp:audit"
            tool_path = "audit"
            result_type = "general_analysis"
        
        print(f"[FinanceAgent] Selected tool: {tool_name}")
        
        # 模拟任务执行结果（不调用实际的 MCP Tool）
        # 在完整流程中，这里会创建 Task-MCP Token 并通过网关调用 MCP Tool
        
        result = {
            "status": "success",
            "agent_did": self.agent_did,
            "user_id": user_id,
            "task_description": task_description,
            "result_type": result_type,
            "tool_used": tool_name,
            "data": {
                "summary": f"Finance task completed: {task_description}",
                "details": f"Processed by {self.agent_did} using {tool_name}"
            }
        }
        
        print(f"[FinanceAgent] Task completed successfully")
        return result
    
    async def execute_with_authorization(
        self,
        user_id: str,
        user_jwt: str,
        task_description: str,
        authorization_token: str
    ) -> Dict[str, Any]:
        """
        使用授权凭证执行任务。
        
        在完整的授权流程中，Task Agent 收到 Main Agent 的任务分派时，
        会同时收到网关颁发的授权凭证，用于后续的 MCP Tool 调用。
        
        Args:
            user_id: 用户 ID
            user_jwt: 用户 JWT Token
            task_description: 任务描述
            authorization_token: 网关颁发的授权凭证
            
        Returns:
            任务执行结果
        """
        print(f"\n[FinanceAgent] ========== Executing Authorized Task ==========")
        print(f"[FinanceAgent] User: {user_id}")
        print(f"[FinanceAgent] Task: {task_description}")
        print(f"[FinanceAgent] Authorization: {authorization_token[:50]}...")
        
        # 执行任务
        result = await self.execute_task(user_id, task_description)
        result["authorization_used"] = True
        
        return result
    
    async def call_mcp_tool_via_gateway(
        self,
        user_id: str,
        user_jwt: str,
        tool_name: str
    ) -> Dict[str, Any]:
        """
        通过网关调用 MCP 工具。
        
        这是 Task Agent 调用 MCP Tool 的标准方式：
        1. 创建 Task-MCP Token
        2. 将 User JWT + Task Token 发送给网关
        3. 网关验证后转发到 MCP Tool Server
        
        Args:
            user_id: 用户 ID
            user_jwt: 用户 JWT Token
            tool_name: 工具名称 (如 "urn:mcp:audit")
            
        Returns:
            MCP 工具执行结果
        """
        print(f"[FinanceAgent] Calling MCP tool via gateway: {tool_name}")
        
        # 创建 Task-MCP Token
        token_data = self.create_task_token_for_user(user_id, tool_name)
        
        # 提取工具路径
        tool_path = tool_name.replace("urn:mcp:", "")
        
        # 发送请求到网关
        gateway_url = f"{GATEWAY_URL}/gateway/mcp/{tool_path}"
        
        headers = {
            "X-User-Token": user_jwt,
            "X-Task-Token-Payload": token_data["payload"],
            "X-Task-Token-Signature": token_data["signature"],
            "Content-Type": "application/json"
        }
        
        request_body = {
            "jsonrpc": "2.0",
            "method": tool_name,
            "params": {"user_id": user_id},
            "id": 1
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    gateway_url,
                    json=request_body,
                    headers=headers,
                    timeout=30.0
                )
                
                if response.status_code == 200:
                    return response.json()
                else:
                    return {
                        "error": f"Gateway returned {response.status_code}",
                        "detail": response.json() if response.content else None
                    }
        except httpx.HTTPError as e:
            return {"error": str(e)}


class HRAgent(BaseAgent):
    """
    人事 Agent (Task Agent)。
    
    作为 Task Agent，处理人事相关任务。
    """
    
    def __init__(self):
        super().__init__(agent_did="did:agent:hr_agent")
        self._agent_type = "hr"
        self._capabilities = ["employee_data", "recruitment", "payroll"]
    
    @property
    def agent_type(self) -> str:
        return self._agent_type
    
    @property
    def capabilities(self) -> list:
        return self._capabilities.copy()
    
    def get_metadata(self) -> Dict[str, Any]:
        return {
            "type": self._agent_type,
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
