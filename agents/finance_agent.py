"""
Finance Agent
财务 Agent，实现财务相关的任务处理
"""

import httpx
from typing import Dict, Any

from agents.base_agent import BaseAgent
from core.token_manager import decode_task_token_payload


GATEWAY_URL = "http://localhost:8000"


class FinanceAgent(BaseAgent):
    """财务 Agent。"""
    
    def __init__(self):
        super().__init__(agent_did="did:agent:fin_analyst")
    
    async def execute_task(self, user_id: str, task_description: str) -> Dict[str, Any]:
        """
        执行财务任务。
        
        Args:
            user_id: 用户 ID
            task_description: 任务描述
            
        Returns:
            任务执行结果
        """
        print(f"[FinanceAgent] Executing task for user {user_id}: {task_description}")
        
        # 根据任务描述选择工具
        if "audit" in task_description.lower():
            tool_name = "urn:mcp:audit"
            tool_path = "audit"
        elif "report" in task_description.lower():
            tool_name = "urn:mcp:report"
            tool_path = "report"
        else:
            tool_name = "urn:mcp:audit"
            tool_path = "audit"
        
        # 创建 Task-MCP Token
        token_data = self.create_task_token_for_user(user_id, tool_name)
        
        print(f"[FinanceAgent] Created Task-Token for tool: {tool_name}")
        
        # 发送请求到网关
        gateway_url = f"{GATEWAY_URL}/gateway/mcp/{tool_path}"
        
        # 构造请求头
        headers = {
            "X-Task-Token-Payload": token_data["payload"],
            "X-Task-Token-Signature": token_data["signature"],
            "Content-Type": "application/json"
        }
        
        # 请求体 (JSON-RPC 格式)
        request_body = {
            "jsonrpc": "2.0",
            "method": tool_name,
            "params": {
                "user_id": user_id,
                "task": task_description
            },
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
                response.raise_for_status()
                result = response.json()
                print(f"[FinanceAgent] Request successful: {result}")
                return result
        except httpx.HTTPError as e:
            error_msg = f"Failed to execute task: {str(e)}"
            print(f"[FinanceAgent] {error_msg}")
            return {"error": error_msg}
    
    async def call_mcp_tool_direct(
        self,
        user_id: str,
        tool_name: str,
        user_token: str
    ) -> Dict[str, Any]:
        """
        直接调用 MCP 工具（通过网关）。
        
        Args:
            user_id: 用户 ID
            tool_name: 工具名称
            user_token: 用户身份 Token
            
        Returns:
            工具执行结果
        """
        # 创建 Task-MCP Token
        token_data = self.create_task_token_for_user(user_id, tool_name)
        
        # 提取工具路径
        tool_path = tool_name.replace("urn:mcp:", "")
        
        # 发送请求到网关
        gateway_url = f"{GATEWAY_URL}/gateway/mcp/{tool_path}"
        
        headers = {
            "X-User-Token": user_token,
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
                response.raise_for_status()
                return response.json()
        except httpx.HTTPError as e:
            return {"error": str(e)}

