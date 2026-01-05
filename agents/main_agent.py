"""
Main Agent (Orchestrator)
主 Agent (协调者)：负责接收用户请求、意图识别、任务拆解、向网关申请调用 Task Agent

职责：
1. 接收网关转发的用户请求
2. 进行意图识别与任务拆解
3. 通过 HTTP 向网关查询 Task Agent
4. 通过 HTTP 向网关申请调用 Task Agent 的授权
5. 通过 HTTP 将授权的 Agent 添加到协作组
6. 协调 Task Agent 执行任务

所有与网关/注册中心的交互都通过 HTTP 进行！
"""

import httpx
from typing import Dict, Any, List, Optional
from dataclasses import dataclass

from agents.base_agent import BaseAgent


GATEWAY_URL = "http://localhost:8000"


@dataclass
class TaskDecomposition:
    """任务拆解结果。"""
    task_type: str  # 任务类型 (finance, hr, sales, etc.)
    description: str  # 任务描述
    required_agent_type: str  # 需要的 Agent 类型
    priority: int = 1  # 优先级


class MainAgent(BaseAgent):
    """
    主 Agent (协调者)。
    
    负责接收用户请求，进行意图识别和任务拆解，
    然后通过 HTTP 向网关申请调用相应的 Task Agent。
    
    所有与注册中心/网关的交互都通过 HTTP API 进行。
    """
    
    def __init__(self, gateway_url: str = GATEWAY_URL):
        super().__init__(agent_did="did:agent:main_orchestrator")
        self._gateway_url = gateway_url
        self._current_session_id: Optional[str] = None
    
    def analyze_intent(self, user_query: str) -> List[TaskDecomposition]:
        """
        意图识别与任务拆解。
        
        分析用户请求，识别需要哪些 Task Agent 来完成任务。
        
        Args:
            user_query: 用户的原始请求
            
        Returns:
            任务拆解结果列表
        """
        print(f"[MainAgent] Analyzing user intent: {user_query}")
        
        tasks = []
        query_lower = user_query.lower()
        
        # 简化的意图识别逻辑（实际生产中应使用 NLP/LLM）
        if any(word in query_lower for word in ["audit", "财务", "审计", "finance", "report", "报表"]):
            tasks.append(TaskDecomposition(
                task_type="finance",
                description=f"执行财务任务: {user_query}",
                required_agent_type="finance"
            ))
        
        if any(word in query_lower for word in ["employee", "员工", "hr", "人事", "招聘"]):
            tasks.append(TaskDecomposition(
                task_type="hr",
                description=f"执行人事任务: {user_query}",
                required_agent_type="hr"
            ))
        
        if any(word in query_lower for word in ["sales", "销售", "客户", "订单"]):
            tasks.append(TaskDecomposition(
                task_type="sales",
                description=f"执行销售任务: {user_query}",
                required_agent_type="sales"
            ))
        
        # 如果没有识别出任何任务类型，默认尝试财务
        if not tasks:
            tasks.append(TaskDecomposition(
                task_type="general",
                description=user_query,
                required_agent_type="finance"  # 默认尝试财务 Agent
            ))
        
        print(f"[MainAgent] Identified {len(tasks)} task(s): {[t.task_type for t in tasks]}")
        return tasks
    
    async def query_agent_from_gateway(self, task_type: str) -> Optional[str]:
        """
        通过 HTTP 向网关查询合适的 Task Agent。
        
        Args:
            task_type: 任务类型
            
        Returns:
            Task Agent 的 DID，如果没有找到则返回 None
        """
        print(f"[MainAgent] Querying gateway for agent (task_type: {task_type})")
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self._gateway_url}/gateway/query-agent",
                    params={"task_type": task_type},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    if result.get("status") == "found":
                        agent_did = result.get("agent_did")
                        print(f"[MainAgent] Found agent via gateway: {agent_did}")
                        return agent_did
                    else:
                        print(f"[MainAgent] No agent found for task type: {task_type}")
                        return None
                else:
                    print(f"[MainAgent] Gateway query failed: {response.status_code}")
                    return None
        except httpx.HTTPError as e:
            print(f"[MainAgent] HTTP error querying gateway: {e}")
            return None
    
    async def request_agent_authorization(
        self,
        user_jwt: str,
        target_agent_did: str,
        task_description: str,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        通过 HTTP 向网关申请调用 Task Agent 的授权。
        
        Args:
            user_jwt: 用户的 JWT Token
            target_agent_did: 目标 Task Agent 的 DID
            task_description: 任务描述
            session_id: 协作会话 ID (可选)
            
        Returns:
            授权结果
        """
        print(f"[MainAgent] Requesting authorization via HTTP: {target_agent_did}")
        
        headers = {
            "X-User-Token": user_jwt,
            "Content-Type": "application/json"
        }
        
        if session_id:
            headers["X-Session-Id"] = session_id
        
        request_body = {
            "target_agent_did": target_agent_did,
            "task_description": task_description
        }
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self._gateway_url}/gateway/authorize-agent-call",
                    json=request_body,
                    headers=headers,
                    timeout=30.0
                )
                
                result = response.json()
                
                if response.status_code == 200:
                    print(f"[MainAgent] Authorization GRANTED for {target_agent_did}")
                    return {
                        "status": "authorized",
                        "agent_did": target_agent_did,
                        "authorization_token": result.get("authorization", {}).get("authorization_token"),
                        "result": result
                    }
                else:
                    print(f"[MainAgent] Authorization DENIED for {target_agent_did}: {result}")
                    return {
                        "status": "denied",
                        "agent_did": target_agent_did,
                        "error": result.get("detail", "Unknown error"),
                        "http_status": response.status_code
                    }
        except httpx.HTTPError as e:
            error_msg = f"Failed to request authorization: {str(e)}"
            print(f"[MainAgent] {error_msg}")
            return {
                "status": "error",
                "agent_did": target_agent_did,
                "error": error_msg
            }
    
    async def add_agent_to_collaboration(
        self,
        user_jwt: str,
        session_id: str,
        agent_did: str,
        authorization_token: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        通过 HTTP 将授权的 Agent 添加到协作组。
        
        Args:
            user_jwt: 用户的 JWT Token
            session_id: 协作会话 ID
            agent_did: 要添加的 Agent DID
            authorization_token: 授权凭证 (可选)
            
        Returns:
            添加结果
        """
        print(f"[MainAgent] Adding agent to collaboration via HTTP: {agent_did}")
        
        headers = {
            "X-User-Token": user_jwt,
            "X-Session-Id": session_id,
            "Content-Type": "application/json"
        }
        
        request_body = {
            "agent_did": agent_did
        }
        if authorization_token:
            request_body["authorization_token"] = authorization_token
        
        try:
            async with httpx.AsyncClient() as client:
                response = await client.post(
                    f"{self._gateway_url}/gateway/collaboration/add-agent",
                    json=request_body,
                    headers=headers,
                    timeout=10.0
                )
                
                result = response.json()
                
                if response.status_code == 200:
                    print(f"[MainAgent] Agent {agent_did} added to collaboration")
                    return {
                        "status": "success",
                        "agent_did": agent_did,
                        "result": result
                    }
                else:
                    print(f"[MainAgent] Failed to add agent to collaboration: {result}")
                    return {
                        "status": "error",
                        "agent_did": agent_did,
                        "error": result.get("detail", "Unknown error")
                    }
        except httpx.HTTPError as e:
            error_msg = f"HTTP error: {str(e)}"
            print(f"[MainAgent] {error_msg}")
            return {
                "status": "error",
                "agent_did": agent_did,
                "error": error_msg
            }
    
    async def get_collaboration_agents(
        self,
        user_jwt: str,
        session_id: str
    ) -> List[str]:
        """
        通过 HTTP 获取协作组中的 Agent 列表。
        
        Args:
            user_jwt: 用户的 JWT Token
            session_id: 协作会话 ID
            
        Returns:
            协作组中的 Agent DID 列表
        """
        try:
            async with httpx.AsyncClient() as client:
                response = await client.get(
                    f"{self._gateway_url}/gateway/collaboration/{session_id}/agents",
                    headers={"X-User-Token": user_jwt},
                    timeout=10.0
                )
                
                if response.status_code == 200:
                    result = response.json()
                    return result.get("authorized_agents", [])
                else:
                    return []
        except httpx.HTTPError:
            return []
    
    async def process_user_request(
        self,
        user_jwt: str,
        user_query: str,
        session_id: Optional[str] = None
    ) -> Dict[str, Any]:
        """
        处理用户请求的完整流程（全部通过 HTTP）。
        
        1. 意图识别与任务拆解
        2. 通过 HTTP 向网关查询需要的 Task Agent
        3. 通过 HTTP 向网关申请授权
        4. 通过 HTTP 将授权的 Agent 添加到协作组
        5. 返回处理结果
        
        Args:
            user_jwt: 用户的 JWT Token
            user_query: 用户的请求
            session_id: 协作会话 ID (可选)
            
        Returns:
            处理结果，包含授权状态和可用的 Agent 列表
        """
        print(f"\n[MainAgent] ========== Processing User Request ==========")
        print(f"[MainAgent] Query: {user_query}")
        print(f"[MainAgent] Session: {session_id}")
        
        self._current_session_id = session_id
        
        # Step 1: 意图识别与任务拆解
        tasks = self.analyze_intent(user_query)
        
        # Step 2, 3, 4: 查找 Agent、申请授权、添加到协作组
        authorization_results = []
        authorized_agents = []
        denied_agents = []
        
        for task in tasks:
            # Step 2: 通过 HTTP 向网关查询 Agent
            agent_did = await self.query_agent_from_gateway(task.required_agent_type)
            
            if not agent_did:
                authorization_results.append({
                    "task": task.task_type,
                    "status": "no_agent_found",
                    "error": f"No agent found for task type: {task.required_agent_type}"
                })
                continue
            
            # Step 3: 通过 HTTP 向网关申请授权
            auth_result = await self.request_agent_authorization(
                user_jwt=user_jwt,
                target_agent_did=agent_did,
                task_description=task.description,
                session_id=session_id
            )
            
            auth_result["task"] = task.task_type
            auth_result["task_description"] = task.description
            authorization_results.append(auth_result)
            
            if auth_result["status"] == "authorized":
                # Step 4: 通过 HTTP 将 Agent 添加到协作组
                if session_id:
                    add_result = await self.add_agent_to_collaboration(
                        user_jwt=user_jwt,
                        session_id=session_id,
                        agent_did=agent_did,
                        authorization_token=auth_result.get("authorization_token")
                    )
                    if add_result["status"] == "success":
                        authorized_agents.append(agent_did)
                    else:
                        # 添加失败也算授权成功，只是没加入协作组
                        authorized_agents.append(agent_did)
                else:
                    authorized_agents.append(agent_did)
            else:
                denied_agents.append({
                    "agent_did": agent_did,
                    "error": auth_result.get("error", "Unknown")
                })
        
        # 汇总结果
        all_authorized = len(denied_agents) == 0 and len(authorized_agents) > 0
        
        result = {
            "status": "completed" if all_authorized else ("partial" if authorized_agents else "denied"),
            "user_query": user_query,
            "session_id": session_id,
            "tasks_identified": len(tasks),
            "authorized_agents": authorized_agents,
            "denied_agents": denied_agents,
            "authorization_details": authorization_results
        }
        
        if all_authorized:
            result["message"] = f"All {len(authorized_agents)} agent(s) authorized and added to collaboration."
        elif authorized_agents:
            result["message"] = f"{len(authorized_agents)} agent(s) authorized, {len(denied_agents)} denied."
        else:
            result["message"] = "No agents were authorized. Access denied."
        
        print(f"[MainAgent] Result: {result['status']} - {result['message']}")
        
        return result
    
    async def execute_task(self, user_id: str, task_description: str) -> Dict[str, Any]:
        """
        执行任务（BaseAgent 抽象方法的实现）。
        
        注意：MainAgent 作为协调者，不直接执行任务，
        而是协调其他 Task Agent 来执行。
        """
        return {
            "status": "error",
            "message": "MainAgent is an orchestrator and does not execute tasks directly. "
                      "Use process_user_request() instead."
        }
