"""
演示脚本 1: Agent 动态注册展示
Demo Script 1: Agent Dynamic Registration Display

本脚本演示三个具有不同密级属性的 Task Agent 实例的动态注册：
- 销售助手 (Internal)
- 财务分析师 (Confidential)
- 人事档案员 (TopSecret)

运行前请确保网关已启动:
    python -m services.gateway
"""

import asyncio
import httpx
from datetime import datetime

from agents.finance_agent import FinanceAgent, HRAgent, SalesAgent


GATEWAY_URL = "http://localhost:8000"


def print_header():
    """打印演示标题。"""
    print("""
================================================================================
          Agent Dynamic Registration Demo - Multi-Agent Security System
================================================================================
          
  本演示展示三个具有不同密级属性的 Task Agent 实例的动态注册过程：
  
  +------------------+-------------+---------------+
  |     Agent        |   Owner     |  Sensitivity  |
  +------------------+-------------+---------------+
  | 销售助手          | Sales       | Internal      |
  | 财务分析师        | Finance     | Confidential  |
  | 人事档案员        | HR          | TopSecret     |
  +------------------+-------------+---------------+
  
================================================================================
""")


def print_agent_info(agent, index: int):
    """打印 Agent 详细信息。"""
    metadata = agent.get_metadata()
    
    # 敏感度对应的颜色/标记
    sensitivity_display = {
        "Internal": "Internal     [*]",
        "Confidential": "Confidential [**]",
        "TopSecret": "TopSecret    [***]"
    }
    
    print(f"""
+------------------------------------------------------------------------------+
| Agent #{index}: Preparing for Registration
+------------------------------------------------------------------------------+
| DID:          {agent.agent_did}
| Type:         {metadata.get('type')}
| Owner:        {metadata.get('owner')}
| Sensitivity:  {sensitivity_display.get(metadata.get('sensitivity'), metadata.get('sensitivity'))}
| Capabilities: {metadata.get('capabilities')}
+------------------------------------------------------------------------------+
""")


async def register_agent_to_gateway(agent, index: int) -> bool:
    """通过 HTTP 将 Agent 注册到网关。"""
    metadata = agent.get_metadata()
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Sending HTTP POST to /gateway/register-agent...")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.post(
                f"{GATEWAY_URL}/gateway/register-agent",
                json={
                    "agent_did": agent.agent_did,
                    "public_key_pem": agent.key_pair.public_key_pem(),
                    "metadata": metadata
                }
            )
            
            if response.status_code == 200:
                result = response.json()
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Response: {response.status_code} OK")
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Agent #{index} registered successfully!")
                return True
            else:
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Response: {response.status_code} FAILED")
                print(f"[{datetime.now().strftime('%H:%M:%S')}] Error: {response.text}")
                return False
    except Exception as e:
        print(f"[{datetime.now().strftime('%H:%M:%S')}] HTTP Error: {e}")
        return False


async def show_registered_agents():
    """显示所有已注册的 Agent。"""
    print("""
================================================================================
                    Registered Agents Summary
================================================================================
""")
    
    try:
        async with httpx.AsyncClient(timeout=10.0) as client:
            response = await client.get(f"{GATEWAY_URL}/gateway/agents")
            
            if response.status_code == 200:
                data = response.json()
                agents = data.get("agents", [])
                
                print(f"  Total Registered Agents: {len(agents)}")
                print()
                print("  +-----+-----------------------------+----------+--------------+")
                print("  | No. | DID                         | Owner    | Sensitivity  |")
                print("  +-----+-----------------------------+----------+--------------+")
                
                for i, agent in enumerate(agents, 1):
                    did = agent.get("did", "N/A")[:27]
                    owner = agent.get("owner", "N/A")[:8]
                    sensitivity = agent.get("sensitivity", "N/A")[:12]
                    print(f"  | {i:3} | {did:27} | {owner:8} | {sensitivity:12} |")
                
                print("  +-----+-----------------------------+----------+--------------+")
                print()
                
                # 详细信息
                print("  Detailed Attributes (for PIP retrieval):")
                print("  -----------------------------------------")
                for agent in agents:
                    print(f"""
  Agent: {agent.get('did')}
    - type:         {agent.get('type')}
    - owner:        {agent.get('owner')}
    - sensitivity:  {agent.get('sensitivity')}
    - capabilities: {agent.get('capabilities')}
    - registered:   {agent.get('registered_at', 'N/A')}
""")
            else:
                print(f"  Failed to fetch agents: {response.status_code}")
    except Exception as e:
        print(f"  Error: {e}")


async def main():
    """主函数：演示 Agent 动态注册。"""
    print_header()
    
    # 检查网关是否运行
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Checking gateway status...")
    try:
        async with httpx.AsyncClient(timeout=5.0) as client:
            response = await client.get(f"{GATEWAY_URL}/gateway/health")
            if response.status_code != 200:
                print(f"[ERROR] Gateway is not healthy!")
                return
    except Exception:
        print(f"""
[ERROR] Cannot connect to gateway at {GATEWAY_URL}

Please start the gateway first:
    python -m services.gateway
""")
        return
    
    print(f"[{datetime.now().strftime('%H:%M:%S')}] Gateway is running at {GATEWAY_URL}")
    print()
    
    # 创建三个 Task Agent 实例
    agents = [
        (SalesAgent(), "Sales Assistant (Internal)"),
        (FinanceAgent(), "Finance Analyst (Confidential)"),
        (HRAgent(), "HR Archivist (TopSecret)")
    ]
    
    print("=" * 80)
    print("  Starting Agent Registration Process")
    print("=" * 80)
    
    # 逐个注册 Agent
    success_count = 0
    for i, (agent, name) in enumerate(agents, 1):
        print(f"\n{'='*80}")
        print(f"  Registering Agent #{i}: {name}")
        print(f"{'='*80}")
        
        print_agent_info(agent, i)
        
        if await register_agent_to_gateway(agent, i):
            success_count += 1
        
        # 短暂延迟，使输出更易读
        await asyncio.sleep(0.5)
    
    # 显示注册结果汇总
    print(f"\n{'='*80}")
    print(f"  Registration Complete: {success_count}/{len(agents)} agents registered")
    print(f"{'='*80}")
    
    # 显示所有已注册的 Agent
    await show_registered_agents()
    
    print("""
================================================================================
  Demo Complete!
  
  All agents are now registered in the Gateway's Registry.
  Their attributes (owner, sensitivity) are available for PIP retrieval
  during ABAC policy evaluation.
================================================================================
""")


if __name__ == "__main__":
    asyncio.run(main())

