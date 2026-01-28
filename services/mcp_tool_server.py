"""
MCP Tool Server (Bridge)

本服务作为 HTTP -> MCP 的桥接器：
- 对外暴露 /mcp/tools/{tool_path}，供 Gateway 调用
- 对内通过 HTTP 调用真正的 Finance MCP Server（services/finance_mcp_server.py）
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Dict, Any
import os
import httpx


app = FastAPI(title="MCP Tool Server (Bridge)")

# 真实 Finance MCP Server 地址（本地端口，手动启动）
FINANCE_MCP_SERVER_URL = os.getenv("FINANCE_MCP_SERVER_URL", "http://127.0.0.1:8003")


def map_tool_path_to_mcp_name(tool_path: str) -> str:
    """
    将 Gateway 调用的 tool_path 映射为 MCP 工具名。
    
    例如：
    - "report"        -> "finance.report.get"
    - "audit"         -> "finance.audit.query" (预留，将来可扩展)
    - "foo/bar"       -> "foo.bar"
    """
    if tool_path == "report":
        return "finance.report.get"
    if tool_path == "audit":
        return "finance.audit.query"
    return tool_path.replace("/", ".")


@app.post("/mcp/tools/{tool_path:path}")
async def mcp_bridge_tool(tool_path: str, request: Request):
    """
    通用 MCP 工具端点（Bridge）。
    
    外部（Gateway）调用格式保持不变：
        POST /mcp/tools/{tool_path}
        body: 可以是 JSON-RPC 格式，也可以是简单 JSON 参数
    
    内部会转换为 MCP 风格的 tools/call 请求：
        POST {FINANCE_MCP_SERVER_URL}/tools/call
    """
    try:
        body = await request.json()
    except Exception:
        body = {}
    
    print(f"[MCP Bridge] Incoming request - Path: {tool_path}, Body: {body}")
    
    # 兼容 JSON-RPC: {"jsonrpc": "2.0", "method": "...", "params": {...}, "id": 1}
    incoming_params = body.get("params", body) or {}
    request_id = body.get("id", 1)
    
    # 将 path 映射到 MCP 工具名
    tool_name = map_tool_path_to_mcp_name(tool_path)
    
    # 构造 MCP Server 的调用请求
    mcp_request: Dict[str, Any] = {
        "jsonrpc": "2.0",
        "id": request_id,
        "method": "tools/call",
        "params": {
            "name": tool_name,
            "arguments": incoming_params,
        },
    }
    
    try:
        async with httpx.AsyncClient(timeout=30.0) as client:
            resp = await client.post(
                f"{FINANCE_MCP_SERVER_URL}/tools/call",
                json=mcp_request,
            )
            resp.raise_for_status()
            mcp_response = resp.json()
    except httpx.HTTPError as e:
        print(f"[MCP Bridge] Error calling Finance MCP Server: {e}")
        raise HTTPException(
            status_code=502,
            detail=f"Finance MCP Server error: {str(e)}",
        )
    except Exception as e:
        print(f"[MCP Bridge] Unexpected error: {e}")
        raise HTTPException(status_code=500, detail=f"Bridge internal error: {e}")
    
    print(f"[MCP Bridge] MCP response: {mcp_response}")
    
    # 直接将 MCP Server 返回的 JSON 透传给 Gateway / Client
    return JSONResponse(mcp_response)


@app.get("/health")
async def health_check():
    """健康检查端点。"""
    return {"status": "healthy", "service": "mcp-tool-bridge"}


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

