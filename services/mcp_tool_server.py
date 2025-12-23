"""
MCP Tool Server (模拟)
模拟 MCP (Model Context Protocol) 服务器，接收 JSON-RPC 请求
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Dict, Any
import json


app = FastAPI(title="MCP Tool Server (Mock)")


@app.post("/mcp/tools/audit")
async def mcp_audit_tool(request: Request):
    """
    模拟审计工具端点。
    接收 JSON-RPC 格式的请求。
    """
    try:
        body = await request.json()
        
        # JSON-RPC 格式: {"jsonrpc": "2.0", "method": "...", "params": {...}, "id": 1}
        method = body.get("method", "")
        params = body.get("params", {})
        
        print(f"[MCP Tool] Received request - Method: {method}, Params: {params}")
        
        # 模拟返回审计数据
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "tool": "urn:mcp:audit",
                "status": "success",
                "data": {
                    "audit_records": [
                        {"id": 1, "action": "read", "resource": "financial_report_2024"},
                        {"id": 2, "action": "read", "resource": "budget_plan"}
                    ]
                }
            }
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MCP Tool error: {str(e)}")


@app.post("/mcp/tools/report")
async def mcp_report_tool(request: Request):
    """模拟报告生成工具端点。"""
    try:
        body = await request.json()
        method = body.get("method", "")
        params = body.get("params", {})
        
        print(f"[MCP Tool] Received request - Method: {method}, Params: {params}")
        
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "tool": "urn:mcp:report",
                "status": "success",
                "data": {
                    "report_id": "RPT-2024-001",
                    "generated_at": "2024-04-01T10:00:00Z"
                }
            }
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MCP Tool error: {str(e)}")


@app.post("/mcp/tools/delete_db")
async def mcp_delete_db_tool(request: Request):
    """模拟数据库删除工具端点 (应该被拒绝的敏感操作)。"""
    try:
        body = await request.json()
        print(f"[MCP Tool] DELETE_DB request received (should be blocked by gateway)")
        
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "tool": "urn:mcp:delete_db",
                "status": "executed",
                "data": {"deleted": True}
            }
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MCP Tool error: {str(e)}")


@app.post("/mcp/tools/{tool_path:path}")
async def mcp_generic_tool(tool_path: str, request: Request):
    """通用的 MCP 工具端点。"""
    try:
        body = await request.json()
        print(f"[MCP Tool] Generic tool request - Path: {tool_path}")
        
        return JSONResponse({
            "jsonrpc": "2.0",
            "id": body.get("id"),
            "result": {
                "tool": f"urn:mcp:{tool_path}",
                "status": "success",
                "data": {}
            }
        })
    except Exception as e:
        raise HTTPException(status_code=500, detail=f"MCP Tool error: {str(e)}")


if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8001)

