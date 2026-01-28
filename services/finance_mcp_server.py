"""
Finance MCP Server (真实工具服务)

本服务模拟一个符合 MCP 思想的财务工具服务，通过本地 HTTP 端口提供：
- /tools/list  返回可用工具列表
- /tools/call  执行指定工具（当前仅实现 finance.report.get）

Gateway 和 mcp_tool_server 不直接调用这里的内部实现细节，只通过 HTTP 调用
来获得“真实”的财务报表数据，便于论文中展示：
- Task Agent -> Gateway (三元绑定校验)
- Gateway -> MCP Bridge (mcp_tool_server)
- MCP Bridge -> 本 Finance MCP Server (真实工具)
"""

from fastapi import FastAPI, Request, HTTPException
from fastapi.responses import JSONResponse
from typing import Dict, Any, List


app = FastAPI(title="Finance MCP Server")


def get_mock_finance_report(report_id: str, year: int) -> Dict[str, Any]:
    """
    模拟生成一份财务报表数据。
    
    为了论文演示，这里返回结构化的财务数据，而不是简单字符串。
    """
    return {
        "report_id": report_id,
        "year": year,
        "title": f"Financial Report {year} - {report_id}",
        "generated_at": "2024-04-01T10:00:00Z",
        "currency": "CNY",
        "summary": {
            "total_revenue": 12_500_000,
            "total_expense": 9_300_000,
            "net_profit": 3_200_000,
        },
        "sections": [
            {
                "name": "Revenue",
                "items": [
                    {"category": "Product Sales", "amount": 8_000_000},
                    {"category": "Service Income", "amount": 4_500_000},
                ],
            },
            {
                "name": "Expense",
                "items": [
                    {"category": "HR Cost", "amount": 3_000_000},
                    {"category": "Marketing", "amount": 2_300_000},
                    {"category": "IT Infrastructure", "amount": 4_000_000},
                ],
            },
        ],
    }


@app.post("/tools/list")
async def tools_list(request: Request):
    """
    MCP 风格的 tools/list 接口。
    
    为简单起见，使用 HTTP POST + JSON，而不是 JSON-RPC over WebSocket/stdio。
    """
    tools: List[Dict[str, Any]] = [
        {
            "name": "finance.report.get",
            "description": "Get structured financial report by report_id and year.",
            "input_schema": {
                "type": "object",
                "properties": {
                    "report_id": {"type": "string"},
                    "year": {"type": "integer"},
                },
                "required": ["report_id", "year"],
            },
        }
    ]
    
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": 1,
            "result": {"tools": tools},
        }
    )


@app.post("/tools/call")
async def tools_call(request: Request):
    """
    MCP 风格的 tools/call 接口。
    
    期望请求格式（JSON）：
    {
        "jsonrpc": "2.0",
        "id": 1,
        "method": "tools/call",
        "params": {
            "name": "finance.report.get",
            "arguments": {
                "report_id": "Q1-2024",
                "year": 2024
            }
        }
    }
    """
    try:
        body = await request.json()
    except Exception as e:
        raise HTTPException(status_code=400, detail=f"Invalid JSON body: {e}")
    
    method = body.get("method", "")
    params = body.get("params", {}) or {}
    tool_name = params.get("name") or params.get("tool") or ""
    arguments = params.get("arguments", {}) or {}
    request_id = body.get("id", 1)
    
    if method not in ("tools/call", "", None):
        # 对于本地演示，不强制 method，避免客户端对齐成本
        pass
    
    if tool_name != "finance.report.get":
        raise HTTPException(
            status_code=404,
            detail=f"Unknown MCP tool: {tool_name}",
        )
    
    report_id = arguments.get("report_id", "UNKNOWN")
    year = arguments.get("year", 2024)
    
    print(f"[Finance MCP] tools/call - tool={tool_name}, report_id={report_id}, year={year}")
    
    report = get_mock_finance_report(report_id=report_id, year=year)
    
    return JSONResponse(
        {
            "jsonrpc": "2.0",
            "id": request_id,
            "result": {
                "tool": tool_name,
                "status": "success",
                "data": report,
            },
        }
    )


@app.get("/health")
async def health_check():
    """简单健康检查，方便手动启动和验证。"""
    return {"status": "healthy", "service": "finance-mcp-server"}


if __name__ == "__main__":
    import uvicorn

    # 使用不与 gateway / mcp_tool_server 冲突的端口
    uvicorn.run(app, host="0.0.0.0", port=8003)

