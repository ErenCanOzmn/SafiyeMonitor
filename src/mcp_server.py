import asyncio
import json
import os
import sys
from mcp.server.models import InitializationOptions
from mcp.server import Notification, Server
from mcp.server.stdio import stdio_server
import mcp.types as types
import requests

# Safiye MCP Server
# This server provides Safiye's data to AI models (Claude, Gemini, etc.).

server = Server("safiye-analyzer")

SAFIYE_API_BASE = "http://127.0.0.1:5000"

@server.list_tools()
async def handle_list_tools() -> list[types.Tool]:
    """List analysis tools provided by Safiye."""
    return [
        types.Tool(
            name="get_vulnerability_report",
            description="Analyzes all vulnerabilities captured by Safiye (Deserialization, Hijacking, etc.).",
            inputSchema={
                "type": "object",
                "properties": {},
            },
        ),
        types.Tool(
            name="analyze_memory_strings",
            description="Scans memory dump strings for sensitive data (passwords, keys).",
            inputSchema={
                "type": "object",
                "properties": {
                    "filter": {"type": "string", "description": "Search for a specific keyword."},
                },
            },
        )
    ]

@server.call_tool()
async def handle_call_tool(
    name: str, arguments: dict | None
) -> list[types.TextContent | types.ImageContent | types.EmbeddedResource]:
    """Execute tools and return results to AI."""
    if name == "get_vulnerability_report":
        # In a real scenario, this would query Safiye's actual logs or DB
        return [types.TextContent(type="text", text="[Safiye AI] Analyzing: 2 insecure deserialization risks and 1 DLL Hijacking attempt detected.")]
    
    elif name == "analyze_memory_strings":
        return [types.TextContent(type="text", text="[Safiye AI] Memory dump inspected. 'admin123' and 'API_KEY' found in sensitive regions.")]
    
    raise ValueError(f"Unknown tool: {name}")

async def main():
    # Run the server using stdin/stdout streams
    async with stdio_server() as (read_stream, write_stream):
        await server.run(
            read_stream,
            write_stream,
            InitializationOptions(
                server_name="safiye-analyzer",
                server_version="1.0.0",
                capabilities=server.get_capabilities(
                    notification_options=Notification(),
                    experimental_capabilities={},
                ),
            ),
        )

if __name__ == "__main__":
    asyncio.run(main())
