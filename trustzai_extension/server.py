import asyncio
from mcp.server import Server
from mcp.server.stdio import stdio_server
from mcp.types import Tool, TextContent
import sys
import os
sys.path.insert(0, os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from trustzai_mcp.tools import client

app = Server("trustzai-cybersec")

@app.list_tools()
async def list_tools() -> list[Tool]:
    return [
        Tool(
            name="login",
            description="Login to TrustZAI CyberSec AI Agent",
            inputSchema={
                "type": "object",
                "properties": {
                    "username": {
                        "type": "string",
                        "description": "Username (admin/analyst/viewer)"
                    },
                    "password": {
                        "type": "string",
                        "description": "Password"
                    }
                },
                "required": ["username", "password"]
            }
        ),
        Tool(
            name="cve_query",
            description="Query the CyberSec AI Agent about CVEs and security vulnerabilities",
            inputSchema={
                "type": "object",
                "properties": {
                    "question": {
                        "type": "string",
                        "description": "Security question about CVEs or vulnerabilities"
                    }
                },
                "required": ["question"]
            }
        ),
        Tool(
            name="threat_analysis",
            description="Analyze a security threat or attack pattern",
            inputSchema={
                "type": "object",
                "properties": {
                    "threat": {
                        "type": "string",
                        "description": "Threat or attack pattern to analyze"
                    }
                },
                "required": ["threat"]
            }
        ),
        Tool(
            name="security_recommendations",
            description="Get security recommendations for a specific vulnerability",
            inputSchema={
                "type": "object",
                "properties": {
                    "vulnerability": {
                        "type": "string",
                        "description": "Vulnerability to get recommendations for"
                    }
                },
                "required": ["vulnerability"]
            }
        ),
        Tool(
            name="system_health",
            description="Check TrustZAI system health and status",
            inputSchema={
                "type": "object",
                "properties": {}
            }
        )
    ]

@app.call_tool()
async def call_tool(name: str, arguments: dict) -> list[TextContent]:

    if name == "login":
        result = await client.login(
            arguments["username"],
            arguments["password"]
        )
        if result["success"]:
            text = f"✅ {result['message']}\nRole: {result['role']}"
        else:
            text = f"❌ {result['message']}"
        return [TextContent(type="text", text=text)]

    elif name == "cve_query":
        result = await client.query(arguments["question"])
        if "error" in result:
            text = f"❌ {result['error']}"
        else:
            text = f"🔍 CVE Analysis:\n\n{result['answer']}"
            if result.get("sources"):
                text += f"\n\nSources: {', '.join(result['sources'])}"
        return [TextContent(type="text", text=text)]

    elif name == "threat_analysis":
        prompt = f"Analyze this security threat: {arguments['threat']}"
        result = await client.query(prompt)
        if "error" in result:
            text = f"❌ {result['error']}"
        else:
            text = f"🚨 Threat Analysis:\n\n{result['answer']}"
        return [TextContent(type="text", text=text)]

    elif name == "security_recommendations":
        prompt = f"What are the security recommendations for: {arguments['vulnerability']}"
        result = await client.query(prompt)
        if "error" in result:
            text = f"❌ {result['error']}"
        else:
            text = f"🛡️ Security Recommendations:\n\n{result['answer']}"
        return [TextContent(type="text", text=text)]

    elif name == "system_health":
        result = await client.health_check()
        if "error" in result:
            text = f"❌ System unavailable: {result['error']}"
        else:
            text = f"✅ System Status: {result['status']}\nService: {result['service']}\nVersion: {result['version']}"
        return [TextContent(type="text", text=text)]

    return [TextContent(type="text", text="Unknown tool")]

async def main():
    async with stdio_server() as (read_stream, write_stream):
        await app.run(read_stream, write_stream, app.create_initialization_options())

if __name__ == "__main__":
    asyncio.run(main())
