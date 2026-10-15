"""
Example MCP tool for OSS Compass — GitHub audit.
"""
from mcp import types
from mcp.server import Server

server = Server("oss-compass-github-audit")


@server.list_tools()
async def handle_list_tools():
    return [
        types.Tool(
            name="github_repo_health",
            description="Analyze a GitHub repository for health, license, CI status, and quality signals.",
            arguments=[
                types.ToolArgument(
                    name="repo_full_name",
                    description="Full repo name: owner/repo",
                    required=True,
                ),
            ],
        ),
    ]


@server.call_tool()
async def handle_call_tool(name: str, arguments: dict | None):
    if name == "github_repo_health":
        # Implementation: GitHub API call for repo analysis
        repo = arguments.get("repo_full_name", "")
        return [
            types.TextContent(
                type="text",
                text=f"{{"repo": "{repo}", "analyzed": true}}",
            )
        ]
    return []


if __name__ == "__main__":
    import asyncio
    from mcp.server.stdio import stdio_server
    from mcp.server.models import InitializationOptions

    async def run():
        async with stdio_server(server) as (read_stream, write_stream):
            await server.run(read_stream, write_stream, InitializationOptions(server=server))

    asyncio.run(run())
