import asyncio
from fastmcp import Client, FastMCP
import json

client = Client("http://127.0.0.1:8080/mcp") # CHANGE IP


async def main():
    async with client:
        # You can check if server is up
        await client.ping()
        print("Server is up !")

        # List available tools
        tools = await client.list_tools()
        for tool in tools: # pretty print
            print(json.dumps(tool.model_dump(),indent=4))

        # Execute the tool get_flag with i_want_flag = True
        result = await client.call_tool("get_flag", {"i_want_flag": True})
        print(result.structured_content)

asyncio.run(main())