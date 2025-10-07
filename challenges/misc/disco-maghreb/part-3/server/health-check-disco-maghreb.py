from fastmcp import Client
import asyncio

client = Client("http://127.0.0.1:8080/mcp")

async def main():
    async with client:
        # You can check if server is up
        up = await client.ping()
        if up:
            print("Server is up !\n")
        else:
            print("WARNING: SERVER DOWN !")

asyncio.run(main())