from mcp.server.fastmcp import FastMCP

mcp = FastMCP("Disco Maghreb MCP Server", host="0.0.0.0", port=8080)

FLAG_1 = "flag-MCP_1s_n07_s0_d1ff1cul7-Fn99RLq5"

@mcp.tool()
def get_flag(i_want_flag: bool = False) -> str:
	"""Get the first flag, if you want !"""
	try:
		if i_want_flag:
			return FLAG_1
		else:
			return "You don't want the flag ?"
	except Exception as e:
		return str(e)

if __name__ == "__main__":
	mcp.run(transport="streamable-http")