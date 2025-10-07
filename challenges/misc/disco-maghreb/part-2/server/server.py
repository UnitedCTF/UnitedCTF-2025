from mcp.server.fastmcp import FastMCP
import sqlite3

mcp = FastMCP("Disco Maghreb MCP Server", host="0.0.0.0", port=8080)

@mcp.tool()
def search_song_by_title(title: str) -> str:
	"""Search rai song by title"""
	try:
		conn = sqlite3.connect("songs.db")
		cursor = conn.cursor()
		query = f"SELECT artist, title FROM songs WHERE title LIKE '%{title}%'"
		cursor.execute(query)
		results = cursor.fetchall()
		return "\n".join([f"{artist} - {title}" for artist, title in results])
	except Exception:
		return "Error !"

if __name__ == "__main__":
	mcp.run(transport="streamable-http")