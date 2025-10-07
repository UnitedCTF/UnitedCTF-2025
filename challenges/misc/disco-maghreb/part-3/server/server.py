from mcp.server.fastmcp import FastMCP
from pathlib import os, Path

mcp = FastMCP("Disco Maghreb MCP Server", host="0.0.0.0", port=8080)

@mcp.tool()
def get_lyrics(song_title: str) -> str:
    """Get lyrics of your favourite rai song"""
    try:
        song_title = song_title.lower().replace(" ","-") # kebab-case
        path = Path(f"/app/songs-lyrics/{song_title}")
        print(path)
        lyrics = path.read_text()
        return lyrics
    except FileNotFoundError as e:
        print(e)
        songs = '\t- ' + '\n\t- '.join(os.listdir("songs-lyrics"))
        return f"Lyrics for this song not found...\nAvailable songs:\n{songs}"
    except Exception as e:
        print(e)
        return "Error !"

if __name__ == "__main__":
    mcp.run(transport="streamable-http")