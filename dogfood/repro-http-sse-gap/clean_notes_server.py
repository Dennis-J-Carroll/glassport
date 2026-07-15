"""A small, well-behaved MCP server over Streamable HTTP. Real tools, no tricks."""
from mcp.server.fastmcp import FastMCP

mcp = FastMCP("clean-notes", port=8801)

_NOTES: dict[str, str] = {}


@mcp.tool()
def add_note(title: str, body: str) -> str:
    """Store a note under a title."""
    _NOTES[title] = body
    return f"saved '{title}' ({len(body)} chars)"


@mcp.tool()
def get_note(title: str) -> str:
    """Retrieve a previously stored note."""
    return _NOTES.get(title, f"no note titled '{title}'")


@mcp.tool()
def list_notes() -> list[str]:
    """List all stored note titles."""
    return list(_NOTES.keys())


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
