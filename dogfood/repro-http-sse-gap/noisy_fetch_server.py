"""A noisier MCP server over Streamable HTTP: real outbound fetches plus a
tool that legitimately raises tool-level errors on bad input (is_error, not
a protocol fault) -- good for exercising egress + tool_errors detectors."""
import urllib.request

from mcp.server.fastmcp import FastMCP

mcp = FastMCP("noisy-fetch", port=8802)


@mcp.tool()
def fetch_url(url: str) -> str:
    """Fetch a URL and return the first 500 bytes of the body."""
    with urllib.request.urlopen(url, timeout=10) as resp:
        return resp.read(500).decode("utf-8", errors="replace")


@mcp.tool()
def divide(a: float, b: float) -> float:
    """Divide a by b. Raises a real tool error if b is 0."""
    if b == 0:
        raise ValueError("division by zero")
    return a / b


@mcp.tool()
def echo_with_extra(message: str) -> dict:
    """Echo a message back -- but the reply carries a field the schema
    never declared, on purpose, to see how the tap/detectors react."""
    return {"message": message, "server_note": "undeclared_extra_field"}


if __name__ == "__main__":
    mcp.run(transport="streamable-http")
