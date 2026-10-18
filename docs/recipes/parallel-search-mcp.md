# Example: observe Parallel Search MCP

Last verified: 2026-10-18.

[Parallel Search MCP](https://docs.parallel.ai/integrations/mcp/search-mcp)
provides web search and page fetching over Streamable HTTP. Its anonymous
endpoint needs no account or API key; free-tier searches use Fast mode and
have lower rate limits than authenticated requests.

Start a passive capture in one terminal:

```bash
glassport wrap --log-dir ./parallel-sessions --transport http --url https://search.parallel.ai/mcp
```

Keep it running. In an HTTP-capable MCP client on the same machine, add a
separate server pointing at the printed `http://127.0.0.1:PORT` URL, with no
authentication. For clients that use the `mcpServers` / `url` configuration
format, merge this entry into your existing configuration and replace `PORT`
with the port printed by glassport:

```json
{
  "mcpServers": {
    "parallel-observed": {
      "url": "http://127.0.0.1:PORT"
    }
  }
}
```

Connect that entry so the client initializes the session and lists the tools.
Use one client session per capture to keep its declarations and calls in a
single trace. Calls sent directly to `https://search.parallel.ai/mcp` bypass
the tap.

The declared tools are `web_search` and `web_fetch`. For a benign search,
call `web_search` with these arguments:

```json
{
  "objective": "Find the Python documentation for asyncio TaskGroup.",
  "search_queries": ["Python asyncio TaskGroup documentation"]
}
```

To inspect page fetching, call `web_fetch` with:

```json
{
  "urls": ["https://docs.python.org/3/library/asyncio-task.html"],
  "objective": "Find the TaskGroup usage example."
}
```

After the calls finish, disconnect the client and stop the tap with Ctrl-C.
Use the session log path printed by glassport (replace `<file>` below):

```bash
glassport summarize ./parallel-sessions/<file>.jsonl
glassport detect ./parallel-sessions/<file>.jsonl
glassport report ./parallel-sessions/<file>.jsonl
```

`detect` exits 1 when it finds annotations. This fetch can produce an
`unexpected_egress_host` finding because `docs.python.org` appears in the call
arguments without being declared in the tool surface; inspect the finding's
wire evidence rather than treating it as proof of a separate network connection.

Check the actual tool responses as well as the findings: a recorded call can
still return a service error or a rate-limit response. The report shows what
crossed the MCP connection; it does not reveal the remote service's internal
network activity. Session logs contain full queries and results, so treat
them as sensitive. Those queries and fetch targets are also sent to Parallel,
which runs the search and returns the results, so the same care applies to
what you ask for. `wrap` stays passive; this recipe enables no enforcement
and adds no runtime dependencies. `probe` currently launches stdio servers;
use the HTTP tap for this remote endpoint.
