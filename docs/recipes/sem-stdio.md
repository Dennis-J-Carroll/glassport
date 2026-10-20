# Example: observe local code lookup over Sem MCP

[Sem](https://github.com/Ataraxy-Labs/sem) provides local code lookup over stdio.
This recipe records its declarations, requests, and responses with glassport's
passive tap. It does not prove that Sem's code analysis is complete or correct.

Install glassport and Sem on the machine running your MCP client, and confirm
`glassport --help` and `sem --version` work. This recipe was tested with Sem 0.27.0.
Merge this entry into a client that accepts `mcpServers` configuration:

```json
{
  "mcpServers": {
    "sem-observed": {
      "command": "glassport",
      "args": ["wrap", "--log-dir", "/absolute/path/to/session-logs", "--", "sem", "mcp"],
      "env": {"SEM_REPO": "/absolute/path/to/checkout"}
    }
  }
}
```

Replace both paths before connecting. Use a trusted checkout and a private log
directory outside it, so captured source is not accidentally committed. Both
executables must be on the client's `PATH` (or use absolute executable paths).
Connect this entry rather than a separate direct Sem entry, which bypasses the tap.

After initialization and `tools/list`, call the declared `sem_find` tool with a
symbol that exists in your checkout, for example:

```json
{"query": "parse_config", "mode": "context", "token_budget": 1200}
```

Disconnect the client to finish the session. Using the JSONL path printed by
glassport on stderr, inspect the capture:

```sh
glassport summarize /absolute/path/to/session-logs/<session>.jsonl
glassport detect /absolute/path/to/session-logs/<session>.jsonl
glassport report /absolute/path/to/session-logs/<session>.jsonl
```

Check the actual response, including `isError`, as well as annotations. `detect`
exits 1 when it finds annotations; findings must be interpreted against the
recorded wire evidence, not treated as proof of internal filesystem or network
activity. This recipe enables no enforcement and adds no runtime dependencies.

Logs contain code queries and returned source. Treat them as sensitive. A model
using this server will also receive that source. Sem may write a repository index;
`SEM_REPO` is a selector, not a sandbox, and the full server includes validation
tools that can execute commands. This recipe calls only `sem_find`: review the
other declared tools before granting an agent permission to use them.
