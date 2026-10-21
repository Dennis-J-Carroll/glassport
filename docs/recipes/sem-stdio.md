# Example: observe local code lookup over Sem MCP

[Sem](https://github.com/Ataraxy-Labs/sem) provides local code lookup over stdio.
This recipe records its declarations, requests, and responses with glassport's
passive tap. It does not prove that Sem's code analysis is complete or correct.

Install glassport and Sem on the machine running your MCP client, and confirm
`glassport --help` and `sem --version` work. This recipe was last re-run with
glassport 0.7.1 and Sem 0.28.1; it was first written against Sem 0.27.0 and
0.28.1, and 0.27.0 was not re-run.

GNU parallel installs its own command named `sem`, so `sem` may resolve to that
instead. `sem --version` prints `sem <version>` (for example `sem 0.28.1`) for
Sem and `GNU parallel …` for the wrong binary. Run the check under the same
`PATH` your MCP client gives glassport, which can differ from your shell's. If
the wrong one resolves, use the absolute path to the Sem binary in the client
configuration below. A wrong binary does not fail loudly: glassport still
reports `session ended (exit 0)`, the capture has zero frames, and `detect`
prints `no findings`.

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

After initialization, send `notifications/initialized` and wait for the
`tools/list` response before calling any tool. A call sent earlier cannot be
checked against a declaration, and `detect` exits 1: `declaration_unavailable`
if `tools/list` was requested but its response had not arrived,
`call_before_declaration` if `tools/list` had not been requested yet, and a
`premature_call` warning (alongside `declaration_unavailable`) if
`notifications/initialized` had not been sent. The
annotation means the call went unchecked, so a clean `detect` says nothing
about an early call. `declaration_unavailable` also appears when the listing is
incomplete or was invalidated; it says only that no complete declaration was
available.
Then call the declared `sem_find` tool with a symbol that exists in your
checkout, for example:

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

A clean run against Sem 0.28.1 looks like this: `summarize` lists eight
declared tools with `sem_find` the only one called, and `detect` prints
`no findings` and exits 0. Check the actual response, including `isError`, as
well as annotations. `detect` exits 1 when it finds any annotation, including
informational ones; it also scans returned source for credential-shaped
strings, so a checkout with key-shaped test fixtures can produce a
`pii_in_result_*` finding in a correctly ordered session. Findings must be
interpreted against the recorded wire evidence, not treated as proof of
internal filesystem or network activity. `summarize` and `report` exited 0
even in captures where `detect` exited 1. `report` writes `<session>.html` beside the JSONL, with
your default file permissions rather than the log's `0600`. This recipe enables
no enforcement and adds no runtime dependencies.

Logs contain code queries and returned source, and `sem_find` can read any text
file in the checkout, not only code. Treat the JSONL and the HTML report as
sensitive. A model using this server will also receive that source.

Sem keeps state outside the log directory. It writes an index of the checkout,
including copies of its file contents, to `~/.cache/sem/repos/<hash>/cache.db`,
and creates `.git/sem/mcp-v2.lock` inside the checkout; remove the cache when
you are done with a throwaway checkout. It also appends launch records
(command, OS, timestamp, version) to `~/.sem/telemetry-spool.jsonl`;
`sem config telemetry` controls whether anything is uploaded. Sem prints
`sem: shared MCP unavailable; falling back to standalone stdio` on stderr and
takes about two seconds to answer `initialize`; both were normal in testing.

`SEM_REPO` is a selector, not a sandbox. The server declares eight tools and
this recipe calls only `sem_find`. It did not exercise `sem_grep`, `sem_impact`,
`sem_check`, `sem_certify`, `sem_diff`, `sem_graph`, or `sem_history`, and none
of the eight declares MCP read-only annotations. `sem_check` runs the checkout's
compiler, linters, and tests, and arbitrary build or test commands through its
`run` argument, so grant it only for a checkout you trust to execute. Review the
other declared tools before granting an agent permission to use them.
