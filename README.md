<p align="center">
  <img src="https://raw.githubusercontent.com/Dennis-J-Carroll/glassport/main/assets/glassport_logo-360.jpg" alt="Glassport logo" width="160">
</p>

# glassport

**See what an MCP server actually does, not just what it declares.**

<p align="center">
  <img src="https://raw.githubusercontent.com/Dennis-J-Carroll/glassport/main/docs/screenshots/probe.gif" alt="glassport probe: the reference filesystem server completes its handshake with 14 tools declared; a server that exits on initialize is reported as INCOMPLETE" width="820">
</p>

<p align="center">
  <img src="https://raw.githubusercontent.com/Dennis-J-Carroll/glassport/main/docs/screenshots/probe-report.png" alt="glassport probe report for the reference filesystem server: CLEAN verdict, 14 declared tools, handshake timeline" width="820">
</p>

An MCP server tells your agent what it offers in its `tools/list` handshake. Everything after that is behavior. Glassport sits on the wire between the two and reports the gap: calls outside the declared surface, secrets leaving in arguments, a tool list that quietly changes mid-session. Point it at a server and it plays the client, or put it in front of a real agent session and it records passively. No cloud, no sandbox, zero dependencies.

```bash
pip install glassport
glassport probe -- npx -y @modelcontextprotocol/server-filesystem /tmp
# -> handshake, tools/list, detectors; prints the path to an HTML report
```

- **Real sessions:** `glassport wrap -- <server command>` in your MCP client config, then `glassport report <session.jsonl>`.
- **CI:** `glassport audit <path> --sarif` reads server source without running it and uploads to the GitHub Security tab.

**[Deeper docs →](https://github.com/Dennis-J-Carroll/glassport/blob/main/docs/guide.md)** · MIT · Python 3.10+ · runs in Termux
