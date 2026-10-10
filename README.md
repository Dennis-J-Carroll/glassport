# glassport

**See what an MCP server actually does, not just what it declares.**

<!-- TODO(week 1): replace with the probe GIF -->
<p align="center">
  <img src="https://raw.githubusercontent.com/Dennis-J-Carroll/glassport/main/docs/screenshots/report.png" alt="glassport session report: declared tools, called tools, findings" width="820">
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
