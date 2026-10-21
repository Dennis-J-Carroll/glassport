# Recipes

Worked examples of observing a real MCP server with glassport's passive tap.

## Accepting a recipe

A recipe is welcome if it:

1. **Reproduces.** A reader can follow it and get the same result. Name the
   server version and glassport version you tested.
2. **Discloses affiliation.** If you maintain or work for the server's vendor,
   say so in the PR description.
3. **Observes, doesn't endorse.** It shows how to inspect traffic. It does not
   claim the server is safe, correct, or complete.
4. **Flags the risks.** State what the captured logs contain, whether they are
   sensitive, and which declared tools you did not exercise.
5. **Changes nothing else.** Docs only: no runtime changes or new dependencies.

Maintainers run each recipe once before merging. Recipes may be removed if
they stop reproducing.

## Index

- [Parallel Search MCP](parallel-search-mcp.md): remote server
- [Sem](sem-stdio.md): local stdio server
