# VHS tape for the README GIF: glassport probe against the reference
# filesystem server.  https://github.com/charmbracelet/vhs
#
# Prereqs (run once, from the repo root, with #92 checked out or merged):
#   pip install -e .              # `glassport probe` on PATH
#   node 18+ with npx on PATH
# Record:
#   vhs docs/screenshots/probe.tape
# Output: docs/screenshots/probe.gif. Then swap the README's report.png
# stand-in for probe.gif (keep the absolute raw.githubusercontent URL so
# it renders on PyPI).

Output docs/screenshots/probe.gif

Require glassport
Require npx

Set Shell "bash"
Set FontSize 18
Set Width 1200
Set Height 560
Set Padding 24
Set Theme "Catppuccin Mocha"
Set TypingSpeed 45ms
Set CursorBlink false

# --- off camera: short prompt, short log dir, warm the npx cache so the
# GIF shows probe, not a package download --------------------------------
Hide
Type "export PS1='$ ' && rm -rf /tmp/gp && mkdir -p /tmp/gp && cd /tmp/gp"
Enter
Type "npx -y @modelcontextprotocol/server-filesystem /tmp </dev/null >/dev/null 2>&1; clear"
Enter
Sleep 20s
Show

# --- beat 1: one command, real server, full handshake --------------------
Type "glassport probe --log-dir /tmp/gp -- npx -y @modelcontextprotocol/server-filesystem /tmp"
Sleep 600ms
Enter
# Wait needs vhs >= 0.8; on older vhs replace this line with `Sleep 8s`
Wait+Screen@60s /report:/
Sleep 3s

# --- beat 2: a server that dies mid-handshake still gets a report,
# marked INCOMPLETE instead of CLEAN --------------------------------------
Type "glassport probe --log-dir /tmp/gp -- python3 -c 'raise SystemExit(1)'"
Sleep 600ms
Enter
Wait+Screen@30s /INCOMPLETE[\s\S]*report:/
Sleep 4s
