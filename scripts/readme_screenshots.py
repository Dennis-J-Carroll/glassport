#!/usr/bin/env python3
"""Regenerate the README screenshots from a real gated session.

    python scripts/readme_screenshots.py [OUT_DIR]      # default docs/screenshots

Records a fresh session with scripts/readme_demo.py (a real `glassport gate`
in front of a hostile demo server), then captures:

  report.png   `glassport report` HTML, rendered by headless Chrome
  detect.png   `glassport detect` terminal output (real stdout, rendered)
  console.png  `glassport serve --http` web console with the session open
  tui.png      `glassport tui` curses view, captured from a tmux pane

Dev-only tooling, not part of the package: needs google-chrome (or $CHROME),
node >= 22 (for scripts/cdp_screenshot.mjs), and tmux. Pillow, if installed,
trims empty background. Nothing here is a runtime dependency of glassport.
"""
from __future__ import annotations

import html
import os
import re
import shutil
import socket
import subprocess
import sys
import tempfile
import time
from pathlib import Path

REPO = Path(__file__).resolve().parent.parent
sys.path.insert(0, str(REPO / "scripts"))
import readme_demo  # noqa: E402  (sibling script)

CHROME = os.environ.get("CHROME", "google-chrome")
ENV = {**os.environ, "PYTHONPATH": str(REPO / "src"), "TERM": "xterm-256color"}
SESSION = "demo-notes-server.jsonl"

TERMINAL_CSS = """
body{margin:0;background:#0d1117;font:13px/18px ui-monospace,SFMono-Regular,Menlo,
Consolas,"DejaVu Sans Mono",monospace;color:#c9d1d9}
.win{margin:16px;border:1px solid #30363d;border-radius:8px;overflow:hidden}
.bar{background:#161b22;padding:7px 12px;color:#8b949e;font-size:12px}
.bar i{display:inline-block;width:11px;height:11px;border-radius:50%;margin-right:6px;
vertical-align:-1px}
pre{margin:0;padding:12px 14px;white-space:pre-wrap;word-break:break-word}
.p{color:#7ee787}.c0{color:#0d1117}.c1{color:#ff7b72}.c2{color:#7ee787}
.c3{color:#e3b341}.c4{color:#79c0ff}.c5{color:#d2a8ff}.c6{color:#56d4dd}
.c7{color:#c9d1d9}.b0{background:#484f58}.b1{background:#8e1519}.b2{background:#1a7f37}
.b3{background:#9e6a03}.b4{background:#1f6feb}.b5{background:#8250df}.b6{background:#1b7c83}
.b7{background:#c9d1d9}.cr{color:#0d1117}.bold{font-weight:bold}.dim{opacity:.6}
"""


def run(cmd, **kw) -> subprocess.CompletedProcess:
    return subprocess.run(cmd, env=ENV, capture_output=True, text=True, **kw)


def chrome_shot(url: str, out: Path, width: int, height: int) -> None:
    subprocess.run([CHROME, "--headless=new", "--disable-gpu", "--hide-scrollbars",
                    "--no-first-run", f"--window-size={width},{height}",
                    f"--screenshot={out}", url],
                   check=True, capture_output=True, timeout=90)


def trim(png: Path, pad: int = 16) -> None:
    """Crop uniform background from the bottom/right (Pillow optional)."""
    try:
        from PIL import Image, ImageChops
    except ImportError:
        return
    img = Image.open(png).convert("RGB")
    bg = Image.new("RGB", img.size, img.getpixel((img.width - 1, img.height - 1)))
    box = ImageChops.difference(img, bg).getbbox()
    if box:
        img.crop((0, 0, min(img.width, box[2] + pad),
                  min(img.height, box[3] + pad))).save(png)


def ansi_to_html(text: str) -> str:
    """Minimal SGR renderer for curses output: 8 colours, bold, dim, reverse."""
    out, state = [], {"fg": None, "bg": None, "bold": False, "dim": False, "rev": False}

    def span_open() -> str:
        fg, bg = state["fg"], state["bg"]
        if state["rev"]:   # reversed: text takes the background colour
            fg, bg = (bg if bg is not None else "r"), (fg if fg is not None else 7)
        classes = ([f"c{fg}"] if fg is not None else []) + \
                  ([f"b{bg}"] if bg is not None else []) + \
                  (["bold"] if state["bold"] else []) + (["dim"] if state["dim"] else [])
        return f'<span class="{" ".join(classes)}">' if classes else "<span>"

    pos = 0
    out.append(span_open())
    for m in re.finditer(r"\x1b\[([0-9;]*)m", text):
        out.append(html.escape(text[pos:m.start()]))
        pos = m.end()
        codes = [int(c) for c in m.group(1).split(";") if c] or [0]
        for c in codes:
            if c == 0:
                state.update(fg=None, bg=None, bold=False, dim=False, rev=False)
            elif c == 1:
                state["bold"] = True
            elif c == 2:
                state["dim"] = True
            elif c == 7:
                state["rev"] = True
            elif 30 <= c <= 37:
                state["fg"] = c - 30
            elif c == 39:
                state["fg"] = None
            elif 40 <= c <= 47:
                state["bg"] = c - 40
            elif c == 49:
                state["bg"] = None
        out.append("</span>" + span_open())
    out.append(html.escape(text[pos:]) + "</span>")
    return "".join(out)


def terminal_page(title: str, body_html: str) -> str:
    dots = ('<i style="background:#ff5f57"></i><i style="background:#febc2e"></i>'
            '<i style="background:#28c840"></i>')
    return (f"<!doctype html><meta charset=utf-8><style>{TERMINAL_CSS}</style>"
            f'<div class=win><div class=bar>{dots} {html.escape(title)}</div>'
            f"<pre>{body_html}</pre></div>")


def free_port() -> int:
    with socket.socket() as s:
        s.bind(("127.0.0.1", 0))
        return s.getsockname()[1]


def main(out_dir: Path) -> None:
    out_dir.mkdir(parents=True, exist_ok=True)
    work = Path(tempfile.mkdtemp(prefix="gp-shots-"))
    logs = work / "logs"
    session = readme_demo.record(work / "raw")
    logs.mkdir()
    log = logs / SESSION                      # neutral name: no local paths
    shutil.copy(session, log)

    # 1. HTML session report
    run([sys.executable, "-m", "glassport.tap", "report", str(log)], check=True)
    chrome_shot(log.with_suffix(".html").as_uri(), out_dir / "report.png", 1280, 2800)
    trim(out_dir / "report.png")

    # 2. detect, as a terminal
    detect = run([sys.executable, "-m", "glassport.tap", "detect", SESSION], cwd=logs)
    page = work / "detect.html"
    page.write_text(terminal_page(
        "glassport detect", f'<span class=p>$ glassport detect {SESSION}</span>\n'
        + html.escape(detect.stdout.rstrip())), encoding="utf-8")
    chrome_shot(page.as_uri(), out_dir / "detect.png", 1400, 900)
    trim(out_dir / "detect.png")

    # 3. web console, session opened through its own attach()
    port = free_port()
    server = subprocess.Popen([sys.executable, "-m", "glassport.tap", "serve", "--http",
                               "--port", str(port), "--log-dir", str(logs)],
                              env=ENV, stdout=subprocess.DEVNULL, stderr=subprocess.DEVNULL)
    try:
        time.sleep(1.5)
        subprocess.run(["node", str(REPO / "scripts" / "cdp_screenshot.mjs"),
                        f"http://127.0.0.1:{port}/", str(out_dir / "console.png"),
                        "1440x620", f'attach("{SESSION}")', "3000"],
                       check=True, capture_output=True, timeout=90)
    finally:
        server.terminate()

    # 4. curses TUI from a detached tmux pane
    name = f"gpshot{os.getpid()}"
    subprocess.run(["tmux", "new-session", "-d", "-s", name, "-x", "150", "-y", "30",
                    f"env PYTHONPATH={REPO / 'src'} TERM=xterm-256color "
                    f"{sys.executable} -m glassport.tap tui {log}"], check=True)
    try:
        time.sleep(3)
        pane = subprocess.run(["tmux", "capture-pane", "-t", name, "-e", "-p"],
                              check=True, capture_output=True, text=True).stdout
    finally:
        subprocess.run(["tmux", "kill-session", "-t", name], capture_output=True)
    page = work / "tui.html"
    page.write_text(terminal_page(f"glassport tui {SESSION}", ansi_to_html(pane.rstrip())),
                    encoding="utf-8")
    chrome_shot(page.as_uri(), out_dir / "tui.png", 1240, 900)
    trim(out_dir / "tui.png")

    shutil.rmtree(work, ignore_errors=True)
    for png in ("report", "detect", "console", "tui"):
        print(out_dir / f"{png}.png")


if __name__ == "__main__":
    main(Path(sys.argv[1]) if len(sys.argv) > 1 else REPO / "docs" / "screenshots")
