"""
report.py — M3: render one tap session as a self-contained static HTML
page. Dark, green, no JavaScript, opens on a phone.

The renderer is deliberately dumb in the same way the adapter is: it
draws the trace plus whatever annotations are already attached to it,
and never runs detectors itself. The convenience pipeline is:

    report(log_path)            # adapter -> annotate() -> HTML next to log

    python3 report.py ~/.glassport/sessions/<file>.jsonl [-o out.html]

Every string that came off the wire is escaped before it touches the
page. A hostile server can name a tool '<img onerror=...>'; the report
must render that as text, never as markup — this file opens in a
browser from file:// where injected script would run with local-file
reach.

Severity scale (from detectors.py): 1 = worth a look, 2 = should not
happen, 3 = hostile or hallucinated unless proven otherwise.
"""
from __future__ import annotations

import html
import json
import sys
import unicodedata
from collections import Counter
from datetime import datetime, timezone
from pathlib import Path
from typing import Optional

from glassport import detectors
from glassport.interaction_trace import (
    ActorKind, Annotation, AnnotationKind, Event, EventKind,
    InteractionTrace, PartKind,
)

VERDICTS = {
    0: ("CLEAN", "behavior matched declaration"),
    1: ("WORTH A LOOK", "low-severity anomalies present"),
    2: ("SHOULD NOT HAPPEN", "protocol contract broken"),
    3: ("HOSTILE OR HALLUCINATED", "calls or requests outside any declaration"),
}

_CSS = """
:root { --bg:#0b0f0b; --panel:#111911; --line:#1f2d1f; --fg:#c9e4c9;
        --dim:#739173; --green:#4ade80;
        --sev1:#eab308; --sev2:#fb923c; --sev3:#f87171; }
* { box-sizing: border-box; }
body { background: var(--bg); color: var(--fg); margin: 0 auto;
       padding: 1rem; max-width: 64rem;
       font: 14px/1.55 ui-monospace, SFMono-Regular, Menlo, Consolas,
             "Liberation Mono", monospace; }
h1 { color: var(--green); font-size: 1.2rem; margin: 0 0 .25rem; }
h2 { color: var(--green); font-size: 1rem; border-bottom: 1px solid var(--line);
     padding-bottom: .25rem; margin: 1.5rem 0 .75rem; }
.dim { color: var(--dim); }
.verdict { display: inline-block; padding: .15rem .6rem; border-radius: .25rem;
           font-weight: bold; margin: .5rem 0; }
.v0 { color: #052e16; background: var(--green); }
.v1 { color: #1c1400; background: var(--sev1); }
.v2 { color: #2a1200; background: var(--sev2); }
.v3 { color: #2d0606; background: var(--sev3); }
.chips span { display: inline-block; background: var(--panel);
              border: 1px solid var(--line); border-radius: .25rem;
              padding: 0 .5rem; margin: 0 .25rem .25rem 0; }
.chips .bad { border-color: var(--sev3); color: var(--sev3); }
.evt { background: var(--panel); border: 1px solid var(--line);
       border-radius: .25rem; padding: .4rem .6rem; margin: 0 0 .5rem; }
.evt .head { display: flex; flex-wrap: wrap; gap: .6rem; align-items: baseline; }
.evt .seq { color: var(--dim); min-width: 4.5rem; }
.evt .dir { color: var(--green); }
.evt.s2c .dir { color: #7dd3fc; }
.evt .ref { color: var(--dim); }
details { margin-top: .3rem; }
summary { cursor: pointer; color: var(--dim); }
pre { background: var(--bg); border: 1px solid var(--line);
      border-radius: .25rem; padding: .5rem; margin: .3rem 0 0;
      white-space: pre-wrap; word-break: break-word; overflow-x: auto; }
.ann { border-left: 3px solid; border-radius: 0 .25rem .25rem 0;
       padding: .25rem .6rem; margin: .4rem 0 0; }
.ann[data-sev="1"] { border-color: var(--sev1); color: var(--sev1); }
.ann[data-sev="2"] { border-color: var(--sev2); color: var(--sev2); }
.ann[data-sev="3"] { border-color: var(--sev3); color: var(--sev3); }
/* info (e.g. gate enforcement) is a record, not an alarm — keep it green;
   placed after the sev rules so it wins at equal specificity */
.ann[data-kind="info"] { border-color: var(--green); color: var(--green); }
footer { color: var(--dim); border-top: 1px solid var(--line);
         margin-top: 2rem; padding-top: .5rem; font-size: .85em; }
"""


# Look-alike / hidden characters html.escape leaves untouched. A hostile
# server can name a tool with a right-to-left override, a zero-width joiner, or
# a Cyrillic/Armenian homoglyph; escaping renders the markup inert but the
# *deception* survives into the report a human reads to make a trust decision.
# We REVEAL each such character as a visible codepoint sentinel (‹U+XXXX›)
# rather than silently dropping it — the analyst must see the server used one.
_HOMOGLYPHS = frozenset(chr(k) for k in detectors._CONFUSABLES) | {
    "ˋ",   # MODIFIER LETTER GRAVE ACCENT — backtick look-alike
    "Ѕ",   # CYRILLIC CAPITAL LETTER DZE — 'S' look-alike
}
_SAFE_WS = frozenset("\t\n\r ")


def _is_deceptive(ch: str) -> bool:
    if ch in _SAFE_WS:                       # ordinary layout whitespace stays
        return False
    if ch in _HOMOGLYPHS:
        return True
    if detectors._INVISIBLE_RE.match(ch):    # bidi + zero-width + Hangul filler
        return True
    return unicodedata.category(ch) in ("Cc", "Cf", "Cn", "Co", "Cs")


def _neutralize(text: str) -> str:
    """Reveal deceptive Unicode as visible ‹U+XXXX› sentinels; legitimate text
    (letters, whitespace, CJK, emoji) passes through untouched."""
    if text.isascii() and text.isprintable():          # common fast path
        return text
    return "".join(f"‹U+{ord(ch):04X}›" if _is_deceptive(ch) else ch
                   for ch in text)


def _redact_secrets(text: str) -> str:
    """Replace any credential/PII the detectors recognize with a
    non-reversible tag, so the rendered report is safe to share. Reuses the
    exact scan + redaction the runtime detector uses — a tool argument or
    result carrying a live key must never reach the HTML verbatim."""
    try:
        hits = detectors._scan_pii(text)
    except Exception:
        return text
    for pat, value in hits:
        if value and value in text:
            text = text.replace(value, detectors._redact(value, pat.category))
    return text


def _esc(value) -> str:
    """Render an attacker-controlled value inert. Order matters: redact secrets
    on the raw bytes first (the detector normalizes internally), then reveal
    deceptive Unicode, then HTML-escape the markup."""
    return html.escape(_neutralize(_redact_secrets(str(value))), quote=True)


def _pretty(content) -> str:
    if isinstance(content, str):
        return content
    try:
        return json.dumps(content, indent=2, ensure_ascii=False, default=str)
    except (TypeError, ValueError):
        return str(content)


def _event_label(e: Event) -> str:
    md = e.metadata
    if e.kind == EventKind.TOOL_CALL:
        for p in e.parts:
            if p.kind == PartKind.TOOL_USE:
                return f"tools/call · {p.content.get('name', '?')}"
        return "tools/call"
    if e.kind == EventKind.TOOL_RESULT:
        label = f"tool result · {md.get('tool_name', '?')}"
        for p in e.parts:
            if p.kind == PartKind.TOOL_RESULT and p.content.get("is_error"):
                label += " · ERROR"
        return label
    if e.kind == EventKind.MESSAGE:
        if md.get("unparsed"):
            return "unparseable wire line"
        if md.get("responds_to"):
            return f"reply to {md['responds_to']}"
        label = md.get("method") or "message"
        if md.get("server_initiated") and not md.get("notification"):
            label += " · server-initiated request"
        elif md.get("notification"):
            label += " · notification"
        return label
    if e.kind == EventKind.STATE_CHANGE:
        if md.get("error_message") is not None:
            return "protocol error"
        replied = md.get("method_replied_to")
        return f"response · {replied}" if replied else "state change"
    return e.kind.value


def render_html(trace: InteractionTrace, source_name: str = "") -> str:
    """Trace + attached annotations -> one self-contained HTML page."""
    actors = {a.id: a for a in trace.actors}
    seq_of = {e.id: e.metadata.get("seq") for e in trace.events}
    anns_by_event: dict[str, list[Annotation]] = {}
    for a in trace.annotations:
        anns_by_event.setdefault(a.event_id, []).append(a)

    # INFO annotations (e.g. gate enforcement records) never drive the
    # verdict — a blocked call is judged by its own non-INFO annotations
    sev_counts = Counter(a.severity for a in trace.annotations
                         if a.kind != AnnotationKind.INFO)
    max_sev = max(sev_counts, default=0)
    verdict, verdict_text = VERDICTS[max_sev]

    declared = sorted(trace.declared_tools())
    called = [name for _, name in trace.called_tools()]
    fabricated = {name for _, name in trace.fabricated_tool_calls()}

    out: list[str] = []
    w = out.append
    w("<!DOCTYPE html>")
    w('<html lang="en"><head><meta charset="utf-8">')
    w('<meta name="viewport" content="width=device-width, initial-scale=1">')
    w(f"<title>glassport · {_esc(source_name or trace.id)}</title>")
    w(f"<style>{_CSS}</style></head><body>")

    w("<h1>glassport session report</h1>")
    w(f'<div class="dim">{_esc(source_name or trace.id)}</div>')
    w(f'<div class="verdict v{max_sev}">{verdict}</div>')
    w(f'<div class="dim">{_esc(verdict_text)}'
      + (" · " + " · ".join(f"{sev_counts[s]} × sev {s}"
                            for s in sorted(sev_counts, reverse=True))
         if sev_counts else "")
      + "</div>")

    w("<h2>surface</h2>")
    w('<div class="chips">declared: '
      + ("".join(f"<span>{_esc(n)}</span>" for n in declared)
         or '<span class="dim">— no tools/list seen</span>')
      + "</div>")
    w('<div class="chips">called: '
      + ("".join(
          f'<span class="{"bad" if n in fabricated else ""}">{_esc(n)}</span>'
          for n in called)
         or '<span class="dim">—</span>')
      + "</div>")

    w("<h2>timeline</h2>")
    for e in trace.events:
        md = e.metadata
        actor = actors.get(e.actor_id)
        is_client = actor is not None and actor.kind == ActorKind.AGENT
        side = "c2s" if is_client else "s2c"
        arrow = "→" if is_client else "←"
        seq = md.get("seq")

        w(f'<div class="evt {side}" data-seq="{_esc(seq)}">')
        w('<div class="head">'
          f'<span class="seq">seq {_esc(seq)}</span>'
          f'<span class="dir">{arrow} {_esc(actor.name if actor else "?")}</span>'
          f"<span>{_esc(_event_label(e))}</span>")
        parent_seq = seq_of.get(e.parent_event_id)
        if e.parent_event_id and parent_seq is not None and \
                e.kind in (EventKind.TOOL_RESULT, EventKind.MESSAGE,
                           EventKind.STATE_CHANGE):
            w(f'<span class="ref">↳ seq {_esc(parent_seq)}</span>')
        w("</div>")

        for p in e.parts:
            w(f"<details><summary>{_esc(p.kind.value)}</summary>"
              f"<pre>{_esc(_pretty(p.content))}</pre></details>")

        for a in sorted(anns_by_event.get(e.id, ()),
                        key=lambda a: -a.severity):
            marker = "•" if a.kind.value == "info" else "⚠"
            w(f'<div class="ann" data-sev="{_esc(a.severity)}" '
              f'data-kind="{_esc(a.kind.value)}">'
              f"{marker} {_esc(a.subcategory)} · sev {_esc(a.severity)} · "
              f"{_esc(a.kind.value)}<br>{_esc(a.explanation)}</div>")
        w("</div>")

    stamp = datetime.now(timezone.utc).strftime("%Y-%m-%d %H:%M UTC")
    w(f"<footer>glassport · {len(trace.events)} events · "
      f"{len(trace.annotations)} annotations · generated {stamp}<br>"
      "severity: 1 worth a look · 2 should not happen · "
      "3 hostile or hallucinated</footer>")
    w("</body></html>")
    return "\n".join(out)


def report(log_path: str | Path, out_path: Optional[str | Path] = None,
           server_name: str = "mcp_server") -> Path:
    """Full pipeline: tap log -> trace -> detectors -> HTML next to the log."""
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport import detectors

    log_path = Path(log_path)
    trace = from_mcp_session_file(log_path, server_name=server_name)
    detectors.annotate(trace)
    out = Path(out_path) if out_path else log_path.with_suffix(".html")
    out.write_text(render_html(trace, source_name=log_path.name),
                   encoding="utf-8")
    return out


def main(argv: list[str]) -> int:
    args = list(argv)
    out: Optional[str] = None
    if "-o" in args:
        i = args.index("-o")
        try:
            out = args[i + 1]
        except IndexError:
            print("usage: report.py <session.jsonl> [-o out.html]",
                  file=sys.stderr)
            return 2
        del args[i:i + 2]
    if len(args) != 1:
        print("usage: report.py <session.jsonl> [-o out.html]",
              file=sys.stderr)
        return 2
    written = report(args[0], out)
    print(written)
    return 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
