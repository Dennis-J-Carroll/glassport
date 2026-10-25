"""Pure limits derived from capture, trailer, and optional decision records.

PLAY-BY-PLAY
------------
Read this file as the list of things a capture does not prove. A report
that says "clean" is worth exactly as much as the gaps behind it, so
`compute_limits()` runs before any verdict is allowed to sound
confident: it names every way the recording could be short, and each
name is a fact about the files, not an inference about the traffic.

The four inputs:

  header   the tap's own first line: transport, mode, profile.
  trailer  the tap's metrics line at session end: seq range, write
           failures, log digest.
  journal  optional decision-journal records, or None when this capture
           path has no journal at all.
  entries  parsed wire entries only.

Checks run in order of trust: were the bookends written, are the frames
we hold complete, is the numbering continuous, did the writer admit
failures, does the journal agree with the wire, which profile was this.
Two unconditional lines close the list: no authorization was evaluated,
and no signature covers the capture.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not read files, parse JSON, or decide anything. It never turns a
gap into a finding, never infers that a missing frame was dropped by an
attacker, and never claims the capture is complete. A limitation is a
statement about evidence.
"""
from __future__ import annotations


def compute_limits(header, trailer, journal_records, wire_entries) -> list[dict]:
    """Return named evidence limitations; never infer delivery or authority.

    ``None`` journal means this path has no decision journal. The wire input
    contains parsed wire entries only (header/trailer may be supplied separately).
    No argument is mutated, and output order is stable.
    """
    # PLAY: Every capture is asked what it fails to prove before anyone
    # reads a finding out of it. Header and trailer are the tap's own
    # bookends; if either is missing, the capture was cut short and the
    # honest answer is a named limitation, not a guess about lost bytes.
    out: list[dict] = []
    # PLAY: Callers hand over whatever the parser produced, so anything
    # that is not a dict degrades to "absent" instead of raising. A
    # limit list is still useful when the inputs are garbage -- that is
    # exactly the case where the caller most needs to be told the truth.
    header = header if isinstance(header, dict) else None
    trailer = trailer if isinstance(trailer, dict) else None
    entries = [e for e in (wire_entries or ()) if isinstance(e, dict)]
    journal = [r for r in (journal_records or ()) if isinstance(r, dict)]
    # PLAY: Without a header we cannot even say which transport was in
    # use, so "we do not know what the raw bytes were" is reported
    # alongside -- one missing fact implies the other.
    if header is None or header.get("type") != "glassport.header":
        out.append({"code": "header_missing"})
        out.append({"code": "unknown_transport_raw_bytes"})
    if trailer is None or trailer.get("type") != "glassport.metrics":
        out.append({"code": "trailer_missing"})
    # PLAY: stdio frames arrive as text. When the log kept only the
    # decoded line and not the exact bytes, every later claim is about a
    # re-encoding, not about what crossed the wire -- so the count of
    # such entries is published rather than quietly tolerated.
    if header is not None and header.get("transport") == "stdio":
        missing_raw = sum(1 for e in entries if e.get("dir") in ("c2s", "s2c")
                          and "wire_b64" not in e)
        if missing_raw:
            out.append({"code": "stdio_decoded_text_no_raw_bytes",
                        "entries": missing_raw})

    # PLAY: Sequence numbers are the proof that the middle of a session
    # was recorded at all. `type(...) is int` again keeps bool out of the
    # set, since True would masquerade as frame number 1.
    seqs = {e["seq"] for e in entries if type(e.get("seq")) is int}
    # PLAY: The trailer's own claimed range is preferred over min/max of
    # the entries that survived. Those two are not the same: if the tail
    # of the log was lost, the surviving entries span a shorter range and
    # the gap would look like a clean ending. Trusting the tap's stated
    # range is what lets a truncated tail show up as missing.
    span = trailer.get("seq_range") if trailer is not None else None
    if (isinstance(span, list) and len(span) == 2
            and all(type(n) is int and n > 0 for n in span)
            and span[0] <= span[1]):
        first, last = span
    elif seqs:
        first, last = min(seqs), max(seqs)
    else:
        first = last = None
    if first is not None:
        # PLAY: A walk, not a set difference. `cursor` tracks the next
        # number that should exist, so each jump forward becomes one
        # closed range; anything after the last entry is reported as a
        # tail gap, which is the shape a killed process leaves behind.
        gaps = []
        cursor = first
        for n in sorted(n for n in seqs if first <= n <= last):
            if n > cursor:
                gaps.append([cursor, n - 1])
            cursor = n + 1
        if cursor <= last:
            gaps.append([cursor, last])
        if gaps:
            out.append({"code": "seq_gap", "ranges": gaps})

    # PLAY: The writer counting its own failed appends is the only place
    # that fact ever exists; nothing downstream can reconstruct it from
    # a shorter log. Zero is not reported, because zero is not a limit.
    failures = trailer.get("write_failures") if trailer is not None else None
    if type(failures) is int and failures > 0:
        out.append({"code": "write_failures", "count": failures})

    # PLAY: No journal is not an error, it is a fact about the capture
    # path: passive stdio has no decisions to record. Saying so keeps
    # "nothing was decided" from being read as "nothing was wrong".
    if not journal:
        out.append({"code": "no_journal_for_path"})
    else:
        if any(r.get("kind") == "truncated" for r in journal):
            out.append({"code": "journal_truncated"})
        # PLAY: Every decision names the wire entry it was made about.
        # If that entry is not in the capture, the journal and the wire
        # disagree, and the specific sequence numbers are published so
        # the discrepancy can be chased instead of just flagged.
        absent = sorted({r["wire_seq"] for r in journal
                         if r.get("kind") == "intent"
                         and type(r.get("wire_seq")) is int
                         and r["wire_seq"] not in seqs})
        if absent:
            out.append({"code": "missing_wire_entry", "sequences": absent})

    # PLAY: The journal's profile record wins over the header, because a
    # run can be started in one mode and switch. Neither is required: if
    # no strict flag can be found the profile is simply not asserted,
    # rather than assumed to be the default.
    profile = next((r for r in journal if r.get("kind") == "profile"), None)
    strict = (profile.get("strict") if profile is not None else
              header.get("strict") if header is not None else None)
    if type(strict) is bool:
        out.append({"code": "strict_profile" if strict else "default_profile"})

    # PLAY: These two are unconditional and deliberately last. A capture
    # never evaluates whether a caller was authorized to make a request,
    # and no signature here covers the log -- if you want either, that is
    # a separate artifact you have to produce and verify yourself.
    out.append({"code": "authorization_not_evaluated"})
    out.append({"code": "no_signature"})
    return out
