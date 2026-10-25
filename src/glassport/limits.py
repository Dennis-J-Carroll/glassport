"""Pure limits derived from capture, trailer, and optional decision records."""
from __future__ import annotations


def compute_limits(header, trailer, journal_records, wire_entries) -> list[dict]:
    """Return named evidence limitations; never infer delivery or authority.

    ``None`` journal means this path has no decision journal. The wire input
    contains parsed wire entries only (header/trailer may be supplied separately).
    No argument is mutated, and output order is stable.
    """
    out: list[dict] = []
    header = header if isinstance(header, dict) else None
    trailer = trailer if isinstance(trailer, dict) else None
    entries = [e for e in (wire_entries or ()) if isinstance(e, dict)]
    journal = [r for r in (journal_records or ()) if isinstance(r, dict)]
    if header is None or header.get("type") != "glassport.header":
        out.append({"code": "header_missing"})
    if header is not None and header.get("transport") == "stdio":
        missing_raw = sum(1 for e in entries if e.get("dir") in ("c2s", "s2c")
                          and "wire_b64" not in e)
        if missing_raw:
            out.append({"code": "stdio_decoded_text_no_raw_bytes",
                        "entries": missing_raw})

    seqs = {e["seq"] for e in entries if type(e.get("seq")) is int}
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

    failures = trailer.get("write_failures") if trailer is not None else None
    if type(failures) is int and failures > 0:
        out.append({"code": "write_failures", "count": failures})

    if not journal:
        out.append({"code": "no_journal_for_path"})
    else:
        absent = sorted({r["wire_seq"] for r in journal
                         if r.get("kind") == "intent"
                         and type(r.get("wire_seq")) is int
                         and r["wire_seq"] not in seqs})
        if absent:
            out.append({"code": "missing_wire_entry", "sequences": absent})

    profile = next((r for r in journal if r.get("kind") == "profile"), None)
    strict = (profile.get("strict") if profile is not None else
              header.get("strict") if header is not None else None)
    if type(strict) is bool:
        out.append({"code": "strict_profile" if strict else "default_profile"})

    out.append({"code": "authorization_not_evaluated"})
    out.append({"code": "no_signature"})
    return out
