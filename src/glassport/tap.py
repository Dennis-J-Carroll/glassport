#!/usr/bin/env python3
"""
glassport_tap — M0 of the Glassport active proxy.

A passive stdio man-in-the-middle for MCP servers. Drop it between any
MCP client (Claude Desktop, Cursor, Claude Code) and any stdio MCP
server. It relays every byte faithfully and logs every JSON-RPC frame
to a JSONL session file.

    The glass before the port. Observe first. Enforce later.

Usage (wrap mode — replaces the server command in your MCP config):

    {
      "mcpServers": {
        "exa": {
          "command": "python3",
          "args": ["/path/to/glassport_tap.py", "--", "npx", "exa-mcp-server"]
        }
      }
    }

Usage (summarize mode — read a session log after the fact):

    python3 glassport_tap.py summarize ~/.glassport/sessions/<file>.jsonl

Design constraints honored:
  * Zero dependencies. Pure stdlib. Runs in Termux.
  * Byte-faithful relay. The tap must NEVER alter, reorder, or delay
    frames beyond pipe latency. If logging fails, relaying continues.
  * Newline-delimited JSON framing per MCP stdio transport. Lines that
    don't parse as JSON are relayed verbatim and logged as raw.
  * Crash-isolated: a logging bug must not kill the session.

Frame log schema (one JSON object per wire line, between header and trailer):
  {
    "schema_version": "0.2",
    "seq":  int,            # monotonic per session, both directions
    "ts":   str,            # ISO 8601 UTC
    "dir":  "c2s" | "s2c",  # client→server or server→client
    "frame": dict | null,   # parsed JSON-RPC frame, if parseable
    "raw":  str | null      # raw line, only when parsing failed
  }

This log is the precursor wire format for InteractionTrace: the
from_mcp_session() adapter consumes exactly these records, and the
summarize command routes through that same adapter — one code path
from wire to report.

PLAY-BY-PLAY
------------
This file is the entry point (the `glassport` console script calls `cli`)
and the only place where bytes actually move between a client and a
server. Read it in this order.

1. Helpers that make parsing safe. MCP stdio is newline-delimited JSON,
   and every peer is free to send something a different JSON parser
   would read differently. `_lenient_int`, `_unique_object`,
   `_nesting_exceeds`, and `_dumps_strict_json` exist so the gate never
   judges a message other than the one the peer will receive.
2. `SessionLog` — the append-only JSONL writer. One envelope per wire
   line, one lock, and no exception ever escapes.
3. `Gate` — the optional enforcement layer: declaration tracking, the
   checks, and the synthesized errors a blocked request earns.
4. `pump` / `run_tap` — the relay itself: two threads copying pipe to
   pipe, logging on the way past, waiting on the child process.
5. `summarize` and the `_cmd_*` functions — the post-hoc side, which
   reads a log and produces a report, SARIF, or advice.
6. `main` — argument parsing and dispatch for every verb.

The one rule that shapes everything else: the relay is sacred. A bug in
logging, detection, or the gate may never alter, delay, or kill the live
session. That is why so many functions here catch broadly and return
None, and why the block paths are the only places allowed to write
bytes the server never produced.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not interpret MCP semantics for the relay (the pump is dumb on
purpose), it does not keep a session in memory as a model, and it does
not push anything anywhere. Analysis lives in detectors, state in
session, rendering in report.

Author: Dennis J. Carroll · 2026 (skeleton drafted with Claude)
"""
from __future__ import annotations

from glassport.adapters.mcp_session import MCPTraceBuilder
from glassport.attestation import ATTESTATION_KEY, validate_public_key
from glassport.evidence import gate_level
from glassport.detectors import (
    MAX_SCAN_BYTES, find_taint, _schema_problems, _scan_pii, _redact,
    neutralize_text, _TAINT_PATTERNS,
)

import difflib
import hashlib
import importlib.metadata
import json
import math
import os
import re
import secrets
import shlex
import shutil
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any
from urllib.parse import urlsplit

SCHEMA_VERSION = "0.2"
DEFAULT_LOG_DIR = Path(os.environ.get("GLASSPORT_LOG_DIR",
                                      Path.home() / ".glassport" / "sessions"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _source_commit() -> str | None:
    """Installed VCS provenance or explicit build metadata; never infer HEAD."""
    # PLAY: Two sources only: an explicit environment variable, or the
    # install metadata pip writes. Running `git rev-parse` here would be
    # convenient and wrong -- the checkout on disk is not necessarily the
    # code that is installed, and a log naming the wrong commit makes
    # every provenance claim downstream suspect.
    candidate = os.environ.get("GLASSPORT_COMMIT")
    if candidate is None:
        try:
            direct_url = importlib.metadata.distribution("glassport").read_text(
                "direct_url.json")
            candidate = (json.loads(direct_url or "{}").get("vcs_info") or {}).get(
                "commit_id")
        except (importlib.metadata.PackageNotFoundError, ValueError, AttributeError):
            return None
    # PLAY: Anything that is not a plausible hex commit id becomes None.
    # A log header that echoes an arbitrary string into a "commit" field
    # would be quoting an unverified claim.
    if isinstance(candidate, str) and re.fullmatch(r"[0-9a-fA-F]{7,64}", candidate):
        return candidate.lower()
    return None


def build_session_header(*, transport: str, mode: str, strict: bool = False,
                         remote_url: str | None = None) -> dict:
    """Tap-owned provenance, with no credential-bearing URL or header value."""
    # PLAY: The import is local because the tap is launched as a fresh
    # process for every session; anything imported at module scope is
    # paid for on the wrapped server's startup path.
    from glassport import __version__
    from glassport.decision_journal import (DETECTOR_ENGINE_VERSION,
                                            JOURNAL_SCHEMA, POLICY_VERSION)

    header = {"type": "glassport.header", "schema_version": SCHEMA_VERSION,
              "glassport_version": __version__, "commit": _source_commit(),
              "transport": transport, "mode": mode, "strict": bool(strict),
              "redacted": ["url_userinfo", "url_query", "url_fragment", "url_path",
                           "header_values"],
              "policy_version": POLICY_VERSION,
              "detector_engine": DETECTOR_ENGINE_VERSION,
              "journal_schema": JOURNAL_SCHEMA, "started_at": _now_iso()}
    if remote_url is not None:
        # PLAY: The remote endpoint is recorded as an identity, not as
        # text. Userinfo, query, and fragment are dropped outright, and
        # the path is kept only as a digest -- an MCP endpoint URL can
        # carry a bearer token in any of those parts, and this header is
        # written to disk on every session.
        parsed = urlsplit(remote_url)
        header["remote"] = {
            "scheme": parsed.scheme, "host": parsed.hostname,
            "port": parsed.port,
            "path_sha256": hashlib.sha256(parsed.path.encode("utf-8")).hexdigest(),
        }
    return header


# tools/call arguments nested deeper than this are blocked before any
# scanner runs: the scanners recurse, and a caller-chosen RecursionError
# must not become a fail-open skip of the credential check. Real tool
# schemas are a handful of levels deep.
MAX_ARGUMENT_DEPTH = 64


def _lenient_int(digits: str) -> int | str:
    """parse_int hook: CPython refuses integer literals past
    sys.get_int_max_str_digits() (4300), which V8 accepts. Keep such a
    literal as its digit string so the frame stays inspectable instead of
    becoming a parser differential the gate cannot judge."""
    try:
        return int(digits)
    except ValueError:
        return digits


def _unique_object(pairs: list) -> dict:
    """object_pairs_hook: refuse duplicate keys. Parsers disagree on which
    duplicate wins (V8 and CPython keep the last, some keep the first, serde
    derives reject), so a frame with one is ambiguous and the gate would be
    judging a different message than the peer receives."""
    # PLAY: If a frame says {"id": 1, "id": 2}, the peer that parses it
    # and the gate that judges it could disagree about which id wins. That
    # is a parser differential: the gate would be judging a different
    # message than the one actually delivered. Refusing the frame is the
    # only answer that is not a guess. dict() keeps the last value, which
    # is why a length comparison detects the collision.
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate object key")
    return obj


def _loads(data: bytes) -> Any:
    """json.loads for gate decisions: tolerant of oversized integers, strict
    about duplicate keys (both are parser differentials)."""
    # PLAY: Both hooks are wired here and nowhere else, so every gate
    # decision in this file parses through one function with one policy.
    return json.loads(data, parse_int=_lenient_int, object_pairs_hook=_unique_object)


def _nesting_exceeds(value: Any, limit: int) -> bool:
    """True when dict/list nesting in `value` goes deeper than `limit`
    (a bare container is depth 1). Iterative, so it cannot itself hit the
    recursion limit it guards against."""
    # PLAY: An explicit stack, not recursion. The input is peer-sized, so
    # a recursive depth check would itself crash on the frame it was
    # called in to refuse -- and a crash inside a check is a fail-open.
    stack = [(value, 1)]
    while stack:
        node, depth = stack.pop()
        if isinstance(node, dict):
            children = node.values()
        elif isinstance(node, list):
            children = node
        else:
            continue
        if depth > limit:
            return True
        stack.extend((child, depth + 1) for child in children)
    return False


def _dumps_strict_json(obj: Any) -> str:
    """ASCII json.dumps that never emits Infinity/-Infinity/NaN, which are
    not JSON: strict parsers (V8's JSON.parse) reject the whole message.
    json.loads reads an overflowing literal such as 1e400 as inf; it is
    re-emitted as 1e999, which parses back to the same infinity. NaN (which
    json.loads also accepts) becomes null. Mutates non-finite floats in
    `obj`; the walk is iterative, so peer-sized nesting cannot overflow it."""
    # PLAY: Fast path first. Almost every frame is finite floats only, so
    # the expensive rewrite below only runs when the dump actually
    # contains a token Python spells but JSON does not.
    text = json.dumps(obj, ensure_ascii=True)
    if "Infinity" not in text and "NaN" not in text:
        return text
    # PLAY: The middle step of a three-step trick. Python writes inf as
    # `Infinity`, which strict parsers reject, and json.dumps has no way
    # to emit `1e999` directly. So each non-finite float is temporarily
    # replaced by a random NUL-prefixed sentinel, the object is dumped,
    # and the sentinels are swapped for JSON literals that parse back to
    # the same value. The token is random because a guessable sentinel
    # would let a peer include it in a string and have the swap rewrite
    # attacker-chosen text.
    token = "\x00glassport-" + secrets.token_hex(8)   # unguessable by the peer
    literals = {token + "p": "1e999", token + "m": "-1e999", token + "n": "null"}
    stack = [obj]
    while stack:
        node = stack.pop()
        pairs = node.items() if isinstance(node, dict) else enumerate(node)
        for key, value in list(pairs):
            if isinstance(value, float) and not math.isfinite(value):
                node[key] = token + ("p" if value > 0 else "m" if value < 0 else "n")
            elif isinstance(value, (dict, list)):
                stack.append(value)
    text = json.dumps(obj, ensure_ascii=True)
    for sentinel, literal in literals.items():
        text = text.replace(json.dumps(sentinel, ensure_ascii=True), literal)
    return text


def _minimal_read_response(rid: Any, contents: list) -> bytes:
    """A resources/read response carrying only the string fields a client
    renders from each content item. Used when the server's full frame is
    too deep to re-encode; shallow by construction."""
    # PLAY: The alternative to this would be forwarding a frame the gate
    # could not re-serialize, or dropping the response entirely. Rebuilding
    # a minimal, provably shallow answer keeps the session alive and makes
    # no claim about the parts that were left out.
    kept = [{k: v for k, v in item.items()
             if k in ("uri", "mimeType", "text", "blob") and isinstance(v, str)}
            for item in contents if isinstance(item, dict)]
    return (json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"contents": kept}},
                       ensure_ascii=True) + "\n").encode("utf-8")


def _note_skip(info: dict | None, tool: str | None, reason: str) -> dict:
    """Record a fail-open check fault on the forward marker. The first
    fault keeps the `reason` field; later ones append to `also_skipped`,
    so the log shows every check that could not run."""
    # PLAY: The first fault keeps the stable `reason` key because readers
    # key on it; later faults are still recorded, because a frame that
    # skipped three checks is a weaker observation than one that skipped
    # one, and that difference should not be lost.
    if info is None:
        return {"action": "gate_skipped", "tool": tool, "reason": reason}
    info.setdefault("also_skipped", []).append(reason)
    return info


# ─────────────────────────────────────────────────────────────────
# Session logger — append-only JSONL, thread-safe, failure-isolated.
# ─────────────────────────────────────────────────────────────────
# PLAY: "Failure-isolated" is the whole design. The pumps call into this
# section on every frame; if any of it raised, the exception would travel
# back into the relay loop and end the session. So every public method
# here swallows its own errors and returns None instead.
def _serialize_entry(entry: dict) -> str:
    """One JSONL line for an envelope. A frame that parsed but is too deep to
    re-encode is kept as wire text in the SAME dict (so what a live fold saw
    and what is on disk never differ); a lone surrogate json.loads accepted
    but UTF-8 cannot carry is escaped, never dropped."""
    # PLAY: Two fallbacks, in this order: depth, then encodability. Neither
    # one drops the entry. A log that silently omits the frames it could
    # not encode is worse than one that says "raw text follows", because
    # the omission is invisible.
    try:
        text = json.dumps(entry, ensure_ascii=False)
    except RecursionError:
        # build_session_entry already applied the wire-text fallback for a
        # frame it could not re-encode; a caller-mutated entry gets the same
        # treatment with whatever raw text it carries.
        entry["frame"] = None
        text = json.dumps(entry, ensure_ascii=False)
    try:
        text.encode("utf-8")
    except UnicodeEncodeError:
        text = json.dumps(entry, ensure_ascii=True)
    return text


def build_session_entry(direction: str, line: bytes, gate: dict | None = None,
                        metadata: dict | None = None, *,
                        observation: dict | None = None,
                        wire_bytes: bytes | None = None,
                        seq: int) -> tuple[dict, str]:
    """The envelope :meth:`SessionLog.record` writes for one wire line, plus
    its serialization. Pure: builds the dict every reader (`MCPTraceBuilder`,
    `from_mcp_session_file`, replay) consumes, without touching a file, so a
    live fold can be fed the exact object that is then written."""
    # PLAY: Pure means "no file access", and that is what lets the live
    # gate fold the very same object the log will contain -- one fold, not
    # one for the wire and a second for the file.
    # errors="replace" keeps an invalid byte sequence from raising here;
    # the frame is still a byte string and still relayed unchanged.
    text = line.decode("utf-8", errors="replace").rstrip("\r\n")
    frame, raw = None, None
    try:
        frame = json.loads(text)
    except (json.JSONDecodeError, ValueError, RecursionError):
        raw = text
    entry = {
        "schema_version": SCHEMA_VERSION,
        "seq": seq,
        "ts": _now_iso(),
        "dir": direction,
        "frame": frame,
        "raw": raw,
    }
    if gate is not None:
        entry["gate"] = {**gate, "evidence_level": gate_level(gate)}
    if metadata is not None:
        entry["sse_meta"] = metadata
    if observation is not None:
        entry["http_observation"] = observation
    if wire_bytes is not None:
        # PLAY: Only HTTP frames carry this. Text that was decoded and
        # re-encoded is not the same bytes that crossed the wire, and a
        # capture that claims to hold the raw frame should hold it.
        import base64
        entry["wire_b64"] = base64.b64encode(wire_bytes).decode("ascii")
    try:
        serialized = json.dumps(entry, ensure_ascii=False)
    except RecursionError:
        # Parsed but too deep to re-encode: keep the wire text rather than
        # silently dropping the entry.
        entry["frame"], entry["raw"] = None, text
        serialized = json.dumps(entry, ensure_ascii=False)
    try:
        serialized.encode("utf-8")
    except UnicodeEncodeError:
        # json.loads accepts lone surrogates ("\\ud800") that UTF-8 cannot
        # carry: escape this entry, never drop it.
        serialized = json.dumps(entry, ensure_ascii=True)
    return entry, serialized


class SessionLog:
    # PLAY: Contract for every method below: it never raises. Callers are
    # relay pumps and a gate holding a lock, where an exception would mean
    # a dropped frame or a hung session. A failed write increments
    # write_failures and reports itself once, then returns.
    def __init__(self, path: Path, header: dict | None = None):
        # Create the session dir private (0o700) and the log file private
        # (0o600) explicitly, independent of the caller's umask. Glassport
        # logs full MCP traffic — credentials, PII — so world/group access is
        # a policy violation, not a preference. POSIX only; on other OSes the
        # mode is advisory and we fall back to normal open() (SECURITY.md).
        path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
        if os.name == "posix":
            # mkdir(mode=) is subject to umask, and exist_ok means a looser
            # pre-existing dir is possible — re-assert 0o700 either way.
            try:
                os.chmod(path.parent, 0o700)
            except OSError:
                pass
            # O_CREAT with an explicit 0o600 avoids the window where the file
            # exists at the umask-default mode before a chmod; fchmod
            # re-asserts if the file pre-existed looser.
            fd = os.open(path, os.O_WRONLY | os.O_CREAT | os.O_APPEND, 0o600)
            try:
                os.fchmod(fd, 0o600)
            except OSError:
                pass
            self._fh = os.fdopen(fd, "ab", buffering=0)
        else:
            # Non-POSIX: st_mode is advisory; do not fake enforcement.
            self._fh = open(path, "ab", buffering=0)
        self._lock = threading.Lock()
        self._seq = 0
        self.write_failures = 0
        self._warned_write_failure = False
        self.path = path
        self._digest = hashlib.sha256()
        self._entries_written = 0
        if header is not None:
            try:
                self._write(json.dumps(header, ensure_ascii=True) + "\n")
            except Exception:
                self.close()
                raise

    def _write(self, text: str) -> bytes:
        """Count failed append calls once; caller holds the session lock."""
        # PLAY: The counters here are the capture's own confession. A
        # short or invalid write raises, which record() turns into None,
        # and write_failures carries the count into the trailer so
        # `glassport limits` can report that the log is incomplete.
        try:
            encoded = text.encode("utf-8")
            written = self._fh.write(encoded)
            if type(written) is not int or written < 0 or written > len(encoded):
                raise OSError("invalid session log write count")
            # PLAY: The digest takes only the bytes the write reported,
            # and it is updated BEFORE the short-write check raises. So
            # log_sha256 always describes what actually reached the file,
            # even when the write was truncated.
            self._digest.update(encoded[:written])
            if written != len(encoded):
                raise OSError("short session log write")
            return encoded
        except Exception:
            self.write_failures += 1
            if not self._warned_write_failure:
                self._warned_write_failure = True
                try:
                    print("[glassport] session log write failed; capture incomplete; "
                          "relay continues", file=sys.stderr)
                except Exception:
                    pass
            raise

    def file_mode(self) -> int | None:
        """POSIX permission bits of the open log, or None (non-POSIX / error)."""
        if os.name != "posix":
            return None
        try:
            return os.fstat(self._fh.fileno()).st_mode & 0o777
        except (OSError, ValueError):
            return None

    def record(self, direction: str, line: bytes,
               gate: dict | None = None,
               metadata: dict | None = None, *,
               observation: dict | None = None,
               wire_bytes: bytes | None = None,
               sequence: int | None = None) -> dict | None:
        """Log one wire line; return its envelope on write success, else None.

        Never raises — relay must outlive logging. The receipt proves only a
        successful write call, not fsync durability or transport delivery.
        HTTP observation metadata is trusted outer evidence, never peer JSON.
        wire_bytes optionally preserves exact HTTP frame bytes as base64.
        sequence optionally assigns a strictly increasing caller-owned order,
        preserving linkage even after an earlier failed recording attempt.

        `gate` marks frames the gate acted on: {"action": "blocked"} on a
        c2s frame the server never received, {"action": "injected"} on an
        s2c frame the server never sent. Optional field — older schema 0.1
        logs without it stay readable.

        `metadata` carries transport-level annotations that must not be
        smashed into the parseable frame. For SSE it holds fields such as
        ``event``, ``id``, and ``retry`` so the JSON-RPC payload can still
        be logged as a structured ``frame``.

        Equivalent to :func:`build_session_entry` followed by
        :meth:`write_entry` under one lock; a caller that must fold an entry
        before it knows every outer fact uses those two steps directly.
        """
        try:
            with self._lock:
                seq = self._claim_sequence(sequence)
                entry, text = build_session_entry(
                    direction, line, gate=gate, metadata=metadata,
                    observation=observation, wire_bytes=wire_bytes, seq=seq)
                self._write(text + "\n")
                self._entries_written += 1
                return entry
        except Exception:
            return None  # logging is best-effort; the relay is sacred

    def _claim_sequence(self, sequence: int | None) -> int:
        """Caller holds the lock. Validates and advances the log's sequence."""
        # PLAY: `sequence` is for callers that already own an order -- the
        # HTTP path assigns numbers per stream, so two concurrent streams
        # cannot interleave their frames into a nonsense order. Strictly
        # increasing is enforced because a repeat would make the seq-gap
        # analysis ambiguous.
        if sequence is not None:
            if type(sequence) is not int or sequence <= self._seq:
                raise ValueError('session sequence must increase')
            self._seq = sequence
        else:
            self._seq += 1
        return self._seq

    def write_entry(self, entry: dict, text: str | None = None) -> str | None:
        """Append one envelope built by :func:`build_session_entry`; SHA-256 on
        a successful write call. `text` is its serialization when the caller
        still holds the one build_session_entry returned and has not changed
        the entry since; otherwise it is serialized here. Never raises."""
        # PLAY: The returned digest is a receipt for one successful append
        # call. It is not durability (the OS may not have flushed) and not
        # delivery -- the far side may never read the pipe. Callers that
        # need either of those have to prove it elsewhere.
        try:
            with self._lock:
                self._claim_sequence(entry.get("seq"))
                if text is None:
                    text = _serialize_entry(entry)
                written = self._write(text + "\n")
                self._entries_written += 1
            return hashlib.sha256(written).hexdigest()
        except Exception:
            return None

    def write_json(self, entry: dict) -> str | None:
        """Append one caller-shaped JSON record; SHA-256 on a successful write.

        Not a wire frame and not part of the session schema: this is the
        private-file append primitive (0700 dir, 0600 file, one lock, never
        raises) reused by the decision journal, which owns its OWN files.
        Decision evidence and wire evidence are never written to one file.
        """
        # PLAY: Same private-file discipline, different schema: this is
        # how the decision journal writes, and it deliberately cannot
        # write into the session file. Wire evidence and decision
        # evidence sharing one file would make each one deniable.
        try:
            line = json.dumps(entry, ensure_ascii=False) + "\n"
            with self._lock:
                written = self._write(line)
            return hashlib.sha256(written).hexdigest()
        except Exception:
            return None  # journaling is best-effort; the relay is sacred

    def write_metrics(self, **fields) -> None:
        """One self-observation line at session end (H1.09): what the tap
        itself witnessed — frames seen, blocks, duration, bytes. Tagged
        with "type": "glassport.metrics" so the adapter filters it out of
        every analysis view; detector-side facts are computed offline by
        `glassport health`, never asserted here. Never raises."""
        try:
            with self._lock:
                entry = {"type": "glassport.metrics", "ts": _now_iso(),
                         "frames_seen": self._seq, **fields}
                entry["write_failures"] = self.write_failures
                entry.setdefault("log_bytes", self._fh.tell())
                entry["log_sha256"] = self._digest.hexdigest()
                entry["entries_written"] = self._entries_written
                # PLAY: seq_range comes from this log's own counter, so
                # the trailer's claim can be compared against the seqs
                # that survived. That comparison is how a truncated tail
                # becomes visible in `glassport limits`.
                entry["seq_range"] = [1, self._seq] if self._seq else None
                self._write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # metrics are best-effort; the relay is sacred

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


def open_session_log(path: Path, *, transport: str = "stdio",
                     mode: str = "wrap", strict: bool = False,
                     remote_url: str | None = None,
                     session: bool = True) -> "SessionLog | None":
    """Create a verified-private session log, or return None so the relay
    runs without recording. The relay is sacred: neither an unwritable dir
    nor a permission we could not secure may kill the session — we disable
    logging loudly instead."""
    # PLAY: Two independent failure modes, and the second is the subtle
    # one. The first is the filesystem refusing: no log, session continues.
    # The second is a file that exists and is writable but readable by
    # group or world -- in that case we could record, and we refuse to,
    # because a readable log of a full MCP session is a credential leak
    # with a timestamp.
    try:
        header = (build_session_header(transport=transport, mode=mode,
                                       strict=strict, remote_url=remote_url)
                  if session else None)
        log = SessionLog(path, header=header)
    except OSError as exc:
        print(f"[glassport] logging disabled: cannot write to {path.parent} "
              f"({exc}) -- check permissions or set $GLASSPORT_LOG_DIR; "
              f"relay continues", file=sys.stderr)
        return None
    mode = log.file_mode()
    if mode is not None and (mode & 0o077):
        print(f"[glassport] logging disabled: {path} is not owner-only "
              f"(mode {mode:04o}) -- refusing to record sensitive traffic to "
              f"a readable file; relay continues", file=sys.stderr)
        log.close()
        return None
    return log


# ─────────────────────────────────────────────────────────────────
# Gate — M5. Active enforcement on the c2s path. Opt-in, last, on
# purpose: it ships only because the passive detectors came first.
# ─────────────────────────────────────────────────────────────────
# PLAY: Everything in this section is the one place glassport may write
# bytes a peer never produced. Read the class docstring first: the rule is
# that a block must be provable from the wire, and anything less fails
# open with a marker in the log saying so.
class Gate:
    """
    Blocks c2s tools/call frames that name a tool outside the server's
    declared surface. Everything else relays untouched.

    The gate only blocks what the wire can prove. The declaration is the
    shared SessionState fold (the same one the HTTP gate and replay use):
    only a complete, correlated tools/list reply establishes or replaces
    it; a server's notifications/tools/list_changed or an elapsed ttlMs
    makes it unknown (never empty); a reply from before an invalidation
    restores nothing. A pipelined client may fire tools/call while a
    listing is in flight, so the gate HOLDS such calls (blocking the c2s
    pump; stdio backpressure is the flow control a real client expects
    anyway) until that listing settles or `hold_timeout` expires. With no
    current declaration it fails open and the forwarded frame is logged
    with a "gate_skipped" marker, so the log still shows enforcement was
    impossible. The latest complete declaration IS the contract: a server
    that re-declares a smaller surface shrinks what it may be asked to do.

    A blocked request never reaches the server; the client receives a
    synthesized JSON-RPC error (code -32000) whose error.data carries
    {"glassport": "gate_blocked"} so callers can tell the gate's voice
    from the server's. Both the blocked frame and the injected response
    are logged with a "gate" marker — the session log records what each
    side actually saw, and they legitimately differ.
    """

    # PLAY: State, in the order it matters. The fold (`_builder` plus
    # `_fold_seq`) is the declaration as the server saw it; `_lock` and
    # `_state_changed` let a tools/call wait for an in-flight listing
    # instead of blocking on a guess; `_pending_reads` correlates a
    # resources/read reply with the uri that was asked for, so taint
    # analysis knows what came back from where.
    def __init__(self, hold_timeout: float = 2.0,
                 control_path: "Path | None" = None,
                 idempotency_ttl: float = 5.0,
                 idempotency_max_repeats: int = 3,
                 enforce_attestation: bool = False,
                 attestation_pubkey_b64: str | None = None,
                 strict: bool = False) -> None:
        if enforce_attestation:
            validate_public_key(attestation_pubkey_b64)
        # Fault policy. False (default): a check that cannot run fails open
        # with a logged gate_skipped marker. True (opt-in, `gate --strict`):
        # it blocks instead, naming the fault in data.reason.
        self.strict = strict
        self._lock = threading.Lock()
        # Declaration facts: the wire as the server saw it, folded in order.
        # Guarded by _lock; _state_changed wakes calls held for a listing.
        self._builder = MCPTraceBuilder(retain_events=False)
        self._fold_seq = 0
        self._state_changed = threading.Condition(self._lock)
        self._pending_reads: dict[Any, str] = {}  # jsonrpc id -> uri
        self._hold_timeout = hold_timeout
        self.blocked_count = 0
        self.idempotency_ttl = idempotency_ttl
        self.idempotency_max_repeats = idempotency_max_repeats
        # request_hash -> (count, first_seen_monotonic)
        self._recent_calls: dict[str, tuple[int, float]] = {}
        self.enforce_attestation = enforce_attestation
        self.attestation_pubkey_b64 = attestation_pubkey_b64
        # Runtime enable/disable via an override file (M6 TUI control).
        # None (the default) means enforcement is unconditional. Only a
        # tap launched with `gate --controllable` sets this.
        #
        # Threat-model note: the wrapped server runs as the same user,
        # so a hostile server process could write this file itself —
        # same-uid isolation is not achievable here (such a process
        # could equally kill the tap). The override protects against
        # accidents and cross-user actors; every call forwarded while
        # disabled still carries a "gate_disabled" marker in the log.
        self.control_path = control_path

    def _error_object(self, rid, reason: str, tool: str | None, message: str,
                      suggestion: str | None = None, **extra_data) -> dict | None:
        """The JSON-RPC error object behind _block, or None when `rid` is
        unaddressable (see _block)."""
        # PLAY: Which ids can be answered. A notification has no id. A bool
        # is an int subclass, so True would otherwise be echoed back as
        # request id 1 and answer some other request. Containers are out
        # because re-encoding a deeply nested id could overflow and turn
        # the block into a fail-open forward.
        if rid is None or isinstance(rid, bool) or not isinstance(rid, (str, int, float)):
            return None
        if isinstance(rid, float) and not math.isfinite(rid):
            return None
        data = {"glassport": "gate_blocked", "reason": reason, **extra_data}
        if tool is not None:
            data["tool"] = tool
        if suggestion is not None:
            data["suggestion"] = suggestion
        return {"jsonrpc": "2.0", "id": rid,
                "error": {"code": -32000, "message": message, "data": data}}

    def _strict_block(self, frame: dict, tool: str | None, skipped: dict
                      ) -> tuple[str, bytes | None, dict | None]:
        """Strict mode: a check that could not run blocks the call. The first
        fault is the reason; any later ones travel in also_skipped."""
        reasons = [skipped.get("reason"), *skipped.get("also_skipped", [])]
        reasons = [r for r in reasons if isinstance(r, str)] or ["gate_check_error"]
        extra = {"also_skipped": reasons[1:]} if len(reasons) > 1 else {}
        self.blocked_count += 1
        response = self._block(
            frame.get("id"), reasons[0], tool,
            f"glassport gate: tools/call '{tool}' blocked — strict mode: "
            f"{', '.join(reasons)} could not run",
            suggestion="Retry later; the gate could not complete its checks.",
            **extra)
        return ("block", response,
                {"action": "blocked", "tool": tool, "reason": reasons[0], **extra})

    def fault_verdict(self, line: bytes) -> tuple[str, bytes | None, dict | None]:
        """Decision for a line whose check_c2s raised. Default: forward the
        original bytes with a gate_skipped marker (fail open, visibly).
        Strict and enforcing: block, answering the request id if one can be
        read. Never raises."""
        # PLAY: This is the difference between the two fault policies, in
        # one function. Default: the check broke, so relay the frame and
        # log that enforcement was impossible. Strict: the check broke, so
        # refuse -- and note the asymmetry below, where unreadable override
        # state keeps enforcement ON rather than silently disabling it.
        forward = ("forward", None,
                   {"action": "gate_skipped", "reason": "gate_check_error"})
        if not self.strict:
            return forward
        try:
            if not self._enforcement_on():
                return forward
        except Exception:
            pass   # strict: an unreadable override keeps enforcement on
        response = None
        try:
            frame = _loads(line)
            if isinstance(frame, dict):
                response = self._block(
                    frame.get("id"), "gate_check_error", None,
                    "glassport gate: request blocked — strict mode: the gate "
                    "check failed")
        except Exception:
            response = None
        self.blocked_count += 1
        return ("block", response,
                {"action": "blocked", "tool": None, "reason": "gate_check_error"})

    def _block_batch(self, batch: list) -> tuple[str, bytes | None, dict | None]:
        """JSON-RPC batches are refused whole while enforcing: MCP 2025-06-18
        removed batching, and checking elements one by one would mean
        splitting a byte-faithful relay. No element is ever forwarded. Each
        addressable request gets a -32000 batch_unsupported error, returned
        together as one batch response; notifications, client replies,
        unaddressable ids, and nested arrays get nothing, and a batch with no
        addressable request gets no response at all."""
        # PLAY: All-or-nothing. Forwarding the innocent elements would
        # mean rewriting a batch into several frames, which is a change
        # the relay is not allowed to make. So the whole batch is refused
        # and each request that can be answered is told why.
        if not self._enforcement_on():
            return ("forward", None,
                    {"action": "gate_disabled", "tool": None,
                     "reason": "batch_unsupported"})
        self.blocked_count += 1
        errors = []
        for element in batch:
            if isinstance(element, dict) and "method" in element:
                err = self._error_object(
                    element.get("id"), "batch_unsupported", None,
                    "glassport gate: JSON-RPC batch requests are not supported; "
                    "no request in this batch was forwarded",
                    suggestion="Send each request as its own message.")
                if err is not None:
                    errors.append(err)
        response = ((json.dumps(errors, ensure_ascii=True) + "\n").encode("utf-8")
                    if errors else None)
        return ("block", response,
                {"action": "blocked", "tool": None, "reason": "batch_unsupported"})

    def _block(self, rid, reason: str, tool: str | None, message: str,
               suggestion: str | None = None, **extra_data) -> bytes | None:
        """Build the synthesized JSON-RPC error for any gate block.

        All gate blocks reuse -32000 and distinguish checks via data.reason.
        Callers build suggestions from known structured values, never from
        matched payload content.

        Only a JSON-RPC id (string or finite number) is echoed. A notification
        (no id) gets nothing back, and so does a caller-built container,
        boolean, or non-finite number: such a request is unaddressable, and
        re-encoding a deeply nested id could itself overflow and turn the
        block into a fail-open forward.
        """
        err = self._error_object(rid, reason, tool, message, suggestion, **extra_data)
        if err is None:
            return None
        # ASCII-escaped: the message quotes caller text, which may hold lone
        # surrogates that UTF-8 cannot encode; the resulting exception would
        # otherwise turn a block into a fail-open forward.
        return (json.dumps(err, ensure_ascii=True) + "\n").encode("utf-8")

    def _idempotency_hit(self, name: str, arguments: Any) -> bool:
        """Detect repeated canonical calls in a monotonic TTL window."""
        # PLAY: Canonical hashing is the whole trick. sort_keys makes key
        # order irrelevant and default=str keeps an exotic value from
        # raising, so two calls that mean the same thing collide on the
        # same key. Swapping two arguments must not read as a new call.
        now = time.monotonic()
        key = hashlib.sha256(json.dumps(
            {"name": name, "arguments": arguments},
            sort_keys=True, default=str).encode("utf-8")).hexdigest()
        with self._lock:
            stale = [k for k, (_, ts) in self._recent_calls.items()
                     if now - ts > self.idempotency_ttl]
            for k in stale:
                del self._recent_calls[k]
            # PLAY: The window runs from the FIRST sighting, not the
            # last, so a slow drip of identical calls still trips. And the
            # comparison is `>`, so max_repeats=3 allows three and flags
            # the fourth.
            count, first_seen = self._recent_calls.get(key, (0, now))
            count += 1
            self._recent_calls[key] = (count, first_seen)
            return count > self.idempotency_max_repeats

    def _enforcement_on(self) -> bool:
        """Consult the override file. Fail-closed: enforcement stays ON
        unless the file is a well-formed {"enforce": false} owned by
        this uid with no group/world write bits."""
        # PLAY: Four independent gates, and every one of them has to pass
        # before enforcement may switch off: this uid owns the file, no
        # group or world write bit is set, it parses, and it is a dict.
        # Each failure returns True -- enforcement on. A control channel
        # that fails open is not a control channel.
        p = self.control_path
        if p is None:
            return True
        if os.name != "posix":
            # Windows has no uid and st_mode is decorative — the
            # owner/permission proof this reader requires cannot be
            # expressed. Fail closed: enforcement stays ON and the
            # override file is inert (documented in SECURITY.md).
            return True
        try:
            st = p.stat()
            if st.st_uid != os.getuid() or (st.st_mode & 0o022):
                return True
            data = json.loads(p.read_text(encoding="utf-8"))
        except (OSError, ValueError, UnicodeDecodeError, RecursionError):
            return True
        if not isinstance(data, dict):
            return True
        # Only a literal JSON false disables enforcement; null, 0, "", [] and
        # {} are falsy but are not the documented {"enforce": false}.
        # PLAY: `is not False` rather than a truthiness test, for exactly
        # that reason: a truncated file that parsed as null, or a 0, must
        # not be able to turn the gate off by accident.
        return data.get("enforce", True) is not False

    def _fold(self, direction: str, line: bytes) -> None:
        """Fold one relayed line into the declaration facts. Never raises.

        A fold fault is attributed to its direction: a server line that
        cannot be folded leaves the declaration unknown (it may have been a
        retraction), while a client line only abandons a pending listing
        (a caller must not be able to switch enforcement off).
        """
        try:
            frame = _loads(line)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError,
                RecursionError):
            return
        if not isinstance(frame, dict):
            return
        # PLAY: One lock covers the whole fold, and notify_all() runs
        # inside it. A tools/call held in _await_declaration is waiting on
        # this condition, so the wake-up and the state change have to be
        # the same critical section or the waiter could miss it.
        with self._state_changed:
            try:
                self._fold_seq += 1
                self._builder.ingest_frame({"seq": self._fold_seq, "ts": _now_iso(),
                                            "dir": direction, "frame": frame})
            except Exception:
                # PLAY: A fold fault is charged to the direction that
                # caused it. An unreadable server line might have been a
                # withdrawal, so the declaration becomes unknown. An
                # unreadable client line only abandons a pending listing --
                # otherwise a caller could switch enforcement off by
                # sending something the tap cannot parse.
                state = self._builder.state
                if direction == "s2c":
                    state._invalidate_declaration()
                else:
                    state._cancel_pending_declaration()
            self._state_changed.notify_all()

    def observe_s2c(self, line: bytes) -> None:
        """Fold a server line before the client sees it. Never raises."""
        self._fold("s2c", line)

    def observe_c2s(self, line: bytes) -> None:
        """Fold a client line the server is about to receive. Never raises.

        Called only for forwarded lines, before they are written, so a fast
        reply always finds its request already correlated.
        """
        self._fold("c2s", line)

    def _declaration(self) -> tuple[frozenset[str], dict[str, dict]] | None:
        """Names and tool definitions from one consistent state, or None
        when no declaration is current. Caller holds _lock."""
        # PLAY: Both halves are required: something was declared, and it
        # is still current under ttlMs. An expired declaration is unknown,
        # not empty -- which is why this returns None and not set().
        state = self._builder.state
        if state.surface is None or not state.current_at(_now_iso()):
            return None
        return state.surface, state.tool_defs

    def _await_declaration(self) -> tuple[frozenset[str], dict[str, dict]] | None:
        """Current declaration, waiting (lock released) only while a
        correlated listing is in flight. Rechecked after every wake."""
        deadline = None
        with self._state_changed:
            snapshot = self._declaration()
            # PLAY: Only a correlated listing that is actually in flight
            # makes this wait. No listing pending means no reason to hold
            # the call, and the loop re-reads the declaration after every
            # wake rather than trusting the one it saw first.
            while snapshot is None and self._builder.state.listing_in_flight:
                if deadline is None:
                    deadline = time.monotonic() + self._hold_timeout
                remaining = deadline - time.monotonic()
                if remaining <= 0:
                    break
                self._state_changed.wait(remaining)
                snapshot = self._declaration()
            return snapshot

    def _take_pending_read(self, rid: Any) -> str | None:
        """Pop the uri of the resources/read this reply answers, for the log
        marker only. A boolean id never pops: True == 1 in Python, so a
        {"id": true} primer used to consume pending read 1 (A9)."""
        # PLAY: The recorded bug is worth keeping in mind whenever an id is
        # inspected: dict lookups treat True and 1 as the same key, so a
        # boolean must be rejected before it can address a request.
        if rid is None or isinstance(rid, bool):
            return None
        try:
            with self._lock:
                return self._pending_reads.pop(rid, None)
        except TypeError:   # unhashable id: answers no tracked request
            return None

    def _uninspectable_s2c(self, reason: str
                           ) -> tuple[str, bytes | None, dict | None]:
        """A server line the gate cannot read may be a resources/read reply
        whose text a client parser (V8) would still accept, and its id is
        unreadable. While enforcing it is dropped, not released."""
        # PLAY: This is the s2c fail-closed verdict, and it is asymmetric
        # with the c2s side on purpose. A c2s frame we cannot read is
        # forwarded with a marker; an s2c frame we cannot read might be the
        # response carrying text that poisoned a client, so it is dropped.
        if not self._enforcement_on():
            return ("forward", None, {"action": "gate_disabled", "reason": reason})
        return ("drop", None, {"action": "quarantine_dropped", "reason": reason})

    def check_s2c(self, line: bytes
                  ) -> tuple[str, bytes | None, dict | None]:
        """Forward results, or rewrite tainted resources/read text in place.

        A scan failure preserves the original response so the waiting client
        still receives it. Readable results are never dropped by this check;
        unreadable lines are (see _uninspectable_s2c). Blank lines pass.
        """
        # PLAY: Blank lines are legal keep-alives in a newline-delimited
        # stream and carry nothing to judge, so they pass untouched.
        if not line.strip():
            return ("forward", None, None)
        try:
            frame = _loads(line)
        except RecursionError:
            return self._uninspectable_s2c("frame_too_deep")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return self._uninspectable_s2c("uninspectable_frame")
        if isinstance(frame, list):
            # the gate refuses client batches, so a server batch answers
            # nothing legitimate; it could smuggle a read reply past the scan
            return self._uninspectable_s2c("batch_unsupported")
        if not isinstance(frame, dict):
            return self._uninspectable_s2c("uninspectable_frame")
        # PLAY: A frame carrying a method is a server-initiated request or
        # notification, not a reply to anything, so there is no result to
        # quarantine. It goes straight through.
        if "method" in frame:
            return ("forward", None, None)
        uri = None
        rid = None
        try:
            rid = frame.get("id")
            uri = self._take_pending_read(rid)
            result = frame.get("result")
            if not isinstance(result, dict):
                return ("forward", None, None)
            contents = result.get("contents")
            if not isinstance(contents, list):
                return ("forward", None, None)
            # A `contents` array is the shape of a resources/read result (tool
            # results use `content`). Scan it whatever its id: MCP SDKs
            # normalize response ids (TS Number(id), Python int(str)), so "1",
            # 1.0 or true all reach request 1, and correlating on the pending
            # id let a mismatched id carry unneutralized text (A8).
            # PLAY: That bug is the best argument for content-shape
            # detection over id correlation. If the client will deliver
            # this text to the model, the gate must neutralize it -- no
            # matter which request the id claims to answer. The pending
            # id is used only to label the log entry.
            if uri is None:
                uri = next((item.get("uri") for item in contents
                            if isinstance(item, dict)
                            and isinstance(item.get("uri"), str)), None)
            changed = False
            for item in contents:
                if not isinstance(item, dict):
                    continue
                text = item.get("text")
                if not isinstance(text, str):
                    continue
                # detection reads only the first MAX_SCAN_BYTES; a longer text
                # is neutralized whole rather than trusted past the cap (A4)
                # PLAY: The length test comes first on purpose. A scanner
                # that stops at a cap turns "put your payload after byte N"
                # into a bypass, so an over-long text is treated as tainted
                # without being read at all.
                if len(text) > MAX_SCAN_BYTES or find_taint({"text": text}) is not None:
                    sanitized = neutralize_text(text)
                    # Unicode neutralization preserves ASCII delimiters.
                    # Reuse the detection pattern to remove those explicitly.
                    # PLAY: neutralize_text normalizes the invisible
                    # characters; this loop handles the plain-ASCII ones
                    # ("SYSTEM:", "### Instruction") that survive that
                    # pass because they are ordinary text.
                    for kind, pattern in _TAINT_PATTERNS:
                        if kind == "role_switch_delimiter":
                            sanitized = pattern.sub("[role delimiter removed]", sanitized)
                    item["text"] = sanitized
                    changed = True
            if not changed:
                return ("forward", None, None)
            # ASCII-escaped so a lone surrogate in any sibling field cannot
            # fail the encode and release the unneutralized original.
            try:
                new_line = (_dumps_strict_json(frame) + "\n").encode("utf-8")
            except RecursionError:
                # The server sized this structure; near the parser's depth
                # limit it can parse but not re-encode. Deliver only the
                # neutralized contents instead of releasing the original. A
                # container id could itself be too deep to encode (and TS
                # clients read Number([[1]]) as 1), so such a reply is dropped.
                # PLAY: Note the two possible endings and what each claims.
                # "rewrite" with reduced=True says: here is the same reply,
                # minus everything but the fields a client renders. "drop"
                # says: we could not even address an answer to this id.
                if isinstance(rid, bool) or not isinstance(rid, (str, int, float)):
                    return ("drop", None,
                            {"action": "quarantine_dropped", "uri": uri,
                             "reason": "unencodable_reply"})
                new_line = _minimal_read_response(rid, contents)
                return ("rewrite", new_line,
                        {"action": "quarantined", "uri": uri, "reduced": True})
        except Exception:
            if self.strict and self._enforcement_on():
                # strict: never release a read reply the quarantine could
                # not finish; answer its id with an error, or drop it
                # PLAY: Default mode forwards with a quarantine_scan_error
                # marker because a working session outranks an unproven
                # suspicion. Strict mode inverts that: if we could not
                # finish the scan, the text does not reach the model.
                withheld = self._block(
                    rid, "quarantine_scan_error", None,
                    "glassport gate: resource content withheld — strict mode: "
                    "the quarantine scan failed")
                if withheld is None:
                    return ("drop", None, {"action": "quarantine_dropped",
                                           "uri": uri, "reason": "quarantine_scan_error"})
                return ("rewrite", withheld, {"action": "quarantine_withheld",
                                              "uri": uri, "reason": "quarantine_scan_error"})
            return ("forward", None,
                    {"action": "quarantine_scan_error", "uri": uri})
        return ("rewrite", new_line, {"action": "quarantined", "uri": uri})

    def _uninspectable_c2s(self, reason: str
                           ) -> tuple[str, bytes | None, dict | None]:
        """A client line the gate cannot read (too deep, malformed,
        invalid UTF-8, \\r-joined messages a
        universal-newline server splits, or a bare non-object value) may still
        parse on the server and run a call the gate never read. While
        enforcing it is dropped; its id is unreadable, so no error response
        can be addressed."""
        if not self._enforcement_on():
            return ("forward", None,
                    {"action": "gate_disabled", "tool": None, "reason": reason})
        self.blocked_count += 1
        return ("block", None, {"action": "blocked", "tool": None, "reason": reason})

    def check_c2s(self, line: bytes
                  ) -> tuple[str, bytes | None, dict | None]:
        """
        Decide one client→server line. Returns (action, response, info):
        action "forward" relays the line untouched; "block" drops it,
        sends `response` (bytes, or None for id-less calls) back to the
        client, and logs `info` on the blocked entry.
        """
        # PLAY: Read the checks below as a chain of escalating cost: parse,
        # shape, cheapest possible name test, then attestation, then depth,
        # size, idempotency, taint, schema, and PII. Any check can fault,
        # and a fault is recorded rather than raised, because the caller is
        # a relay thread.
        if not line.strip():
            return ("forward", None, None)   # blank lines carry no message
        try:
            frame = _loads(line)
        except RecursionError:
            return self._uninspectable_c2s("frame_too_deep")
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError):
            return self._uninspectable_c2s("uninspectable_frame")
        if isinstance(frame, list):
            return self._block_batch(frame)
        if not isinstance(frame, dict):
            return self._uninspectable_c2s("uninspectable_frame")
        method = frame.get("method")
        # PLAY: A resources/read request is remembered by id so the reply
        # can be labelled with the uri it answered. That is marker
        # metadata, not authorization -- check_s2c scans contents
        # regardless of whether this bookkeeping succeeded.
        if method == "resources/read":
            try:
                rid = frame.get("id")
                uri = (frame.get("params") or {}).get("uri")
                if rid is not None and uri is not None:
                    with self._lock:
                        self._pending_reads[rid] = uri
            except Exception:
                return ("forward", None,
                        {"action": "gate_skipped", "reason": "resource_tracking_error"})
            return ("forward", None, None)
        if method != "tools/call":
            return ("forward", None, None)

        # MCP tools/call params are an object with a string name. Any other
        # shape carries no declared tool: it falls through to the
        # undeclared-surface block instead of raising (an unhashable name
        # used to crash the relay) or reaching a positional-params server.
        # PLAY: Dropping to {} rather than trusting the shape is what
        # makes the comparison below safe. The frame still goes on to be
        # blocked as undeclared, so a malformed call never becomes a free
        # pass -- it just cannot borrow a name to hide behind.
        params = frame.get("params")
        if not isinstance(params, dict):
            params = {}
        name = params.get("name")
        if not isinstance(name, str):
            name = None
        # Names and schemas come from one snapshot: a declaration replaced
        # mid-decision must not pair the new names with the old schema.
        # PLAY: This call may block for up to hold_timeout while a listing
        # is in flight. Blocking the c2s pump is deliberate: stdio
        # backpressure is the flow control a real client already expects,
        # and guessing at an in-flight declaration would be a coin flip.
        snapshot = self._await_declaration()
        surface_missing = snapshot is None
        declared, declared_defs = snapshot if snapshot is not None else (frozenset(), {})
        if surface_missing or name in declared:
            # With no declared surface only the undeclared-tool and schema
            # checks are impossible: fail open for those, visibly, but still
            # run attestation, depth, idempotency, taint, and PII.
            # PLAY: This branch is "allow, or run the checks that do not
            # need a declaration". An unknown surface must not disable the
            # boundary checks; it disables exactly two of them, and says so
            # in the marker.
            forward_info = ({"action": "gate_skipped",
                             "reason": "no_surface_timeout", "tool": name}
                            if surface_missing else None)
            if self.enforce_attestation:
                att = None
                sig_ok = None
                try:
                    from glassport.attestation import (
                        check_meta, signing_payload, verify_signature)
                    meta = params.get("_meta")
                    att = check_meta(meta)
                    if att.present and att.well_formed and not att.expired:
                        try:
                            payload = signing_payload(params)
                        except (ValueError, TypeError, RecursionError):
                            # The caller chose a frame that cannot be signed
                            # (non-finite numbers, excessive nesting); that
                            # is a failed attestation, not a scanner fault.
                            sig_ok = False
                        else:
                            sig_ok = verify_signature(
                                payload, meta[ATTESTATION_KEY]["sig"],
                                self.attestation_pubkey_b64)
                        if sig_ok is None:
                            # Unavailable verification does not disable the
                            # remaining taint/schema/PII boundary checks.
                            forward_info = _note_skip(
                                forward_info, name, "attestation_unavailable")
                except Exception:
                    # Fail open, visibly, but keep the remaining boundary
                    # checks: a scanner fault must not skip them.
                    att = None
                    forward_info = _note_skip(
                        forward_info, name, "attestation_check_error")
                if att is not None and (
                        not att.present or not att.well_formed or att.expired
                        or sig_ok is False):
                    if not self._enforcement_on():
                        return ("forward", None,
                                {"action": "gate_disabled", "tool": name,
                                 "reason": "attestation_failed"})
                    self.blocked_count += 1
                    rid = frame.get("id")
                    response = self._block(
                        rid, "attestation_failed", name,
                        f"glassport gate: tools/call '{name}' blocked — "
                        f"caller attestation missing, malformed, expired, "
                        f"or invalid",
                        suggestion=f"Include a valid {ATTESTATION_KEY} "
                                   f"entry in params._meta, signed with "
                                   f"the configured key.")
                    return ("block", response,
                            {"action": "blocked", "tool": name,
                             "reason": "attestation_failed"})
            arguments = params.get("arguments")
            # Taint and PII cover every params field, not just arguments:
            # _meta and any sibling reach the server too (A2). The params
            # object adds one level around arguments, which keep their
            # MAX_ARGUMENT_DEPTH allowance.
            # PLAY: That is why the depth test below uses
            # MAX_ARGUMENT_DEPTH + 1: the documented allowance is for the
            # arguments, and params wraps them in one more dict. Testing
            # params at the bare limit would reject a legal call.
            extras = {k: v for k, v in params.items()
                      if k not in ("name", "arguments")}
            if _nesting_exceeds(params, MAX_ARGUMENT_DEPTH + 1):
                if not self._enforcement_on():
                    return ("forward", None,
                            {"action": "gate_disabled", "tool": name,
                             "reason": "params_too_deep"})
                self.blocked_count += 1
                rid = frame.get("id")
                response = self._block(
                    rid, "params_too_deep", name,
                    f"glassport gate: tools/call '{name}' blocked — "
                    f"params nested deeper than {MAX_ARGUMENT_DEPTH} "
                    f"levels cannot be inspected safely",
                    suggestion=f"Flatten the arguments to at most "
                               f"{MAX_ARGUMENT_DEPTH} levels of nesting.")
                return ("block", response,
                        {"action": "blocked", "tool": name,
                         "reason": "params_too_deep"})
            try:
                blob = json.dumps(params, ensure_ascii=False, default=str)
            except Exception:
                blob = None
                forward_info = _note_skip(forward_info, name, "pii_scan_error")
            # The scanners inspect at most MAX_SCAN_BYTES per blob/string;
            # anything past that cap would pass unread, so it is refused (A3/A4).
            # PLAY: Refused, not truncated. Truncating would forward data
            # the gate never read while reporting that it checked. The
            # suggestion in the error tells the caller how to comply.
            if blob is not None and len(blob) > MAX_SCAN_BYTES:
                if not self._enforcement_on():
                    return ("forward", None,
                            {"action": "gate_disabled", "tool": name,
                             "reason": "params_too_large"})
                self.blocked_count += 1
                rid = frame.get("id")
                response = self._block(
                    rid, "params_too_large", name,
                    f"glassport gate: tools/call '{name}' blocked — params "
                    f"exceed the {MAX_SCAN_BYTES}-character inspection limit",
                    suggestion="Send large content by reference (a resource "
                               "URI) rather than inline in the call.")
                return ("block", response,
                        {"action": "blocked", "tool": name,
                         "reason": "params_too_large"})
            # A check that faults is skipped visibly, but the remaining
            # checks still run: one scanner error must not waive the rest.
            # PLAY: _note_skip accumulates these on forward_info, so a
            # single frame can carry several skip reasons. Under --strict
            # that accumulator is what _strict_block later turns into a
            # block; without strict it rides out on the forwarded entry.
            try:
                repeat = self._idempotency_hit(name, arguments)
            except Exception:
                repeat = False
                forward_info = _note_skip(forward_info, name, "idempotency_check_error")
            if repeat:
                if not self._enforcement_on():
                    return ("forward", None,
                            {"action": "gate_disabled", "tool": name,
                             "reason": "retry_loop_exceeded"})
                self.blocked_count += 1
                rid = frame.get("id")
                response = self._block(
                    rid, "retry_loop_exceeded", name,
                    f"glassport gate: tools/call '{name}' blocked — "
                    f"identical request repeated more than "
                    f"{self.idempotency_max_repeats} times within "
                    f"{self.idempotency_ttl}s",
                    suggestion="This call is not idempotent-safe to retry "
                               "blindly. Inspect the last result before "
                               "retrying, or wait for the TTL window to "
                               "pass.")
                return ("block", response,
                        {"action": "blocked", "tool": name,
                         "reason": "retry_loop_exceeded"})
            field = "argument"
            try:
                hit = find_taint(arguments)
                if hit is None:
                    hit = find_taint(extras)
                    field = "params field"
            except Exception:
                hit = None
                forward_info = _note_skip(forward_info, name, "taint_scan_error")
            if hit is not None:
                pat_name, key_path, _snippet = hit
                if not self._enforcement_on():
                    return ("forward", None,
                            {"action": "gate_disabled", "tool": name,
                             "reason": "taint_detected"})
                self.blocked_count += 1
                rid = frame.get("id")
                response = self._block(
                    rid, "taint_detected", name,
                    f"glassport gate: tools/call '{name}' blocked — "
                    f"{field} '{key_path}' contains a semantic taint "
                    f"signature ({pat_name})",
                    suggestion="Remove role-switching delimiters and "
                               "zero-width characters from the argument "
                               "and retry with plain text.")
                return ("block", response,
                        {"action": "blocked", "tool": name,
                         "reason": "taint_detected"})
            schema = (declared_defs.get(name) or {}).get("inputSchema")
            try:
                problems = list(_schema_problems(arguments, schema))
            except Exception:
                problems = []
                forward_info = _note_skip(forward_info, name, "schema_scan_error")
            if problems:
                if not self._enforcement_on():
                    return ("forward", None,
                            {"action": "gate_disabled", "tool": name,
                             "reason": "schema_violation"})
                self.blocked_count += 1
                rid = frame.get("id")
                response = self._block(
                    rid, "schema_violation", name,
                    f"glassport gate: tools/call '{name}' blocked — "
                    f"{problems[0]}",
                    suggestion=f"Fix the argument and retry: {problems[0]}")
                return ("block", response,
                        {"action": "blocked", "tool": name,
                         "reason": "schema_violation"})
            try:
                pii_hits = ([(pat, val) for pat, val in _scan_pii(blob)
                             if pat.severity == 3] if blob is not None else [])
            except Exception:
                pii_hits = []
                forward_info = _note_skip(forward_info, name, "pii_scan_error")
            if pii_hits:
                if not self._enforcement_on():
                    return ("forward", None,
                            {"action": "gate_disabled", "tool": name,
                             "reason": "pii_exfiltration"})
                pat, val = pii_hits[0]
                self.blocked_count += 1
                rid = frame.get("id")
                response = self._block(
                    rid, "pii_exfiltration", name,
                    f"glassport gate: tools/call '{name}' blocked — "
                    f"params contain {pat.description}: "
                    f"{_redact(val, pat.category)}",
                    suggestion="Remove the credential/secret from the "
                               "argument before retrying; this tool call "
                               "will not be forwarded with it present.")
                return ("block", response,
                        {"action": "blocked", "tool": name,
                         "reason": "pii_exfiltration"})
            if self.strict and forward_info is not None and self._enforcement_on():
                return self._strict_block(frame, name, forward_info)
            # PLAY: The ordinary ending. `forward_info` is None for a clean
            # frame, or a marker explaining every check that could not run.
            return ("forward", None, forward_info)

        if not self._enforcement_on():
            # would have been blocked; forward, but say so in the log
            return ("forward", None,
                    {"action": "gate_disabled", "tool": name,
                     "declared": sorted(declared)})

        self.blocked_count += 1
        rid = frame.get("id")
        suggestion = (f"Call one of the declared tools: "
                      f"{', '.join(sorted(declared))}") if declared else None
        response = self._block(
            rid, "gate_blocked", name,
            f"glassport gate: tools/call '{name}' blocked — not in the "
            f"declared tool surface",
            suggestion=suggestion, declared=sorted(declared))
        info = {"action": "blocked", "tool": name,
                "declared": sorted(declared)}
        return ("block", response, info)


# ─────────────────────────────────────────────────────────────────
# Pump — moves lines from one fd to another, tapping each line.
# ─────────────────────────────────────────────────────────────────
# PLAY: This is the relay loop, and it is intentionally dumb: read a
# line, optionally ask the gate, write the line, log the line. It parses
# nothing itself and holds no protocol state. Everything that could be
# slow, clever, or fallible lives behind the two optional arguments.
def pump(src, dst, log: SessionLog | None, direction: str,
         gate: Gate | None = None, client_write=None,
         dst_lock: threading.Lock | None = None) -> None:
    """
    Read newline-delimited lines from src, relay them to dst, and tap each
    into the session log. Binary-safe for untouched lines; a gate quarantine
    is the one exception — see below.

    With a gate: c2s lines are checked before forwarding — a blocked
    line never reaches dst, and the synthesized error goes back to the
    client via client_write. s2c lines feed the gate's view of the
    declared surface. A gate may also rewrite a resources/read result whose
    text matches a taint signature before forwarding. Both the server's
    original and the client's replacement are logged with distinct markers.
    dst_lock serializes client-bound writes so an
    injected error can't interleave with a real server response.
    """
    # PLAY: `iter(src.readline, b"")` is the sentinel form: readline
    # returns b"" at EOF, which ends the loop. One pump per direction, each
    # in its own thread, so a slow write on one side cannot stall reads on
    # the other.
    try:
        for line in iter(src.readline, b""):
            gate_info = None   # marker for forwarded-but-noteworthy frames
            if gate is not None and direction == "c2s":
                try:
                    action, response, info = gate.check_c2s(line)
                except Exception:
                    # An unexpected gate fault must not stop the relay. By
                    # default it fails open, visibly; `gate --strict` blocks.
                    # Caller-chosen shapes are handled inside check_c2s, so
                    # this is for defects, not attacker input.
                    try:
                        action, response, info = gate.fault_verdict(line)
                    except Exception:
                        action, response, info = (
                            "forward", None,
                            {"action": "gate_skipped", "reason": "gate_check_error"})
                if action == "block" and info is not None:
                    # PLAY: A block logs twice and relays once. The
                    # request is recorded as blocked (the server never saw
                    # it), and the error the client receives is recorded
                    # separately as injected, because the server never
                    # said it. Two entries, because two peers genuinely
                    # saw different bytes.
                    if log is not None:
                        log.record(direction, line, gate=info)
                    if response is not None and client_write is not None:
                        client_write(response)
                        if log is not None:
                            log.record("s2c", response,
                                       gate={"action": "injected",
                                             "tool": info["tool"]})
                    continue
                gate_info = info   # e.g. gate_skipped fail-open
                # Before the write: the reply must find its request folded.
                # PLAY: Fold-then-forward, never the other way round. A
                # fast server can answer a resources/read before this
                # thread reaches the top of the loop again, and the reply
                # would then arrive with no request to attribute it to.
                gate.observe_c2s(line)
            elif gate is not None and direction == "s2c":
                try:
                    gate.observe_s2c(line)
                except Exception:
                    # never let a surface-harvest defect stop the s2c relay
                    gate_info = {"action": "gate_skipped",
                                 "reason": "surface_observe_error"}
                try:
                    s2c_action, s2c_new_line, s2c_info = gate.check_s2c(line)
                except Exception:
                    strict_now = getattr(gate, "strict", False)
                    try:
                        strict_now = strict_now and gate._enforcement_on()
                    except Exception:
                        pass   # strict: an unreadable override keeps enforcing
                    s2c_action, s2c_new_line, s2c_info = (
                        ("drop", None, {"action": "quarantine_dropped",
                                        "reason": "quarantine_scan_error"})
                        if strict_now
                        else ("forward", None, {"action": "quarantine_scan_error"}))
                if s2c_action == "drop":
                    # PLAY: Dropped means the client never receives this
                    # frame. It is still written to the log, marked as
                    # quarantine_dropped, so the capture shows what was
                    # withheld instead of looking like the server said
                    # nothing.
                    if log is not None:
                        log.record(direction, line, gate=s2c_info)
                    continue
                if s2c_action == "rewrite" and s2c_new_line is not None:
                    # PLAY: Both versions are kept: the server's original
                    # text with the quarantine marker, then the replaced
                    # line through the common log call below. The relay's
                    # byte-faithful promise is preserved as evidence even
                    # though the client sees the sanitized copy.
                    if log is not None:
                        log.record(direction, line, gate=s2c_info)
                    line = s2c_new_line
                    # The common log call below records the replacement once.
                    gate_info = {**(s2c_info or {}), "action": "quarantine_replacement"}
                elif s2c_info is not None:
                    gate_info = s2c_info
            # PLAY: The lock covers write and flush together. Half a line
            # followed by an injected error would corrupt the framing of a
            # newline-delimited protocol, and the client would read two
            # mangled frames.
            if dst_lock is not None:
                with dst_lock:
                    dst.write(line)
                    dst.flush()
            else:
                dst.write(line)
                dst.flush()
            if log is not None:
                log.record(direction, line, gate=gate_info)
    except (BrokenPipeError, ValueError, OSError):
        pass  # one side hung up; let the session wind down
    # PLAY: Closing dst on the way out is what tells the other end the
    # conversation is over -- for c2s that is the child's stdin, which is
    # how the server learns to exit.
    finally:
        try:
            dst.close()
        except Exception:
            pass


def pump_stderr(src, dst) -> None:
    """Pass the child's stderr through untouched (no framing assumed)."""
    # PLAY: Chunked, not line-based, and never parsed. A server can write
    # progress bars, partial lines, or binary to stderr; none of it is
    # protocol, all of it is the human's, so it is copied and forgotten.
    try:
        for chunk in iter(lambda: src.read(4096), b""):
            dst.write(chunk)
            dst.flush()
    except (BrokenPipeError, ValueError, OSError):
        pass


# ─────────────────────────────────────────────────────────────────
# Tap mode — spawn the real server and sit in the middle.
# ─────────────────────────────────────────────────────────────────
def run_tap(server_cmd: list[str], log_dir: Path,
            gate: Gate | None = None,
            gate_controllable: bool = False) -> int:
    session_start = time.time()
    # PLAY: The filename carries the time and the command, because that is
    # what a human sorting a log directory needs. The command is filtered
    # to alphanumerics so a path cannot introduce separators, and the pid
    # keeps two sessions started in the same second apart.
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = "".join(c if c.isalnum() else "_" for c in server_cmd[0])[:32]
    log_path = log_dir / f"{stamp}_{safe_name}_{os.getpid()}.jsonl"
    if gate is not None and gate_controllable:
        gate.control_path = log_path.with_name(log_path.name + ".gate")
    # The relay is sacred: a logging failure must never alter, delay, or kill
    # a live session. If the log dir is unwritable, disable logging and relay
    # anyway — pump() already tolerates a None log.
    # PLAY: Popped, not read. The variable exists so `probe` can tell the
    # tap what kind of session this is; the wrapped server is a separate
    # process that has no business inheriting glassport's own switch.
    probe_capture = os.environ.pop("GLASSPORT_INTERNAL_PROBE", None) == "1"
    mode = "gate" if gate is not None else "probe" if probe_capture else "wrap"
    log = open_session_log(log_path, transport="stdio", mode=mode,
                           strict=bool(gate is not None and gate.strict))

    # Announce on stderr only — stdout belongs to the protocol.
    # PLAY: Not a style choice. One stray byte on stdout lands in the
    # client's parser as a malformed frame and ends the session.
    print(f"[glassport] tapping: {shlex.join(server_cmd)}", file=sys.stderr)
    print(f"[glassport] session log: {log_path}", file=sys.stderr)
    if gate is not None:
        print("[glassport] GATE ACTIVE: tools/call frames outside the "
              "declared surface will be blocked", file=sys.stderr)
        if gate.control_path is not None:
            print(f"[glassport] gate controllable via "
                  f"{gate.control_path} (tui --gate-control)",
                  file=sys.stderr)

    try:
        child = subprocess.Popen(
            server_cmd,
            stdin=subprocess.PIPE,
            stdout=subprocess.PIPE,
            stderr=subprocess.PIPE,
            # PLAY: Unbuffered. A buffered pipe would hold a complete frame
            # until the buffer filled, which is a stall the client would
            # experience as a hung server -- exactly the delay the relay
            # promises never to add.
            bufsize=0,  # unbuffered — frames must not sit in a buffer
        )
    except FileNotFoundError:
        print(f"[glassport] command not found: {server_cmd[0]}", file=sys.stderr)
        return 127

    stdin_b = sys.stdin.buffer
    stdout_b = sys.stdout.buffer

    # One lock for everything client-bound: real server responses and
    # gate-injected errors must never interleave mid-line.
    out_lock = threading.Lock()

    def client_write(data: bytes) -> None:
        with out_lock:
            stdout_b.write(data)
            stdout_b.flush()

    threads = [
        threading.Thread(target=pump, daemon=True,
                         args=(stdin_b, child.stdin, log, "c2s"),
                         kwargs={"gate": gate, "client_write": client_write}),
        threading.Thread(target=pump, daemon=True,
                         args=(child.stdout, stdout_b, log, "s2c"),
                         kwargs={"gate": gate, "dst_lock": out_lock}),
        threading.Thread(target=pump_stderr, daemon=True,
                         args=(child.stderr, sys.stderr.buffer)),
    ]
    for t in threads:
        t.start()

    # Forward termination signals to the child so configs behave normally.
    def _forward(sig, _frame):
        try:
            child.send_signal(sig)
        except Exception:
            pass
    for s in (signal.SIGINT, signal.SIGTERM):
        signal.signal(s, _forward)

    rc = child.wait()
    # PLAY: The child has exited, but the pumps are daemon threads that may
    # still be copying the final lines out of the pipes. A tenth of a
    # second is a best-effort drain, not a guarantee; a frame lost here is
    # still reported by the trailer's own counters.
    time.sleep(0.1)  # let pumps drain their last lines
    if log is not None:
        log.write_metrics(
            frames_blocked=gate.blocked_count if gate is not None else 0,
            session_duration_s=round(time.time() - session_start, 3))
        log.close()
    log_note = str(log_path) if log is not None else "(logging disabled)"
    suffix = f"; blocked {gate.blocked_count} call(s)" \
        if gate is not None and gate.blocked_count else ""
    print(f"[glassport] session ended (exit {rc}){suffix}; "
          f"log: {log_note}", file=sys.stderr)

    # PLAY: The short version of the long comment below: this function is
    # the process's last act, the daemon c2s thread is still parked in a
    # stdin read, and normal interpreter teardown can abort with SIGABRT
    # *after* a perfectly good session. So the process exits immediately
    # and skips finalization. If you are editing here, read the whole
    # comment first -- it records what was verified.
    # The c2s pump is a daemon thread blocked on a buffered sys.stdin read. If we
    # `return` and let the interpreter finalize, that finalization can trip
    # `_enter_buffered_busy` on the stdin BufferedReader the daemon still holds
    # and abort the process with SIGABRT — *after* a clean relay (a rare,
    # load-sensitive shutdown race). run_tap owns the process lifetime (it
    # installs SIGINT/SIGTERM handlers and is always the terminal call), so we
    # exit immediately with os._exit, skipping the finalization that aborts.
    #
    # Only stderr is flushed here: relayed stdout is already flushed frame-by-
    # frame in client_write, so nothing is buffered there. Do NOT add
    # `sys.stdout.flush()` — flushing stdout in this state re-triggers the exact
    # `_enter_buffered_busy` stdin abort this exit is avoiding (verified).
    sys.stderr.flush()
    os._exit(rc)


# ─────────────────────────────────────────────────────────────────
# Summarize mode — M2. Declared vs called vs delta, computed on an
# InteractionTrace via adapters/mcp_session.py so this CLI and the
# Understanding Layer read the wire through one code path.
# ─────────────────────────────────────────────────────────────────
def summarize(log_path: Path, as_json: bool = False, as_sarif: bool = False) -> int:
    """
    Render the declared/called/fabricated delta for one session log.

    The log is first lifted into an InteractionTrace by the
    from_mcp_session adapter; everything printed here is derived from
    the trace, never from the raw JSONL. Tap mode stays standalone —
    only summarize requires the Understanding Layer modules.

    With as_json the same facts are emitted as one JSON object, so an
    agent can shell out to `glassport summarize --json` and parse the
    result instead of scraping the human rendering.
    """
    # PLAY: Every import in this function is local for the same reason the
    # tap keeps its own imports light: `summarize` is a post-hoc verb, so
    # the adapter and detector stack load only when someone asks for a
    # summary, not when the tap starts.
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.detectors import context_violations
    from glassport.interaction_trace import PartKind

    # PLAY: One hop from JSONL to the model. Everything printed below is
    # derived from the trace object, never re-parsed from the raw lines,
    # so this command and the Python API cannot drift apart.
    trace = from_mcp_session_file(log_path)

    # doctrine: assert only what the wire proves — a summary of a
    # tail-only ingest must say the head was never analyzed
    # PLAY: The warning goes to stderr and the completeness field goes in
    # the output, because a partial count presented as a total is exactly
    # the kind of quiet overclaim the doctrine forbids.
    partial = bool(trace.metadata.get("tail_only"))
    if partial:
        print("WARN: log ingested tail-only — file exceeded the tail cap; "
              "the head was NOT analyzed and these counts are partial",
              file=sys.stderr)

    if as_sarif:
        from glassport.detectors import annotate
        from glassport.sarif import render_session_sarif
        annotate(trace)            # mutates trace.annotations in place
        # full path (not base+name): _seq_to_line must read the real file
        # for line numbers; a repo-relative path already resolves in the Security tab
        print(render_session_sarif(trace, str(log_path)))
        return 0

    # PLAY: Events are keyed back to wire sequence numbers so every line
    # of output can be traced to a line of the log. An agent reading the
    # summary can then go look at the frame itself.
    seq_of = {e.id: e.metadata.get("seq", -1) for e in trace.events}
    # one event per parsed frame; raw wire lines carry the unparsed flag
    frames = sum(1 for e in trace.events if not e.metadata.get("unparsed"))
    declared = trace.declared_tools()
    called = [(seq_of[eid], name) for eid, name in trace.called_tools()]
    fabricated = [(seq_of[eid], name)
                  for eid, name in trace.fabricated_tool_calls()]
    unused = sorted(declared - {n for _, n in called})

    # Two distinct failure modes, kept apart: a JSON-RPC *protocol* error
    # (the `error` member — malformed/unknown method) versus a valid
    # tools/call *result* carrying isError=true (the tool ran, the
    # operation failed). Conflating them inflates the protocol-error count
    # with ordinary denied-access / validation results.
    # PLAY: This distinction is the difference between "the server does
    # not implement that method" and "the tool refused your input". One is
    # a server defect, the other is normal operation, and a summary that
    # merges them is misleading in both directions.
    errors: list[tuple[int, str]] = []          # protocol errors (seq, message)
    tool_errors: list[tuple[int, str]] = []     # isError results (seq, message)
    for e in trace.events:
        for p in e.parts:
            if p.kind == PartKind.ERROR:
                errors.append((e.metadata.get("seq", -1),
                               str(e.metadata.get("error_message", p.content))))
            elif p.kind == PartKind.TOOL_RESULT and p.content.get("is_error"):
                out = p.content.get("output")
                msg = out.get("message", str(out)) if isinstance(out, dict) \
                    else str(out)
                tool_errors.append((e.metadata.get("seq", -1), msg))

    violations = sorted(context_violations(trace),
                        key=lambda a: (a.metadata.get("seq") or 0))

    if as_json:
        print(json.dumps({
            "session": log_path.name,
            "completeness": "partial_tail_only" if partial else "complete",
            "frames_parsed": frames,
            "declared_tools": sorted(declared),
            # PLAY: The boolean exists because an empty list alone cannot
            # tell a consumer whether the server declared nothing or never
            # declared anything.
            "declaration_known": trace.declared_surface() is not None,
            "called_tools": [n for _, n in called],
            "unused_declared": unused,
            "fabricated_calls": [{"seq": s, "tool": n}
                                 for s, n in fabricated],
            "protocol_errors": [{"seq": s, "message": m}
                                for s, m in errors],
            "tool_errors": [{"seq": s, "message": m}
                            for s, m in tool_errors],
            "context_violations": [
                {"severity": a.severity, "subcategory": a.subcategory,
                 "seq": a.metadata.get("seq"), "explanation": a.explanation}
                for a in violations],
        }, indent=2, ensure_ascii=False))
        return 0

    print(f"session: {log_path.name}")
    if partial:
        print("completeness:     PARTIAL (tail-only — head not analyzed)")
    print(f"frames parsed:    {frames}")
    # PLAY: Same distinction, in words, for the human reading the output.
    surface_label = ("— (unknown: no usable tools/list seen)"
                     if trace.declared_surface() is None else "— (explicitly empty)")
    print(f"declared tools:   {sorted(declared) or surface_label}")
    print(f"called tools:     {[n for _, n in called] or '—'}")
    print(f"unused declared:  {unused or '—'}")
    if fabricated:
        print(f"FABRICATED CALLS: {fabricated}   <-- calls outside the "
              f"declared surface")
    else:
        print("fabricated calls: none")
    if errors:
        print(f"protocol errors:  {errors}")
    if tool_errors:
        print(f"tool errors:      {tool_errors}   <-- server-side isError "
              f"results (the tool ran, the operation failed)")

    if violations:
        print("CONTEXT VIOLATIONS:")
        for a in violations:
            print(f"  [sev {a.severity}] seq {a.metadata.get('seq')} "
                  f"{a.subcategory}: {a.explanation}")
    else:
        print("context violations: none")
    return 0


# ─────────────────────────────────────────────────────────────────
# Detect mode — run every behavioral detector over one session log
# and print the findings. Exit 1 when anything was found (grep-style)
# so scripts and CI can branch on the result.
# ─────────────────────────────────────────────────────────────────
def _cmd_detect(log_path: Path, as_sarif: bool = False) -> int:
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.detectors import annotate

    trace = from_mcp_session_file(log_path)
    # PLAY: annotate() mutates the trace's annotation list and returns it,
    # so both names point at the same findings. The SARIF branch relies on
    # that: it renders the same trace it just annotated.
    annotations = annotate(trace)
    if as_sarif:
        from glassport.sarif import render_session_sarif
        # full path (not base+name): _seq_to_line must read the real file
        # for line numbers; a repo-relative path already resolves in the Security tab
        print(render_session_sarif(trace, str(log_path)))
        return 0
    if not annotations:
        print(f"detect: {log_path.name} — no findings")
        return 0
    print(f"detect: {log_path.name} — {len(annotations)} finding(s)\n")
    # PLAY: Worst first, then wire order. Severity descending is what a
    # human wants; sequence ascending keeps repeated runs comparable.
    for a in sorted(annotations,
                    key=lambda x: (-x.severity, x.metadata.get("seq") or 0)):
        sev_label = {1: "INFO", 2: "WARN", 3: "HIGH"}.get(
            a.severity, str(a.severity))
        print(f"  [{sev_label}] seq={a.metadata.get('seq', '?')} "
              f"{a.subcategory}: {a.explanation}")
    return 1


# ─────────────────────────────────────────────────────────────────
# Advise mode — render findings as a markdown advisory block for an
# agent-instruction file (CLAUDE.md / AGENTS.md / GEMINI.md).
# I/O lives only here; advise.py stays pure.
# ─────────────────────────────────────────────────────────────────
def _cmd_advise(audit: str | None, session: str | None,
                write: str | None, min_severity: int) -> int:
    from glassport.advise import render_advisory, wrap_block, splice_block

    if not audit and not session:
        print("usage: glassport advise [--audit <path>] [--session <s.jsonl>] "
              "[--write <FILE>] [--all]", file=sys.stderr)
        return 2

    report = None
    if audit:
        from glassport.audit import audit_path
        report = audit_path(audit)

    annotations = None
    if session:
        from glassport.adapters.mcp_session import from_mcp_session_file
        from glassport.detectors import annotate
        annotations = annotate(from_mcp_session_file(Path(session)))

    content = render_advisory(report, annotations,
                              min_severity=min_severity, base=audit or "")

    if not write:
        # never let a cp1252 console kill the render — degrade the
        # emoji, keep the findings (Windows default stdout is strict)
        # PLAY: The fallback re-encodes with "replace" so the report always
        # prints. Losing a glyph is acceptable; losing the findings because
        # a console cannot encode a character is not.
        block = wrap_block(content)
        try:
            print(block)
        except UnicodeEncodeError:
            enc = getattr(sys.stdout, "encoding", None) or "utf-8"
            print(block.encode(enc, "replace").decode(enc))
        return 0

    target = Path(write)
    # explicit utf-8 both ways: the block contains non-ASCII and the
    # platform default encoding (cp1252 on Windows) must never matter.
    # PLAY: Note the read-then-write with the file closed in between. The
    # splice is idempotent, so the file is rewritten whole -- and it has
    # to be closed before re-opening or Windows keeps the lock.
    # Context managers ensure handles are released before the idempotent
    # rewrite path re-opens the file (avoiding CI file-lock races).
    existing = ""
    if target.exists():
        with open(target, "r", encoding="utf-8") as fh:
            existing = fh.read()
    try:
        new_text = splice_block(existing, content)
    except ValueError as exc:
        print(f"advise: {exc}; fix or remove the glassport block in {write}",
              file=sys.stderr)
        return 1
    with open(target, "w", encoding="utf-8") as fh:
        fh.write(new_text)
    print(f"advise: wrote observations to {write}")
    return 0


def _cmd_observe(args: list[str]) -> int:
    """`glassport observe --url <remote>` — explicit HTTP observation mode.

    Strict on purpose, and deliberately separate from the `wrap` path's
    positional parsing: an unknown or duplicated option here must fail rather
    than silently select a different mode. Observation only — no gate exists.
    """
    from glassport.adapters.mcp_http import _validate_remote, run_http_tap
    from glassport.decision_journal import DecisionJournal
    from glassport.http_sessions import HTTPObserver, HTTPRegistryLimits

    # PLAY: A hand-rolled parser, and a strict one. `wrap` accepts an
    # unknown flag by passing it to the child command; `observe` must not,
    # because an option it ignores could silently mean "observe something
    # else". Duplicates fail too: --url given twice has no defensible
    # winner.
    values: dict[str, str] = {}
    flags = {"--url", "--log-dir", "--journal-dir", "--bind", "--port",
             "--max-sessions"}
    rest = list(args)
    while rest:
        arg = rest.pop(0)
        if arg not in flags:
            print(f"glassport: unknown option {arg!r} for observe; expected "
                  f"one of {' '.join(sorted(flags))}", file=sys.stderr)
            return 2
        if arg in values:
            print(f"glassport: {arg} given more than once", file=sys.stderr)
            return 2
        if not rest:
            print(f"glassport: {arg} requires a value", file=sys.stderr)
            return 2
        values[arg] = rest.pop(0)
    if "--url" not in values:
        print("usage: glassport observe --url <remote-mcp-url> [--log-dir DIR] "
              "[--journal-dir DIR] [--bind HOST] [--port N] [--max-sessions N]",
              file=sys.stderr)
        return 2
    try:
        port = int(values.get("--port", "0"))
        sessions = int(values["--max-sessions"]) if "--max-sessions" in values else None
    except ValueError:
        print("glassport: --port and --max-sessions take integers", file=sys.stderr)
        return 2
    log_dir = Path(values.get("--log-dir", DEFAULT_LOG_DIR))
    journal_dir = Path(values.get("--journal-dir", log_dir / "decisions"))
    # Validate before building anything, so a bad URL never leaves an observer
    # and a journal dangling behind an early return.
    try:
        _validate_remote(values["--url"])
        limits = (HTTPRegistryLimits(max_sessions=sessions) if sessions is not None
                  else HTTPRegistryLimits())
    except ValueError as exc:
        print(f"glassport: invalid observe configuration: {exc}", file=sys.stderr)
        return 2
    # PLAY: Only after validation do we build state. An early return with
    # an observer already holding sockets and a journal already append-
    # opening a file would leave both behind for nothing.
    observer = HTTPObserver(log_dir, limits=limits)
    journal = DecisionJournal(journal_dir, observer)
    run_http_tap(values["--url"], log_dir, values.get("--bind", "127.0.0.1"),
                 port, observer=observer, journal=journal)
    return 0


def _run_http_gate(remote_url: str, log_dir: Path, port: int = 0, *,
                   endpoint_era: str = "auto",
                   scope_headers: tuple = (), public_surface: bool = False,
                   strict: bool = False) -> int:
    """`glassport gate --transport http --url <remote>` — HTTP enforcement.

    Deliberately the same construction as `observe`, differing in exactly one
    argument: the journal's mode. Enforcement is therefore not a second
    analysis path that could drift from the observed one — it is the observed
    one, with the verdict it already computed finally acted upon. Everything
    the observe command guarantees about session isolation, bounded state and
    fail-open recording holds here unchanged.
    """
    from glassport.adapters.mcp_http import GATE_MAX_BODY, _validate_remote, run_http_tap
    from glassport.decision_journal import MODE_GATE, DecisionJournal
    from glassport.http_sessions import HTTPObserver, HTTPRegistryLimits

    # Validate before building anything, so a bad URL never leaves an observer
    # and a journal dangling behind an early return (as `observe` does).
    _validate_remote(remote_url)
    # Gate mode refuses any body its observer cannot fold whole, so the
    # observer's frame limit is the enforcement inspection limit.
    # PLAY: That is why the frame limit is GATE_MAX_BODY here and the
    # default elsewhere: if a body is too large to fold, the gate cannot
    # judge it, and an unjudged body must not be forwarded by the gate.
    observer = HTTPObserver(log_dir, limits=HTTPRegistryLimits(max_frame_bytes=GATE_MAX_BODY),
                            scope_headers=scope_headers, public_surface=public_surface)
    journal = DecisionJournal(log_dir / "decisions", observer, mode=MODE_GATE,
                              strict=strict)
    run_http_tap(remote_url, log_dir, port=port, observer=observer,
                 journal=journal, endpoint_era=endpoint_era)
    return 0


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────
USAGE = """\
glassport — wire-level observability and enforcement for MCP servers

usage: glassport <command> [options]   (`glassport help <command>`, `glassport --version`)

  probe:           glassport probe [--call NAME JSON]... [--log-dir DIR]
                        [--timeout S] [--startup-timeout S] [-o out.html]
                        [--json] [--open] -- <server command...>
                   (be the client: handshake + tools/list through the tap,
                    then write the HTML report. List-only unless --call.
                    exit 0 clean, 1 findings, 3 handshake incomplete)
  wrap (default):  glassport [wrap] [--log-dir DIR] -- <server command...>
                   glassport wrap --transport http --url <remote-mcp-url> [--port N]
                        (passive MITM over MCP Streamable-HTTP; logs both
                         directions to the same JSONL as the stdio tap.
                         --port pins the local proxy port; default random)
  gate:            glassport gate [--controllable] [--strict] [--log-dir DIR] -- <server command...>
                   (active: blocks tools/call outside the declared surface;
                    --controllable lets `tui --gate-control` toggle it;
                    --strict blocks when a check cannot run instead of
                    forwarding with a logged gate_skipped marker)
                   glassport gate --transport http --url <remote-mcp-url> [--strict] [--port N]
                        [--endpoint-era auto|legacy|modern]
                        [--scope-header NAME]... [--public-surface]
                        (active MITM over MCP Streamable-HTTP: everything
                         `observe` does, plus the recorded would-blocks are
                         enforced. --port pins the local proxy port; default
                         random. By default only a severity-3 tools/call proved against
                         an observed declared surface is refused — locally,
                         with a JSON-RPC -32000 error and no upstream request.
                         Default forwards missing/partial declarations and
                         faulted analysis. --strict blocks tools/call when
                         evidence is missing, including a failed wire write;
                         complete tools/list first and provide a scope for
                         modern stateless callers (or --public-surface);
                         PII, taint and schema findings remain warn-only)
  audit:           glassport audit <path> [--json|--sarif]
                        [--provenance [--provenance-cache DIR]
                         [--provenance-refresh]] | audit --rubric
                   (static, pre-deployment: reads source, never runs it.
                    --provenance: opt-in npm/PyPI registry enrichment, off
                    by default so the core audit stays offline/reproducible)
  observe:         glassport observe --url <remote-mcp-url> [--log-dir DIR]
                        [--journal-dir DIR] [--bind HOST] [--port N]
                        [--max-sessions N]
                   (HTTP tap with per-epoch session isolation plus recorded
                    candidate decisions and delivery outcomes. Observation
                    only: nothing is ever blocked)
  replay-decisions: glassport replay-decisions <journal.jsonl>
                        --wire <session.jsonl> [--json]
                   (re-derive one epoch's decisions under identical code;
                    digests cross-check artifacts, not signatures.
                   exit 0 only when analysis is equivalent)
  bundle:          glassport bundle (--wire PATH... | --log-dir DIR)
                        [--journal-dir DIR] [--audit PATH] -o OUT
                        [--sign KEYFILE] [--redact]
                   glassport bundle verify OUT [--trusted-key PUB] [--json]
  summarize:       glassport summarize [--json|--sarif] <session.jsonl>
  detect:          glassport detect [--sarif] <session.jsonl>
                   (run all behavioral detectors; exit 1 if findings,
                    or emit SARIF 2.1.0 with --sarif)
  advise:          glassport advise [--audit <path>] [--session <s.jsonl>] [--write FILE] [--all]
  report:          glassport report <session.jsonl> [-o out.html]
  watch:           glassport watch [log-dir] [--json]
  serve:           glassport serve [--log-dir DIR]
                   (expose glassport itself as a queryable MCP server)
                   glassport serve --http [--port N] [--bind HOST]
                        [--log-dir DIR] [--audit PATH]
                   (web console at http://127.0.0.1:PORT/console —
                    live timeline, drift, audit, SARIF, advisory)
  tui:             glassport tui [session.jsonl] [--log-dir DIR]
                        [--audit PATH] [--gate-control]
                   (live curses inspector; no argument = session picker.
                    --audit adds the static scorecard to the `a` panel;
                    --gate-control lets `!` toggle a controllable gate)
  prune:           glassport prune --older-than 30d [--log-dir DIR]
                        [--apply] [--force] [--threshold N]
                   (retention: dry-run by default; keeps logs carrying
                    detector_error evidence unless --force)
  health:          glassport health [--log-dir DIR] [--last N] [--json]
                   (aggregate tap self-metrics: frames, blocks,
                    detector errors across recent sessions)

(`python3 glassport_tap.py ...` from a clone works identically.)
"""


VERBS = ("probe", "wrap", "gate", "audit", "observe", "replay-decisions", "bundle",
         "summarize", "detect", "advise", "report", "watch", "serve", "tui",
         "prune", "health")
_VERB_HEAD = re.compile(r"^  ([a-z-]+)(?: \([a-z]+\))?:", re.M)


def _verb_usage(verb: str) -> str:
    """That verb's block of USAGE (header line through its last
    continuation line), or the whole USAGE if the verb has no block."""
    # PLAY: Help is sliced out of the same USAGE string the program prints,
    # so `glassport help watch` cannot describe a flag that `glassport
    # watch` no longer accepts. One source, no second copy to forget.
    heads = list(_VERB_HEAD.finditer(USAGE))
    for i, m in enumerate(heads):
        if m.group(1) == verb:
            end = heads[i + 1].start() if i + 1 < len(heads) else len(USAGE)
            return "usage:\n" + USAGE[m.start():end].rstrip() + "\n"
    return USAGE


def _escape_unencodable_output() -> None:
    """Session logs can carry lone surrogates (json.loads accepts "\\ud800")
    that a UTF-8 stdout cannot encode. Print them backslash-escaped, which
    inside JSON output is still a valid escape, rather than crash mid-report.
    A stream without reconfigure() (e.g. a test's StringIO) is left as is."""
    # PLAY: A lone surrogate is legal in a JSON string and illegal in UTF-8,
    # so a captured frame can be perfectly valid JSON that cannot be
    # printed. backslashreplace turns the unprintable character into text
    # that still parses as the same JSON escape.
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def _parse_gate_flags(argv: list[str]) -> tuple[list[str], bool, bool]:
    """Strip leading `gate` flags in any order: (rest, controllable, strict)."""
    # PLAY: Leading only. Once the parser sees something that is not a gate
    # flag, the remainder belongs to the server command line and must reach
    # it untouched -- the child may legitimately want a flag of its own.
    controllable = strict = False
    while argv and argv[0] in ("--controllable", "--strict"):
        if argv[0] == "--controllable":
            controllable = True
        else:
            strict = True
        argv = argv[1:]
    return argv, controllable, strict


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help", "help"):
        if argv[1:2] and argv[1] in VERBS:
            print(_verb_usage(argv[1]))
        else:
            print(USAGE)
        return 0
    if argv[0] in ("--version", "-V", "version"):
        from glassport import __version__
        print(f"glassport {__version__}")
        return 0
    # `<verb> --help` answers for every verb here, uniformly, before any
    # verb-specific parsing can mistake the flag for a path, a URL, or (for
    # wrap/gate) a server command to launch
    # PLAY: This check runs before any verb-specific parsing, and that
    # ordering is load-bearing: for wrap and gate, `--help` would otherwise
    # be read as a server command to launch.
    if argv[0] in VERBS and argv[1:2] and argv[1] in ("-h", "--help"):
        print(_verb_usage(argv[0]))
        return 0

    # "wrap" stays the passive default forever; "gate" is the opt-in
    # enforcing sibling it was reserved for (M5)
    # PLAY: `gate` doubles as the flag "the user asked for enforcement".
    # Over stdio it is the real Gate object; over HTTP it is a sentinel and
    # enforcement comes from the journal's mode instead.
    gate: Gate | None = None
    gate_controllable = False
    if argv[0] == "wrap":
        argv = argv[1:]
    elif argv[0] == "gate":
        argv, gate_controllable, strict = _parse_gate_flags(argv[1:])
        gate = Gate(strict=strict)
    if not argv:
        print(USAGE)
        return 2

    if argv[0] == "summarize":
        args = argv[1:]
        as_json = "--json" in args
        as_sarif = "--sarif" in args
        args = [a for a in args if not a.startswith("--")]
        if len(args) != 1:
            print("usage: glassport summarize [--json|--sarif] <session.jsonl>",
                  file=sys.stderr)
            return 2
        _escape_unencodable_output()
        return summarize(Path(args[0]), as_json=as_json, as_sarif=as_sarif)

    if argv[0] == "detect":
        args = argv[1:]
        as_sarif = "--sarif" in args
        args = [a for a in args if not a.startswith("--")]
        if len(args) != 1:
            print(USAGE)
            return 2
        _escape_unencodable_output()
        return _cmd_detect(Path(args[0]), as_sarif=as_sarif)

    if argv[0] == "advise":
        args = argv[1:]
        min_sev = 0 if "--all" in args else 2

        def _val(flag):
            if flag in args:
                idx = args.index(flag) + 1
                return args[idx] if idx < len(args) else None
            return None

        return _cmd_advise(_val("--audit"), _val("--session"),
                           _val("--write"), min_sev)

    # PLAY: Every dispatch below imports its module inside the branch.
    # That is the whole reason `glassport wrap -- npx some-server` starts
    # fast: tapping needs the logger and the gate, not the TUI, the HTML
    # renderer, or the static auditor.
    if argv[0] == "serve":
        # glassport as a queryable MCP audit server. Lazy import.
        from glassport import server as server_mod
        return server_mod.main(argv[1:])

    if argv[0] == "probe":
        # one-command client: drive a server through the tap, then report
        from glassport import probe as probe_mod
        return probe_mod.main(argv[1:])

    if argv[0] == "report":
        # M3 — static HTML render. Lazy import keeps tap mode import-light.
        from glassport import report as report_mod
        return report_mod.main(argv[1:])

    if argv[0] == "watch":
        # M4 — drift across sessions. Same lazy-import contract.
        from glassport import watch as watch_mod
        return watch_mod.main(argv[1:])

    if argv[0] == "audit":
        # static pre-deployment audit; standalone module, no trace deps
        from glassport import audit as audit_mod
        return audit_mod.main(argv[1:])

    if argv[0] == "tui":
        # live/replay curses inspector. Same lazy-import contract.
        from glassport import tui as tui_mod
        return tui_mod.main(argv[1:])

    if argv[0] == "prune":
        # retention for the log dir; dry-run by default. Lazy import.
        from glassport import prune as prune_mod
        return prune_mod.main(argv[1:])

    if argv[0] == "observe":
        # Explicit HTTP observation mode (session isolation + decision
        # journal). Its own strict parser; the wrap path below is untouched.
        return _cmd_observe(argv[1:])

    if argv[0] == "replay-decisions":
        # Verify recorded decisions against their wire evidence. Lazy import.
        from glassport import decision_replay
        return decision_replay.main(argv[1:])

    if argv[0] == "bundle":
        from glassport import bundle as bundle_mod
        return bundle_mod.main(argv[1:])

    if argv[0] == "health":
        # tap self-metrics over recent sessions. Lazy import.
        from glassport import health as health_mod
        return health_mod.main(argv[1:])

    log_dir = DEFAULT_LOG_DIR
    if argv[0] == "--log-dir":
        log_dir = Path(argv[1])
        argv = argv[2:]
    # H2.01: passive tap over MCP's Streamable-HTTP transport. Default stays
    # stdio (spawn + relay a child). `--transport http --url <remote>` runs a
    # local MITM proxy instead. Gate (active enforcement) now covers both
    # stdio and HTTP; they differ only in control surface — `--controllable`
    # is stdio-only and refused below for the HTTP gate.
    transport = "stdio"
    remote_url = None
    if argv and argv[0] == "--transport":
        transport = argv[1] if len(argv) > 1 else ""
        argv = argv[2:]
    if argv and argv[0] == "--url":
        remote_url = argv[1] if len(argv) > 1 else None
        argv = argv[2:]
    endpoint_era = "auto"
    if transport == "http":
        # Nothing after --url may be silently ignored: a mistyped enforcement
        # option would otherwise run with a weaker posture than was asked for.
        scope_headers: list[str] = []
        public_surface = False
        port = 0
        port_given = False
        # PLAY: Strict parsing again, for a security reason: an unknown or
        # mistyped option here would otherwise be ignored, and the gate
        # would run with a weaker posture than the operator asked for.
        # Refusing is the only way to know what was actually requested.
        while argv:
            option = argv[0]
            if option not in ("--endpoint-era", "--scope-header",
                              "--public-surface", "--strict", "--port"):
                print(f"glassport: unexpected argument {option!r} for --transport http",
                      file=sys.stderr)
                return 2
            if option == "--port":
                if port_given:
                    print("glassport: --port given more than once", file=sys.stderr)
                    return 2
                if len(argv) < 2:
                    print("glassport: --port requires a value", file=sys.stderr)
                    return 2
                try:
                    port = int(argv[1])
                except ValueError:
                    print("glassport: --port must be an integer", file=sys.stderr)
                    return 2
                if not 0 <= port <= 65535:
                    print("glassport: --port must be between 0 and 65535",
                          file=sys.stderr)
                    return 2
                port_given = True
                argv = argv[2:]
                continue
            if gate is None:
                print(f"glassport: {option} applies to gate mode only", file=sys.stderr)
                return 2
            if option == "--strict":
                gate.strict, argv = True, argv[1:]
                continue
            if option == "--public-surface":
                public_surface, argv = True, argv[1:]
                continue
            value = argv[1] if len(argv) > 1 else None
            if option == "--endpoint-era":
                from glassport.adapters.mcp_http import ENDPOINT_ERAS
                if value not in ENDPOINT_ERAS:
                    print("glassport: --endpoint-era must be one of "
                          + ", ".join(ENDPOINT_ERAS), file=sys.stderr)
                    return 2
                endpoint_era = value
            else:
                from glassport.http_sessions import _CREDENTIAL_NAMES, _HEADER_TOKEN
                if (value is None or not _HEADER_TOKEN.match(value.lower())
                        or value.lower() in _CREDENTIAL_NAMES):
                    print("glassport: --scope-header needs a header name other than "
                          "the credential headers", file=sys.stderr)
                    return 2
                scope_headers.append(value)
            argv = argv[2:]
        if not remote_url:
            print("usage: glassport %s --transport http --url <remote-mcp-url>"
                  % ("gate" if gate is not None else "wrap"), file=sys.stderr)
            return 2
        if gate is not None and gate_controllable:
            # --controllable toggles the stdio Gate through an override file;
            # the HTTP gate has no such control surface. Refuse rather than
            # accept the flag and quietly enforce unconditionally anyway.
            # PLAY: Silently accepting it would be the worst option: the
            # operator would believe they had a kill switch they do not.
            print("glassport: --controllable applies to the stdio gate only",
                  file=sys.stderr)
            return 2
        from glassport.adapters.mcp_http import run_http_tap
        try:
            if gate is not None:
                # `gate` here is only the sentinel meaning "the user asked for
                # enforcement" — the stdio Gate object itself is never used
                # over HTTP. HTTP enforcement is a property of the decision
                # journal's mode, and runs through the same observer the
                # `observe` command builds.
                return _run_http_gate(remote_url, log_dir, port=port,
                                      endpoint_era=endpoint_era,
                                      scope_headers=tuple(scope_headers),
                                      public_surface=public_surface,
                                      strict=gate.strict)
            run_http_tap(remote_url, log_dir, "127.0.0.1", port)
        except ValueError as exc:
            print(f"[glassport] invalid --url: {exc}", file=sys.stderr)
            return 2
        except OSError as exc:
            print(f"glassport: cannot bind 127.0.0.1:{port}: {exc}",
                  file=sys.stderr)
            return 2
        return 0
    if transport != "stdio":
        print(f"glassport: unknown transport {transport!r} "
              "(expected 'stdio' or 'http')", file=sys.stderr)
        return 2
    if argv and argv[0] == "--":
        argv = argv[1:]
    if not argv:
        print(USAGE)
        return 2
    # Refuse before run_tap opens a session log: a typo or a flag we don't
    # know is a usage error, not a server to tap.
    # PLAY: Order matters twice here. The option check comes before the
    # existence check, because "--log-dir" should produce a usage error
    # rather than "command not found"; and both come before run_tap, so a
    # typo never leaves an empty session log behind.
    if argv[0].startswith("-"):
        print(f"glassport: unknown option {argv[0]!r} (see `glassport --help`)",
              file=sys.stderr)
        return 2
    if shutil.which(argv[0]) is None:
        # PLAY: 127 is the shell's convention for "command not found", so
        # a config that greps the exit code behaves the same as it would
        # without the tap in the middle.
        msg = f"glassport: command not found: {argv[0]}"
        # PLAY: The did-you-mean suggestion is why VERBS exists as a tuple
        # in one place. `glassport summrize file.jsonl` now costs a typo
        # instead of a confusing attempt to execute it as a program.
        close = difflib.get_close_matches(argv[0], VERBS, n=1)
        if close:
            msg += f" (did you mean `glassport {close[0]}`?)"
        print(msg, file=sys.stderr)
        return 127
    return run_tap(argv, log_dir, gate=gate,
                   gate_controllable=gate_controllable)


def cli() -> None:
    """Console-script entry point (``glassport`` command)."""
    # PLAY: The one line pyproject.toml points at. Everything else in this
    # file is reachable from here, so `glassport --help` is the map.
    sys.exit(main(sys.argv[1:]))


if __name__ == "__main__":
    cli()
