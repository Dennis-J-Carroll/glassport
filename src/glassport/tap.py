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

Frame log schema (one JSON object per line):
  {
    "schema_version": "0.1",
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

Author: Dennis J. Carroll · 2026 (skeleton drafted with Claude)
"""
from __future__ import annotations

from glassport.attestation import ATTESTATION_KEY, validate_public_key
from glassport.detectors import (
    MAX_SCAN_BYTES, find_taint, _schema_problems, _scan_pii, _redact,
    neutralize_text, _TAINT_PATTERNS,
)

import hashlib
import json
import math
import os
import secrets
import shlex
import signal
import subprocess
import sys
import threading
import time
from datetime import datetime, timezone
from pathlib import Path
from typing import Any

SCHEMA_VERSION = "0.1"
DEFAULT_LOG_DIR = Path(os.environ.get("GLASSPORT_LOG_DIR",
                                      Path.home() / ".glassport" / "sessions"))


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


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
    obj = dict(pairs)
    if len(obj) != len(pairs):
        raise ValueError("duplicate object key")
    return obj


def _loads(data: bytes) -> Any:
    """json.loads for gate decisions: tolerant of oversized integers, strict
    about duplicate keys (both are parser differentials)."""
    return json.loads(data, parse_int=_lenient_int, object_pairs_hook=_unique_object)


def _nesting_exceeds(value: Any, limit: int) -> bool:
    """True when dict/list nesting in `value` goes deeper than `limit`
    (a bare container is depth 1). Iterative, so it cannot itself hit the
    recursion limit it guards against."""
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
    text = json.dumps(obj, ensure_ascii=True)
    if "Infinity" not in text and "NaN" not in text:
        return text
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
    kept = [{k: v for k, v in item.items()
             if k in ("uri", "mimeType", "text", "blob") and isinstance(v, str)}
            for item in contents if isinstance(item, dict)]
    return (json.dumps({"jsonrpc": "2.0", "id": rid, "result": {"contents": kept}},
                       ensure_ascii=True) + "\n").encode("utf-8")


def _note_skip(info: dict | None, tool: str | None, reason: str) -> dict:
    """Record a fail-open check fault on the forward marker. The first
    fault keeps the `reason` field; later ones append to `also_skipped`,
    so the log shows every check that could not run."""
    if info is None:
        return {"action": "gate_skipped", "tool": tool, "reason": reason}
    info.setdefault("also_skipped", []).append(reason)
    return info


# ─────────────────────────────────────────────────────────────────
# Session logger — append-only JSONL, thread-safe, failure-isolated.
# ─────────────────────────────────────────────────────────────────
class SessionLog:
    def __init__(self, path: Path):
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
            self._fh = open(fd, "a", buffering=1, encoding="utf-8")
        else:
            # Non-POSIX: st_mode is advisory; do not fake enforcement.
            self._fh = open(path, "a", buffering=1, encoding="utf-8")
        self._lock = threading.Lock()
        self._seq = 0
        self.path = path

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
        s2c frame the server never sent. Optional field — schema 0.1 logs
        without it stay readable, readers without it stay correct.

        `metadata` carries transport-level annotations that must not be
        smashed into the parseable frame. For SSE it holds fields such as
        ``event``, ``id``, and ``retry`` so the JSON-RPC payload can still
        be logged as a structured ``frame``.
        """
        try:
            text = line.decode("utf-8", errors="replace").rstrip("\r\n")
            frame, raw = None, None
            try:
                frame = json.loads(text)
            except (json.JSONDecodeError, ValueError, RecursionError):
                raw = text
            with self._lock:
                if sequence is not None:
                    if type(sequence) is not int or sequence <= self._seq:
                        raise ValueError('session sequence must increase')
                    self._seq = sequence
                else:
                    self._seq += 1
                entry = {
                    "schema_version": SCHEMA_VERSION,
                    "seq": self._seq,
                    "ts": _now_iso(),
                    "dir": direction,
                    "frame": frame,
                    "raw": raw,
                }
                if gate is not None:
                    entry["gate"] = gate
                if metadata is not None:
                    entry["sse_meta"] = metadata
                if observation is not None:
                    entry["http_observation"] = observation
                if wire_bytes is not None:
                    import base64
                    entry["wire_b64"] = base64.b64encode(wire_bytes).decode("ascii")
                try:
                    serialized = json.dumps(entry, ensure_ascii=False)
                except RecursionError:
                    # Parsed but too deep to re-encode: keep the wire text
                    # rather than silently dropping the entry.
                    entry["frame"], entry["raw"] = None, text
                    serialized = json.dumps(entry, ensure_ascii=False)
                try:
                    serialized.encode("utf-8")
                except UnicodeEncodeError:
                    # json.loads accepts lone surrogates ("\\ud800") that
                    # UTF-8 cannot carry: escape this entry, never drop it.
                    serialized = json.dumps(entry, ensure_ascii=True)
                self._fh.write(serialized + "\n")
                return entry
        except Exception:
            return None  # logging is best-effort; the relay is sacred

    def write_json(self, entry: dict) -> bool:
        """Append one caller-shaped JSON record; True on a successful write.

        Not a wire frame and not part of the session schema: this is the
        private-file append primitive (0700 dir, 0600 file, one lock, never
        raises) reused by the decision journal, which owns its OWN files.
        Decision evidence and wire evidence are never written to one file.
        """
        try:
            line = json.dumps(entry, ensure_ascii=False) + "\n"
            with self._lock:
                self._fh.write(line)
            return True
        except Exception:
            return False  # journaling is best-effort; the relay is sacred

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
                entry.setdefault("log_bytes", self._fh.tell())
                self._fh.write(json.dumps(entry, ensure_ascii=False) + "\n")
        except Exception:
            pass  # metrics are best-effort; the relay is sacred

    def close(self) -> None:
        try:
            self._fh.close()
        except Exception:
            pass


def open_session_log(path: Path) -> "SessionLog | None":
    """Create a verified-private session log, or return None so the relay
    runs without recording. The relay is sacred: neither an unwritable dir
    nor a permission we could not secure may kill the session — we disable
    logging loudly instead."""
    try:
        log = SessionLog(path)
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
class Gate:
    """
    Blocks c2s tools/call frames that name a tool outside the server's
    declared surface. Everything else relays untouched.

    The gate only blocks what the wire can prove. Until a tools/list
    response has been seen there is no declaration to violate — but a
    pipelined client may fire tools/call before that response lands, so
    the gate HOLDS such calls (blocking the c2s pump; stdio backpressure
    is the flow control a real client expects anyway) until the surface
    arrives or `hold_timeout` expires. On timeout it fails open and the
    forwarded frame is logged with a "gate_skipped" marker, so the log
    still shows enforcement was impossible. The latest tools/list result
    IS the contract: a server that re-declares a smaller surface shrinks
    what it may be asked to do.

    A blocked request never reaches the server; the client receives a
    synthesized JSON-RPC error (code -32000) whose error.data carries
    {"glassport": "gate_blocked"} so callers can tell the gate's voice
    from the server's. Both the blocked frame and the injected response
    are logged with a "gate" marker — the session log records what each
    side actually saw, and they legitimately differ.
    """

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
        self._declared: set[str] | None = None   # None until tools/list seen
        self._declared_defs: dict[str, dict] = {}  # name -> full tool def
        self._pending_reads: dict[Any, str] = {}  # jsonrpc id -> uri
        self._surface_known = threading.Event()
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
        now = time.monotonic()
        key = hashlib.sha256(json.dumps(
            {"name": name, "arguments": arguments},
            sort_keys=True, default=str).encode("utf-8")).hexdigest()
        with self._lock:
            stale = [k for k, (_, ts) in self._recent_calls.items()
                     if now - ts > self.idempotency_ttl]
            for k in stale:
                del self._recent_calls[k]
            count, first_seen = self._recent_calls.get(key, (0, now))
            count += 1
            self._recent_calls[key] = (count, first_seen)
            return count > self.idempotency_max_repeats

    def _enforcement_on(self) -> bool:
        """Consult the override file. Fail-closed: enforcement stays ON
        unless the file is a well-formed {"enforce": false} owned by
        this uid with no group/world write bits."""
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
        return data.get("enforce", True) is not False

    def observe_s2c(self, line: bytes) -> None:
        """Harvest tool declarations from server output. Never raises."""
        try:
            frame = _loads(line)
        except (json.JSONDecodeError, ValueError, UnicodeDecodeError,
                RecursionError):
            return
        if not isinstance(frame, dict):
            return
        result = frame.get("result")
        if isinstance(result, dict) and isinstance(result.get("tools"), list):
            # string names only: an unhashable server-sent name used to
            # raise here, ending the s2c relay and leaving no surface
            defs = {t["name"]: t for t in result["tools"]
                    if isinstance(t, dict) and isinstance(t.get("name"), str)}
            with self._lock:
                self._declared = set(defs)
                self._declared_defs = defs
            self._surface_known.set()

    def _take_pending_read(self, rid: Any) -> str | None:
        """Pop the uri of the resources/read this reply answers, for the log
        marker only. A boolean id never pops: True == 1 in Python, so a
        {"id": true} primer used to consume pending read 1 (A9)."""
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
                if len(text) > MAX_SCAN_BYTES or find_taint({"text": text}) is not None:
                    sanitized = neutralize_text(text)
                    # Unicode neutralization preserves ASCII delimiters.
                    # Reuse the detection pattern to remove those explicitly.
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
                withheld = self._block(
                    rid, "quarantine_scan_error", None,
                    "glassport gate: resource content withheld — strict mode: "
                    "the quarantine scan failed")
                if withheld is None:
                    return ("drop", None, {"action": "quarantine_dropped",
                                           "uri": uri, "reason": "quarantine_scan_error"})
                return ("rewrite", withheld, {"action": "quarantine_withheld", "uri": uri})
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
        params = frame.get("params")
        if not isinstance(params, dict):
            params = {}
        name = params.get("name")
        if not isinstance(name, str):
            name = None
        with self._lock:
            declared = self._declared
        surface_missing = False
        if declared is None:
            # pipelined client: hold the call until the tools/list
            # response lands; the s2c pump will wake us via observe_s2c
            self._surface_known.wait(timeout=self._hold_timeout)
            with self._lock:
                declared = self._declared
            surface_missing = declared is None
        if surface_missing or name in declared:
            # With no declared surface only the undeclared-tool and schema
            # checks are impossible: fail open for those, visibly, but still
            # run attestation, depth, idempotency, taint, and PII.
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
            with self._lock:
                schema = (self._declared_defs.get(name) or {}).get("inputSchema")
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
                    if log is not None:
                        log.record(direction, line, gate=s2c_info)
                    continue
                if s2c_action == "rewrite" and s2c_new_line is not None:
                    if log is not None:
                        log.record(direction, line, gate=s2c_info)
                    line = s2c_new_line
                    # The common log call below records the replacement once.
                    gate_info = {**(s2c_info or {}), "action": "quarantine_replacement"}
                elif s2c_info is not None:
                    gate_info = s2c_info
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
    finally:
        try:
            dst.close()
        except Exception:
            pass


def pump_stderr(src, dst) -> None:
    """Pass the child's stderr through untouched (no framing assumed)."""
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
    stamp = datetime.now(timezone.utc).strftime("%Y%m%dT%H%M%SZ")
    safe_name = "".join(c if c.isalnum() else "_" for c in server_cmd[0])[:32]
    log_path = log_dir / f"{stamp}_{safe_name}_{os.getpid()}.jsonl"
    if gate is not None and gate_controllable:
        gate.control_path = log_path.with_name(log_path.name + ".gate")
    # The relay is sacred: a logging failure must never alter, delay, or kill
    # a live session. If the log dir is unwritable, disable logging and relay
    # anyway — pump() already tolerates a None log.
    log = open_session_log(log_path)

    # Announce on stderr only — stdout belongs to the protocol.
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
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.detectors import context_violations
    from glassport.interaction_trace import PartKind

    trace = from_mcp_session_file(log_path)

    # doctrine: assert only what the wire proves — a summary of a
    # tail-only ingest must say the head was never analyzed
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
    observer = HTTPObserver(log_dir, limits=limits)
    journal = DecisionJournal(journal_dir, observer)
    run_http_tap(values["--url"], log_dir, values.get("--bind", "127.0.0.1"),
                 port, observer=observer, journal=journal)
    return 0


def _run_http_gate(remote_url: str, log_dir: Path) -> int:
    """`glassport gate --transport http --url <remote>` — HTTP enforcement.

    Deliberately the same construction as `observe`, differing in exactly one
    argument: the journal's mode. Enforcement is therefore not a second
    analysis path that could drift from the observed one — it is the observed
    one, with the verdict it already computed finally acted upon. Everything
    the observe command guarantees about session isolation, bounded state and
    fail-open recording holds here unchanged.
    """
    from glassport.adapters.mcp_http import _validate_remote, run_http_tap
    from glassport.decision_journal import MODE_GATE, DecisionJournal
    from glassport.http_sessions import HTTPObserver

    # Validate before building anything, so a bad URL never leaves an observer
    # and a journal dangling behind an early return (as `observe` does).
    _validate_remote(remote_url)
    observer = HTTPObserver(log_dir)
    journal = DecisionJournal(log_dir / "decisions", observer, mode=MODE_GATE)
    run_http_tap(remote_url, log_dir, observer=observer, journal=journal)
    return 0


# ─────────────────────────────────────────────────────────────────
# CLI
# ─────────────────────────────────────────────────────────────────
USAGE = """\
glassport — passive MCP stdio proxy

  wrap (default):  glassport [wrap] [--log-dir DIR] -- <server command...>
                   glassport wrap --transport http --url <remote-mcp-url>
                        (passive MITM over MCP Streamable-HTTP; logs both
                         directions to the same JSONL as the stdio tap)
  gate:            glassport gate [--controllable] [--strict] [--log-dir DIR] -- <server command...>
                   (active: blocks tools/call outside the declared surface;
                    --controllable lets `tui --gate-control` toggle it;
                    --strict blocks when a check cannot run instead of
                    forwarding with a logged gate_skipped marker)
                   glassport gate --transport http --url <remote-mcp-url>
                        (active MITM over MCP Streamable-HTTP: everything
                         `observe` does, plus the recorded would-blocks are
                         enforced. Only a severity-3 tools/call proved against
                         an observed declared surface is refused — locally,
                         with a JSON-RPC -32000 error and no upstream request.
                         Missing/partial declarations, faulted analysis, PII
                         and unexpected-egress findings all still forward)
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
                   (re-run one epoch's analysis and verify the recorded
                    decisions; exit 0 only when equivalence is proved)
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


def _escape_unencodable_output() -> None:
    """Session logs can carry lone surrogates (json.loads accepts "\\ud800")
    that a UTF-8 stdout cannot encode. Print them backslash-escaped, which
    inside JSON output is still a valid escape, rather than crash mid-report.
    A stream without reconfigure() (e.g. a test's StringIO) is left as is."""
    for stream in (sys.stdout, sys.stderr):
        try:
            stream.reconfigure(errors="backslashreplace")
        except (AttributeError, ValueError, OSError):
            pass


def _parse_gate_flags(argv: list[str]) -> tuple[list[str], bool, bool]:
    """Strip leading `gate` flags in any order: (rest, controllable, strict)."""
    controllable = strict = False
    while argv and argv[0] in ("--controllable", "--strict"):
        if argv[0] == "--controllable":
            controllable = True
        else:
            strict = True
        argv = argv[1:]
    return argv, controllable, strict


def main(argv: list[str]) -> int:
    if not argv or argv[0] in ("-h", "--help"):
        print(USAGE)
        return 0

    # "wrap" stays the passive default forever; "gate" is the opt-in
    # enforcing sibling it was reserved for (M5)
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

    if argv[0] == "serve":
        # glassport as a queryable MCP audit server. Lazy import.
        from glassport import server as server_mod
        return server_mod.main(argv[1:])

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
    if transport == "http":
        if not remote_url:
            print("usage: glassport %s --transport http --url <remote-mcp-url>"
                  % ("gate" if gate is not None else "wrap"), file=sys.stderr)
            return 2
        if gate is not None and gate_controllable:
            # --controllable toggles the stdio Gate through an override file;
            # the HTTP gate has no such control surface. Refuse rather than
            # accept the flag and quietly enforce unconditionally anyway.
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
                return _run_http_gate(remote_url, log_dir)
            run_http_tap(remote_url, log_dir)
        except ValueError as exc:
            print(f"[glassport] invalid --url: {exc}", file=sys.stderr)
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
    return run_tap(argv, log_dir, gate=gate,
                   gate_controllable=gate_controllable)


def cli() -> None:
    """Console-script entry point (``glassport`` command)."""
    sys.exit(main(sys.argv[1:]))


if __name__ == "__main__":
    cli()
