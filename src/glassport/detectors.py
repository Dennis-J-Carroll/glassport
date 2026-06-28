"""
detectors.py — M2 analysis passes over an InteractionTrace.

The adapter (adapters/mcp_session.py) produces the faithful trace and
nothing else; everything judgmental lives here. Each detector takes a
trace and returns Annotation objects — it never mutates events, so the
record of what crossed the wire stays separate from what we think of it.

Detectors only assert what the wire proves. If no initialize frame was
captured, no capability claim is made; if no tools/list was seen, a
schema can't be violated. Absence of evidence is reported as absence,
not as guilt.

Severity scale: 1 = worth a look, 2 = should not happen, 3 = hostile
or hallucinated unless proven otherwise.

    from detectors import annotate
    trace = from_mcp_session_file(path)
    annotate(trace)            # trace.annotations now populated
"""
from __future__ import annotations

import json
import math
import os
import re
import sys
import unicodedata
from typing import Any, Iterator, NamedTuple, Optional, Callable

from glassport.interaction_trace import (
    Annotation, AnnotationKind, HallucinationCategory,
    ActorKind, EventKind, Event, InteractionTrace, PartKind,
    _new_id,
)

ANNOTATOR = "glassport.detectors"

# Hard cap on the bytes any single blob is scanned for PII. Wire payloads
# are small; a multi-megabyte tool result is either a mistake or an attempt
# to make the scanner the bottleneck. Matches audit.MAX_FILE_BYTES.
MAX_SCAN_BYTES = 1_000_000

# Server-initiated requests and the client capability that must have been
# granted in the initialize handshake for the server to send them.
SERVER_REQUEST_CAPABILITY = {
    "sampling/createMessage": "sampling",
    "roots/list": "roots",
    "elicitation/create": "elicitation",
}
ALWAYS_ALLOWED_SERVER_REQUESTS = {"ping"}

_JSON_TYPES = {
    "string": str,
    "boolean": bool,
    "object": dict,
    "array": list,
    "null": type(None),
}


def _ann(event: Event, kind: AnnotationKind, subcategory: str,
         explanation: str, severity: int,
         category: Optional[HallucinationCategory] = None,
         **md) -> Annotation:
    return Annotation(
        id=_new_id("ann"), event_id=event.id, kind=kind, category=category,
        subcategory=subcategory, severity=severity, explanation=explanation,
        annotator=ANNOTATOR,
        metadata={"seq": event.metadata.get("seq"), **md},
    )


def _matches_type(value, type_name: str) -> bool:
    # bool is a subclass of int in Python; JSON Schema keeps them distinct
    if type_name == "boolean":
        return isinstance(value, bool)
    if type_name == "integer":
        return isinstance(value, int) and not isinstance(value, bool)
    if type_name == "number":
        return isinstance(value, (int, float)) and not isinstance(value, bool)
    py = _JSON_TYPES.get(type_name)
    return True if py is None else isinstance(value, py)


def _schema_problems(args, schema) -> Iterator[str]:
    """
    Top-level check of tools/call arguments against a declared inputSchema.
    Deliberately a subset of JSON Schema (required, top-level property
    types, additionalProperties: false) — enough to catch an agent
    inventing arguments, with zero dependencies.
    """
    if not isinstance(schema, dict) or schema.get("type", "object") != "object":
        return
    if not isinstance(args, dict):
        yield f"arguments are {type(args).__name__}, schema expects object"
        return
    props = schema.get("properties") or {}
    for req in schema.get("required") or []:
        if req not in args:
            yield f"missing required argument '{req}'"
    if schema.get("additionalProperties") is False:
        for key in args:
            if key not in props:
                yield (f"unexpected argument '{key}' "
                       f"(additionalProperties: false)")
    for key, value in args.items():
        spec = props.get(key)
        if not isinstance(spec, dict):
            continue
        declared_type = spec.get("type")
        types = (declared_type if isinstance(declared_type, list)
                 else [declared_type] if isinstance(declared_type, str)
                 else [])
        if types and not any(_matches_type(value, t) for t in types):
            yield (f"argument '{key}' is {type(value).__name__}, "
                   f"schema expects {declared_type}")


def _tool_call_parts(event: Event):
    for p in event.parts:
        if p.kind == PartKind.TOOL_USE:
            yield p.content.get("name", "?"), p.content.get("arguments")


def _list_result_names(event: Event) -> Optional[set[str]]:
    """Tool names in a tools/list response event, or None if not one."""
    if event.metadata.get("method_replied_to") != "<tools/list>":
        return None
    for p in event.parts:
        frame = p.content if isinstance(p.content, dict) else {}
        tools = (frame.get("result") or {}).get("tools")
        if isinstance(tools, list):
            return {t["name"] for t in tools
                    if isinstance(t, dict) and "name" in t}
    return None


def context_violations(trace: InteractionTrace) -> list[Annotation]:
    """
    Wire-provable violations of the session's negotiated context:

      schema_violation        call arguments break the declared inputSchema
      capability_violation    server-initiated request the client never granted
      unknown_server_request  server-initiated request outside the MCP set
      premature_call          tools/call before notifications/initialized
      call_before_declaration tools/call when no tools/list request was
                              ever sent (a call merely racing the
                              response is valid pipelining, not flagged)
      orphaned_response       response whose id matched no request
      surface_change          tools/list result changed mid-session
    """
    out: list[Annotation] = []

    client_caps: Optional[dict] = None
    tool_defs: dict[str, dict] = {}
    for actor in trace.actors:
        if actor.kind == ActorKind.AGENT and "capabilities" in actor.metadata:
            client_caps = actor.metadata["capabilities"]
        for t in actor.metadata.get("tools") or []:
            if isinstance(t, dict) and "name" in t:
                tool_defs.setdefault(t["name"], t)

    initialized_seen = False
    tools_list_requested = False
    first_surface: Optional[set[str]] = None

    for e in trace.events:
        md = e.metadata

        if e.kind == EventKind.MESSAGE and \
                md.get("method") == "notifications/initialized":
            initialized_seen = True

        # a c2s tools/list request means the client INTENDS to learn the
        # surface; parsed c2s requests carry no "dir" key, so the absent
        # server_initiated flag is the direction discriminator
        if e.kind == EventKind.MESSAGE and md.get("method") == "tools/list" \
                and not md.get("server_initiated"):
            tools_list_requested = True

        names = _list_result_names(e)
        if names is not None:
            if first_surface is None:
                first_surface = names
            elif names != first_surface:
                delta = sorted(names ^ first_surface)
                out.append(_ann(
                    e, AnnotationKind.DIVERGENCE, "surface_change",
                    f"tools/list surface changed mid-session; delta: {delta}",
                    severity=2, delta=delta))

        if e.kind == EventKind.TOOL_CALL:
            for name, args in _tool_call_parts(e):
                if not initialized_seen:
                    out.append(_ann(
                        e, AnnotationKind.ANOMALY, "premature_call",
                        f"tools/call '{name}' before notifications/initialized",
                        severity=2))
                elif first_surface is None and not tools_list_requested:
                    out.append(_ann(
                        e, AnnotationKind.ANOMALY, "call_before_declaration",
                        f"tools/call '{name}' and no tools/list request "
                        f"was ever sent", severity=1))
                schema = (tool_defs.get(name) or {}).get("inputSchema")
                for problem in _schema_problems(args, schema):
                    out.append(_ann(
                        e, AnnotationKind.DIVERGENCE, "schema_violation",
                        f"'{name}': {problem}", severity=2,
                        category=HallucinationCategory.TOOL_USE))

        if md.get("server_initiated") and not md.get("notification"):
            method = md.get("method")
            if method in ALWAYS_ALLOWED_SERVER_REQUESTS:
                pass
            elif method in SERVER_REQUEST_CAPABILITY:
                needed = SERVER_REQUEST_CAPABILITY[method]
                # no initialize captured -> no claim either way
                if client_caps is not None and needed not in client_caps:
                    out.append(_ann(
                        e, AnnotationKind.ANOMALY, "capability_violation",
                        f"server requested '{method}' but the client never "
                        f"granted the '{needed}' capability", severity=3))
            else:
                out.append(_ann(
                    e, AnnotationKind.ANOMALY, "unknown_server_request",
                    f"server-initiated request '{method}' is not a known "
                    f"MCP client capability", severity=2))

        if md.get("orphaned"):
            out.append(_ann(
                e, AnnotationKind.ANOMALY, "orphaned_response",
                f"response id={md.get('jsonrpc_id')} matched no request",
                severity=1))

    return out


def fabricated_calls(trace: InteractionTrace) -> list[Annotation]:
    """trace.fabricated_tool_calls() lifted into annotations."""
    events_by_id = {e.id: e for e in trace.events}
    declared = trace.declared_tools()
    out = []
    for event_id, name in trace.fabricated_tool_calls():
        out.append(_ann(
            events_by_id[event_id], AnnotationKind.HALLUCINATION,
            "fabricated_tool_call",
            f"tools/call '{name}' is outside the declared surface",
            severity=3, category=HallucinationCategory.TOOL_USE,
            no_declaration_seen=not declared))
    return out


def gate_actions(trace: InteractionTrace) -> list[Annotation]:
    """
    Gate enforcement (M5) surfaced as INFO annotations — the record that
    a frame was stopped at the glass, not a judgment about it (the call
    itself is still judged by fabricated_calls / context_violations).
    """
    out: list[Annotation] = []
    for e in trace.events:
        g = e.metadata.get("gate")
        if not isinstance(g, dict):
            continue
        if g.get("action") == "blocked":
            out.append(_ann(
                e, AnnotationKind.INFO, "gate_blocked",
                f"gate blocked tools/call '{g.get('tool')}' — outside the "
                f"declared surface; the server never saw this frame",
                severity=1, tool=g.get("tool")))
        elif g.get("action") == "injected":
            out.append(_ann(
                e, AnnotationKind.INFO, "gate_injected_response",
                f"error response synthesized by the gate for blocked call "
                f"'{g.get('tool')}'; the server never sent this frame",
                severity=1, tool=g.get("tool")))
        elif g.get("action") == "gate_skipped":
            out.append(_ann(
                e, AnnotationKind.INFO, "gate_skipped",
                f"gate failed open for tools/call '{g.get('tool')}' — "
                f"no tools/list response arrived within the hold window, "
                f"so this call was forwarded unenforced",
                severity=1, tool=g.get("tool"), reason=g.get("reason")))
    return out


# ─────────────────────────────────────────────────────────
# Data exfiltration — PII / credential egress (M6)
#
# Doctrine matches the rest of this module: assert only what the wire
# shows. A pattern fires on bytes that crossed the glass, a validator
# culls the obvious false positive, and the raw value never leaves this
# function — explanations and metadata carry a non-reversible tag, not
# the secret. The allowlist of trusted clouds LOWERS severity; it never
# suppresses a finding, because the most common real exfil channel is an
# attacker-controlled bucket on an otherwise-trusted domain.
# ─────────────────────────────────────────────────────────


def _calculate_entropy(s: str) -> float:
    """Shannon entropy (bits/char). High values flag random key material."""
    if not s:
        return 0.0
    freq: dict[str, int] = {}
    for ch in s:
        freq[ch] = freq.get(ch, 0) + 1
    n = len(s)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())


def _luhn_check(card_number: str) -> bool:
    """Luhn checksum — culls random digit runs that aren't real cards."""
    digits = [int(d) for d in card_number if d.isdigit()]
    if len(digits) < 13:
        return False
    total = 0
    for i, d in enumerate(reversed(digits)):
        if i % 2 == 1:
            d *= 2
            if d > 9:
                d -= 9
        total += d
    return total % 10 == 0


def _validate_ssn(ssn: str) -> bool:
    """Reject SSNs in ranges the SSA never issues (000/666/9xx, 00, 0000)."""
    if not re.match(r"^\d{3}-\d{2}-\d{4}$", ssn):
        return False
    area, group, serial = ssn.split("-")
    if area in ("000", "666") or area.startswith("9"):
        return False
    return group != "00" and serial != "0000"


def _iban_check(s: str) -> bool:
    """ISO 13616 MOD-97-10. Strip spaces/case, move the first 4 chars to the
    end, map A=10…Z=35, and validate as a big integer: valid iff % 97 == 1.
    Total — returns False on anything that isn't a structural IBAN."""
    s = s.replace(" ", "").upper()
    if not re.match(r"^[A-Z]{2}\d{2}[A-Z0-9]{11,30}$", s):
        return False
    rearranged = s[4:] + s[:4]
    try:
        return int("".join(str(int(c, 36)) for c in rearranged)) % 97 == 1
    except ValueError:                                   # pragma: no cover
        return False


def _aba_check(s: str) -> bool:
    """ABA routing number: 9 digits, a Federal Reserve leading-range guard
    (00–12, 21–32, 61–72, 80 — cuts the ~10% of random 9-digit strings a bare
    checksum would pass), then the weighted-sum test mod 10 == 0 with the
    repeating 3,7,1 weights. Total."""
    if len(s) != 9 or not s.isdigit():
        return False
    prefix = int(s[:2])
    if not (prefix <= 12 or 21 <= prefix <= 32 or 61 <= prefix <= 72
            or prefix == 80):
        return False
    weights = (3, 7, 1, 3, 7, 1, 3, 7, 1)
    return sum(int(d) * w for d, w in zip(s, weights)) % 10 == 0


class PIIPattern(NamedTuple):
    category: str
    severity: int                       # 1 worth a look · 2 should not · 3 hostile
    pattern: re.Pattern
    validator: Optional[Callable[[str], bool]]
    description: str


# Ordered most-specific first. Validators (defined ABOVE this list so the
# module imports cleanly) cull false positives.
PII_PATTERNS: list[PIIPattern] = [
    # ReDoS-hardened PEM matchers. The body is [^-]{20,8000}?, not
    # [\s\S]{20,}?: a PEM body is base64 (never a hyphen), so excluding '-'
    # means the body can't swallow a BEGIN/END marker. A flood of BEGIN
    # markers with no END therefore fails in O(1) per start position
    # instead of backtracking to EOF — and 8000 still holds an RSA-4096
    # key (≈3.2KB). _scan_pii also caps total input as a second guard.
    PIIPattern("rsa_private_key", 3, re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        r"[^-]{20,8000}?"
        r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        None, "RSA/EC/SSH private key (PEM block)"),
    PIIPattern("pgp_private_key", 3, re.compile(
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----[^-]{20,8000}?"
        r"-----END PGP PRIVATE KEY BLOCK-----"),
        None, "PGP private key block"),
    PIIPattern("anthropic_key", 3,
        re.compile(r"(sk-ant-api03-[A-Za-z0-9_-]{20,})"),
        None, "Anthropic API key"),
    PIIPattern("openai_key", 3,
        re.compile(r"(sk-(?:proj-)?[A-Za-z0-9]{32,})"),
        lambda s: len(s) >= 40, "OpenAI API key"),
    PIIPattern("aws_access_key", 3,
        re.compile(r"(?<![A-Z0-9])(AKIA[0-9A-Z]{16})(?![A-Z0-9])"),
        lambda s: len(s) == 20, "AWS access key ID"),
    PIIPattern("aws_secret_key", 3,
        re.compile(r"(?<![A-Za-z0-9/+=])([A-Za-z0-9/+=]{40})(?![A-Za-z0-9/+=])"),
        lambda s: _calculate_entropy(s) > 4.0, "AWS secret access key (entropy)"),
    PIIPattern("github_token", 3,
        re.compile(r"((?:gh[poursab]|github_pat)_[A-Za-z0-9_]{36,})"),
        lambda s: len(s) >= 40, "GitHub token"),
    PIIPattern("slack_token", 3,
        re.compile(r"(xox[baprs]-[0-9]{10,13}-[0-9]{10,13}-[A-Za-z0-9]{24,})"),
        None, "Slack token"),
    PIIPattern("database_url", 3, re.compile(
        r"((?:postgres|postgresql|mysql|mongodb|redis)://"
        r"[A-Za-z0-9_.-]+:[^@\s]+@[A-Za-z0-9._-]+(?::\d+)?/[A-Za-z0-9_-]+)"),
        None, "database URL with credentials"),
    PIIPattern("jwt_token", 2, re.compile(
        r"(eyJ[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,}\.[A-Za-z0-9_-]{10,})"),
        None, "JSON Web Token"),
    PIIPattern("generic_api_key", 2, re.compile(
        r"(?i)(?:api[_-]?key|apikey|secret[_-]?key|access[_-]?token|"
        r"auth[_-]?token|client[_-]?secret)"
        r"['\"]?\s*[:=]\s*['\"]([A-Za-z0-9_\-+=/.]{20,})['\"]"),
        lambda s: _calculate_entropy(s) > 3.0, "generic API key/secret"),
    PIIPattern("ssn", 3, re.compile(r"(?<!\d)(\d{3}-\d{2}-\d{4})(?!\d)"),
        _validate_ssn, "US Social Security Number"),
    PIIPattern("credit_card", 3, re.compile(
        r"(?<!\d)(4[0-9]{12}(?:[0-9]{3})?|5[1-5][0-9]{14}|"
        r"3[47][0-9]{13}|6(?:011|5[0-9]{2})[0-9]{12})(?!\d)"),
        _luhn_check, "credit card number (Luhn)"),
    PIIPattern("iban", 3, re.compile(
        r"(?<![A-Z0-9])([A-Z]{2}\d{2}[A-Z0-9]{11,30})(?![A-Z0-9])"),
        _iban_check, "International Bank Account Number (IBAN, MOD-97)"),
    # NB: ABA routing is deliberately NOT a default pattern. Its regex is a
    # bare \d{9}, which even with the leading-range + mod-10 guard passes ~3.8%
    # of random 9-digit strings — too broad to spend every user's precision
    # budget on. The validator + menu name "aba" still ship, so a consumer who
    # handles banking data opts in via GLASSPORT_PII_PATTERNS (see
    # examples/pii-financial.json). The registry exists precisely for this.
    PIIPattern("email_address", 1, re.compile(
        # bounded quantifiers — the unbounded `+@+` form catastrophically
        # backtracks on long attacker-controlled strings with no '@' (ReDoS)
        r"([A-Za-z0-9._%+-]{1,64}@[A-Za-z0-9.-]{1,255}\.[A-Za-z]{2,})"),
        None, "email address"),
    PIIPattern("private_ip", 1, re.compile(
        r"(?<!\d)(10\.\d{1,3}\.\d{1,3}\.\d{1,3}|"
        r"172\.(?:1[6-9]|2[0-9]|3[01])\.\d{1,3}\.\d{1,3}|"
        r"192\.168\.\d{1,3}\.\d{1,3})(?!\d)"),
        None, "private IP address (RFC 1918)"),
]

# Trusted clouds/CDNs: presence here only DOWNGRADES an egress finding.
TRUSTED_HOSTS = {"localhost", "127.0.0.1", "::1", "0.0.0.0"}
TRUSTED_DOMAINS = {
    "amazonaws.com", "cloudfront.net", "googleapis.com", "googleusercontent.com",
    "azure.com", "azurewebsites.net", "windows.net", "cloudflare.com",
    "fastly.net", "akamai.net", "openai.com", "anthropic.com",
    "modelcontextprotocol.io",
}

_URL_RE = re.compile(r"(?:https?|wss?)://([A-Za-z0-9.\-]+)(?::\d+)?", re.I)
_BARE_DOMAIN_RE = re.compile(r"^[a-z0-9.\-]+\.[a-z]{2,}$")


# Zero-width and bidi controls an attacker can sprinkle between the
# characters of a secret to break a raw-byte match while leaving the
# value intact for a downstream model/parser. Same set the audit flags
# as unicode-hidden; here we strip them so the scan sees through them.
_INVISIBLE_RE = re.compile(
    "[\\u200b-\\u200f\\u2060-\\u2064\\u202a-\\u202e\\u2066-\\u2069\\ufeff]")


def _normalize_for_scan(text: str) -> str:
    """Defeat obfuscation before pattern-matching: drop invisible/bidi
    characters, then NFKC-fold homoglyphs (fullwidth, etc.) to their
    canonical ascii. A secret split with zero-width joiners or disguised
    in fullwidth Latin reads as plaintext to the validators."""
    stripped = _INVISIBLE_RE.sub("", text)
    return unicodedata.normalize("NFKC", stripped)


def _redact(value: str, category: str) -> str:
    """Non-reversible tag — never returns plaintext (not even a prefix)."""
    return f"[{category} redacted · {len(value)} chars]"


# --- Custom-pattern plugin registry -------------------------------------
# Consumer-supplied PII patterns live here, kept SEPARATE from the built-in
# PII_PATTERNS so the baseline can never be corrupted and a reset is a single
# clear(). Two entry points feed it: register_pii_pattern() (in-code, full
# callable validators) and load_pii_patterns_from_json() (declarative,
# validator-by-name). _active_patterns() merges built-ins + customs for the
# scan; register/clear affect every scan that follows the call.
_CUSTOM_PATTERNS: list[PIIPattern] = []


def register_pii_pattern(pat: PIIPattern) -> None:
    """Add a custom PII pattern to every subsequent scan.

    The in-code path: the caller is in-process and trusted, so we do NOT
    re-validate (the PIIPattern type already constrains shape, and this path
    can carry an arbitrary callable validator that JSON cannot express). All
    untrusted-input validation lives in the JSON loader instead.
    """
    _CUSTOM_PATTERNS.append(pat)


def clear_custom_pii_patterns() -> None:
    """Drop all custom patterns and reset the env-autoload cache. Built-in
    PII_PATTERNS are untouched. Used for test isolation and config reload."""
    _CUSTOM_PATTERNS.clear()
    global _env_loaded
    _env_loaded = False


def _active_patterns() -> list[PIIPattern]:
    """Built-in patterns + customs, with GLASSPORT_PII_PATTERNS loaded once."""
    _ensure_env_patterns_loaded()
    return PII_PATTERNS + _CUSTOM_PATTERNS


# Set by _ensure_env_patterns_loaded(); reset by clear_custom_pii_patterns().
_env_loaded = False


# Consumers point this at a JSON file of custom patterns; it is loaded once,
# on the first scan, into the same registry register_pii_pattern() feeds.
_ENV_PATTERNS_VAR = "GLASSPORT_PII_PATTERNS"


def _ensure_env_patterns_loaded() -> None:
    """Load GLASSPORT_PII_PATTERNS once, FAIL-SAFE.

    Unlike the explicit load_pii_patterns_from_json() (which raises so the
    caller learns of a bad file), this implicit path must NEVER let a
    misconfigured custom-pattern file raise out of a scan: a typo there would
    crash data_exfiltration and blind the built-in detectors — the one failure
    this tool cannot have. So we set the cache flag first (no per-scan retry
    loop), then load, and on any error warn once to stderr and keep the
    built-ins live. Reset by clear_custom_pii_patterns()."""
    global _env_loaded
    if _env_loaded:
        return
    _env_loaded = True
    path = os.environ.get(_ENV_PATTERNS_VAR)
    if not path:
        return
    try:
        load_pii_patterns_from_json(path)
    except Exception as e:                                # noqa: BLE001
        print(f"glassport: ignoring {_ENV_PATTERNS_VAR} ({path}): {e}",
              file=sys.stderr)


# Named validators exposed to the JSON (declarative) path. JSON cannot carry a
# Python callable, so a declarative pattern references a built-in validator by
# name here. The in-code register_pii_pattern() path is unaffected — it passes
# its own callable directly.
#
# TODO(you): choose which built-in validators to expose and at what entropy
# thresholds. The built-ins available above are:
#   _luhn_check(s)        -> bool   (credit-card checksum)
#   _validate_ssn(s)      -> bool   (SSA-issued ranges)
#   _calculate_entropy(s) -> float  (Shannon bits/char; generic_api_key uses
#                                    > 3.0, aws_secret_key uses > 4.0)
# Leaving an entry out means JSON authors cannot name it (unknown name raises).
_NAMED_VALIDATORS: dict[str, Callable[[str], bool]] = {
    # Checksum validators — deterministic, ~0 false positives. Already
    # str -> bool and already total (return False on malformed input), so
    # they are named directly with no wrapper.
    "luhn": _luhn_check,        # credit-card checksum
    "ssn": _validate_ssn,       # SSA-issued ranges
    "iban": _iban_check,        # ISO 13616 MOD-97-10
    "aba": _aba_check,          # routing weighted-sum + Fed leading-range
    # Entropy gates — the recall-oriented fallback for opaque random tokens.
    # _calculate_entropy is total (0.0 on empty), so the lambdas can't raise
    # on the str a regex match always yields. Two tiers, per the cascaded-
    # model report's per-charset thresholds:
    #   3.0 — above natural-language's ~3.0 ceiling; catches most secrets
    #         while culling dictionary words. (gitleaks uses >=3 for api keys)
    #   4.0 — stricter, base64-grade; culls high-entropy NON-secrets such as a
    #         32-char hex digest (H~3.9) that 3.0 would keep.
    "entropy": lambda s: _calculate_entropy(s) > 3.0,
    "entropy_high": lambda s: _calculate_entropy(s) > 4.0,
}


def pii_pattern_from_dict(d: dict) -> PIIPattern:
    """Build one PIIPattern from a JSON object. Fails loud (ValueError) on a
    missing field, an out-of-range severity, a regex that will not compile, or
    an unknown validator name — this is the untrusted-input boundary."""
    try:
        category = str(d["category"])
        severity = d["severity"]
        pattern_src = d["pattern"]
        description = str(d["description"])
    except (KeyError, TypeError) as e:
        raise ValueError(f"custom PII pattern missing field {e}") from e
    if isinstance(severity, bool) or not isinstance(severity, int) \
            or not (1 <= severity <= 3):
        raise ValueError(
            f"severity must be an int in 1..3, got {severity!r} "
            f"for category {category!r}")
    try:
        compiled = re.compile(pattern_src)
    except re.error as e:
        raise ValueError(f"bad regex for category {category!r}: {e}") from e
    vname = d.get("validator")
    validator: Optional[Callable[[str], bool]] = None
    if vname is not None:
        if vname not in _NAMED_VALIDATORS:
            raise ValueError(
                f"unknown validator {vname!r} for category {category!r}; "
                f"known names: {sorted(_NAMED_VALIDATORS)}")
        validator = _NAMED_VALIDATORS[vname]
    return PIIPattern(category, severity, compiled, validator, description)


def load_pii_patterns_from_json(path: Any) -> int:
    """Load and register custom PII patterns from a JSON-array file. Returns
    the count registered. Atomic: every entry is validated BEFORE any is
    registered, so a malformed entry never leaves a half-loaded registry."""
    with open(path, encoding="utf-8") as f:
        try:
            data = json.load(f)
        except json.JSONDecodeError as e:
            raise ValueError(f"{path}: invalid JSON: {e}") from e
    if not isinstance(data, list):
        raise ValueError(
            f"{path}: expected a JSON array of patterns, "
            f"got {type(data).__name__}")
    pats = [pii_pattern_from_dict(d) for d in data]   # validate all first
    for p in pats:
        register_pii_pattern(p)
    return len(pats)


def _scan_pii(text: str) -> list[tuple[PIIPattern, str]]:
    """Validated, de-duplicated PII hits in one serialized blob.

    The blob is normalized first (invisible chars stripped, homoglyphs
    NFKC-folded) so obfuscated secrets can't slip past the patterns, and
    capped at MAX_SCAN_BYTES so a multi-megabyte tool payload can't turn
    the scan itself into a denial of service."""
    if len(text) > MAX_SCAN_BYTES:
        text = text[:MAX_SCAN_BYTES]
    text = _normalize_for_scan(text)
    hits: list[tuple[PIIPattern, str]] = []
    seen: set[tuple[str, str]] = set()
    for pat in _active_patterns():
        for m in pat.pattern.finditer(text):
            value = m.group(m.lastindex) if m.lastindex else m.group(0)
            if pat.validator and not pat.validator(value):
                continue
            dedup = (pat.category, value)
            if dedup in seen:
                continue
            seen.add(dedup)
            hits.append((pat, value))
    return hits


def _extract_hosts_from_value(value: Any, hosts: set[str]) -> None:
    """Recursively collect hostnames: embedded URLs anywhere, plus bare
    domain values. Deliberately does NOT mine domains out of prose or
    email addresses — only a real scheme or a whole-string domain counts."""
    if isinstance(value, str):
        for m in _URL_RE.finditer(value):
            hosts.add(m.group(1).lower())
        v = value.strip().lower()
        if " " not in v and "@" not in v and _BARE_DOMAIN_RE.match(v):
            hosts.add(v)
    elif isinstance(value, dict):
        for v in value.values():
            _extract_hosts_from_value(v, hosts)
    elif isinstance(value, (list, tuple)):
        for item in value:
            _extract_hosts_from_value(item, hosts)


def _extract_hosts_from_args(args: Any) -> set[str]:
    hosts: set[str] = set()
    _extract_hosts_from_value(args, hosts)
    return hosts


def _extract_declared_hosts(trace: InteractionTrace) -> set[str]:
    """Hosts the server itself put on the wire: serverInfo and tool defs."""
    declared: set[str] = set()
    for actor in trace.actors:
        si = actor.metadata.get("server_info")
        if isinstance(si, dict):
            _extract_hosts_from_value(si, declared)
        for tool in actor.metadata.get("tools") or []:
            if isinstance(tool, dict):
                _extract_hosts_from_value(tool.get("description", ""), declared)
                _extract_hosts_from_value(tool.get("inputSchema", {}), declared)
    return declared


def _is_trusted_host(hostname: str) -> bool:
    if hostname in TRUSTED_HOSTS:
        return True
    return any(hostname == d or hostname.endswith("." + d)
               for d in TRUSTED_DOMAINS)


def data_exfiltration(trace: InteractionTrace) -> list[Annotation]:
    """PII/credentials in tool-call arguments, sensitive egress to
    undeclared or merely-trusted hosts, and secrets leaked back in tool
    results. Severity: 3 hostile, 2 should-not-happen, 1 worth a look."""
    out: list[Annotation] = []
    declared = _extract_declared_hosts(trace)

    for e in trace.events:
        if e.kind == EventKind.TOOL_CALL:
            for name, args in _tool_call_parts(e):
                blob = json.dumps(args, ensure_ascii=False, default=str)
                hits = _scan_pii(blob)
                for pat, value in hits:
                    out.append(_ann(
                        e, AnnotationKind.DIVERGENCE, f"pii_{pat.category}",
                        f"tools/call '{name}' argument contains {pat.description}: "
                        f"{_redact(value, pat.category)}",
                        severity=pat.severity,
                        category=HallucinationCategory.TOOL_USE,
                        pii_category=pat.category))

                has_pii = any(p.severity >= 2 for p, _ in hits)
                for host in _extract_hosts_from_args(args):
                    if host in declared:
                        continue
                    trusted = _is_trusted_host(host)
                    if trusted and not has_pii:
                        continue            # ordinary cloud traffic, no secret
                    severity = 3 if (has_pii and not trusted) else 2
                    out.append(_ann(
                        e, AnnotationKind.ANOMALY, "unexpected_egress_host",
                        f"tools/call '{name}' reaches {host}"
                        + (" (allowlisted)" if trusted else " (undeclared)")
                        + (" CARRYING SENSITIVE DATA" if has_pii else ""),
                        severity=severity,
                        host=host, has_pii=has_pii, trusted=trusted))

        elif e.kind == EventKind.TOOL_RESULT:
            blob = json.dumps([p.content for p in e.parts],
                              ensure_ascii=False, default=str)
            for pat, _ in _scan_pii(blob):
                if pat.severity < 3:
                    continue
                out.append(_ann(
                    e, AnnotationKind.DIVERGENCE, f"pii_in_result_{pat.category}",
                    f"tool result leaks {pat.description}",
                    severity=3, category=HallucinationCategory.TOOL_USE,
                    pii_category=pat.category))
    return out


DETECTORS = [fabricated_calls, context_violations, gate_actions,
             data_exfiltration]


def _detector_error(detector_name: str, exc: BaseException) -> Annotation:
    """A detector crash is itself a signal — record it as an annotation
    rather than letting it abort the whole pass. Not tied to any one
    event (event_id=""): it's a fact about the analysis, not the trace."""
    return Annotation(
        id=_new_id("ann"), event_id="", kind=AnnotationKind.ANOMALY,
        subcategory="detector_error", severity=2,
        explanation=f"detector {detector_name!r} raised "
                    f"{type(exc).__name__}: {exc}",
        annotator=ANNOTATOR,
        metadata={"detector": detector_name,
                  "error_type": type(exc).__name__},
    )


def annotate(trace: InteractionTrace) -> list[Annotation]:
    """Run every detector and attach the results to the trace.

    Each detector is isolated: if one raises, its failure is captured as
    a 'detector_error' annotation and the remaining detectors still run,
    so a single bad pass can't blind the whole overwatch."""
    found: list[Annotation] = []
    for detector in DETECTORS:
        try:
            found.extend(detector(trace))
        except Exception as exc:                    # noqa: BLE001 — by design
            found.append(_detector_error(
                getattr(detector, "__name__", repr(detector)), exc))
    trace.annotations.extend(found)
    return found
