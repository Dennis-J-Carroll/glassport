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
import re
from typing import Any, Iterator, NamedTuple, Optional, Callable

from glassport.interaction_trace import (
    Annotation, AnnotationKind, HallucinationCategory,
    ActorKind, EventKind, Event, InteractionTrace, PartKind,
    _new_id,
)

ANNOTATOR = "glassport.detectors"

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


class PIIPattern(NamedTuple):
    category: str
    severity: int                       # 1 worth a look · 2 should not · 3 hostile
    pattern: re.Pattern
    validator: Optional[Callable[[str], bool]]
    description: str


# Ordered most-specific first. Validators (defined ABOVE this list so the
# module imports cleanly) cull false positives.
PII_PATTERNS: list[PIIPattern] = [
    PIIPattern("rsa_private_key", 3, re.compile(
        r"-----BEGIN (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"
        r"[\s\S]{20,}?"
        r"-----END (?:RSA |EC |OPENSSH )?PRIVATE KEY-----"),
        None, "RSA/EC/SSH private key (PEM block)"),
    PIIPattern("pgp_private_key", 3, re.compile(
        r"-----BEGIN PGP PRIVATE KEY BLOCK-----[\s\S]{20,}?"
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
    PIIPattern("email_address", 1, re.compile(
        r"([A-Za-z0-9._%+-]+@[A-Za-z0-9.-]+\.[A-Za-z]{2,})"),
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


def _redact(value: str, category: str) -> str:
    """Non-reversible tag — never returns plaintext (not even a prefix)."""
    return f"[{category} redacted · {len(value)} chars]"


def _scan_pii(text: str) -> list[tuple[PIIPattern, str]]:
    """Validated, de-duplicated PII hits in one serialized blob."""
    hits: list[tuple[PIIPattern, str]] = []
    seen: set[tuple[str, str]] = set()
    for pat in PII_PATTERNS:
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


def annotate(trace: InteractionTrace) -> list[Annotation]:
    """Run every detector and attach the results to the trace."""
    found: list[Annotation] = []
    for detector in DETECTORS:
        found.extend(detector(trace))
    trace.annotations.extend(found)
    return found
