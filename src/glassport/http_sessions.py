"""Bounded, opt-in HTTP observation. No transport send or policy authority.

A registry belongs to one configured upstream. Headers route only within an
opaque credential partition. Each epoch has its own wire log and no-history
builder/engine. Neither raw credentials nor session tokens enter that log.
"""
from __future__ import annotations

from collections import OrderedDict
from dataclasses import dataclass, field
import hashlib
import hmac
import json
import re
from pathlib import Path
import secrets
import threading
import time
from typing import Callable

from glassport.adapters.mcp_session import MCPTraceBuilder
from glassport.detectors import snapshot_pii_patterns
from glassport.incremental import DetectorEngine, default_detectors
from glassport.session import SessionLimits
from glassport.tap import _now_iso, open_session_log


@dataclass(frozen=True)
class HTTPRegistryLimits:
    max_sessions: int = 128
    idle_ttl: float = 300.0
    max_identifier_chars: int = 256
    max_sse_ids: int = 1024
    max_frame_bytes: int = 1_000_000

    def __post_init__(self):
        import math
        if (any(type(getattr(self, key)) is not int or getattr(self, key) < 1
                for key in ('max_sessions', 'max_identifier_chars', 'max_sse_ids', 'max_frame_bytes'))
                or isinstance(self.idle_ttl, bool)
                or not isinstance(self.idle_ttl, (int, float))
                or not math.isfinite(self.idle_ttl) or self.idle_ttl <= 0):
            raise ValueError('HTTP limits must be positive and finite')


@dataclass(frozen=True)
class Observation:
    """Linkage for later intent/outcome recording, never a delivery assertion.

    persisted means this exact entry was accepted by SessionLog.write; it is
    neither fsync durability nor proof of a socket write or remote execution.
    """
    epoch: str | None
    seq: int | None
    event: object = None
    annotations: tuple = ()
    persisted: bool = False
    diagnostic: str | None = None


@dataclass(eq=False)
class _Context:
    epoch: str
    partition: str
    last_used: float
    builder: MCPTraceBuilder
    engine: DetectorEngine
    lock: object = field(default_factory=threading.RLock)
    active: int = 0
    retired: bool = False
    lost: bool = False
    key: tuple | None = None
    log: object = None
    log_opened: bool = False
    seq: int = 0
    sse_ids: OrderedDict = field(default_factory=OrderedDict)
    # Frozen at epoch creation; the live registry may mutate afterwards.
    pii_patterns: tuple = ()
    # A stateless (2026-07-28) declaration scope shared by many POSTs.
    shared: bool = False


_CREDENTIAL_NAMES = ('authorization', 'cookie', 'proxy-authorization')
_HEADER_TOKEN = re.compile(r"^[!#$%&'*+.^_`|~0-9a-z-]+$")


def _single(headers, name, limit):
    values = [v for k, v in headers if k.lower() == name]
    if not values:
        return None, None
    if len(values) != 1 or not isinstance(values[0], str):
        return None, 'http_invalid_identity'
    value = values[0]
    # Commas can be a folded duplicate header. Reject instead of guessing.
    if not value or len(value) > limit or any(ord(c) < 33 or ord(c) > 126 or c == ',' for c in value):
        return None, 'http_invalid_identity'
    return value, None


def _rpc_frame(payload):
    """Only complete MCP JSON-RPC objects can supply correlation evidence."""
    try:
        frame = json.loads(payload)
    except (ValueError, UnicodeError, RecursionError):
        return None
    if not isinstance(frame, dict) or frame.get('jsonrpc') != '2.0':
        return None
    if 'method' in frame:
        if (not isinstance(frame['method'], str) or not frame['method']
                or 'result' in frame or 'error' in frame
                or ('params' in frame and not isinstance(frame['params'], dict))):
            return None
    elif ('id' not in frame or ('result' in frame) == ('error' in frame)
          or ('error' in frame and not isinstance(frame['error'], dict))):
        return None
    return frame


class HTTPObserver:
    """Explicit analysis integration object; use one instance per upstream proxy.

    on_observation runs after a context fold, outside its lock. Consumers must
    use epoch/seq rather than callback arrival order. Callback errors fail open.
    Disk captures grow with traffic; retained in-memory state and open logs are
    bounded. Unroutable traffic gets a private request epoch when capacity allows.
    """
    def __init__(self, log_dir: Path, *, limits: HTTPRegistryLimits | None = None,
                 session_limits: SessionLimits | None = None,
                 clock: Callable[[], float] = time.monotonic,
                 on_observation: Callable[[Observation], None] | None = None,
                 scope_headers=(), public_surface: bool = False):
        """`scope_headers` names request headers (e.g. a tenant selector)
        that, with the credentials, define a stateless declaration scope.
        `public_surface` lets anonymous 2026 callers share one scope; without
        it their calls are observed but never enforced (unproven scope)."""
        names = tuple(sorted({str(h).strip().lower() for h in scope_headers}))
        if any(not _HEADER_TOKEN.match(n) or n in _CREDENTIAL_NAMES for n in names):
            raise ValueError('scope headers must be header names other than credentials')
        self.scope_headers = names
        self.public_surface = bool(public_surface)
        self._scopes: dict[tuple, _Context] = {}
        self.log_dir = Path(log_dir)
        self.limits = limits or HTTPRegistryLimits()
        self.session_limits = session_limits or SessionLimits()
        self.clock = clock
        self.on_observation = on_observation
        self._salt = secrets.token_bytes(32)
        self._lock = threading.Lock()
        self._contexts: dict[str, _Context] = {}
        self._bindings: dict[tuple, _Context] = {}
        self._closed = False

    def _partition(self, headers):
        # Cookie and proxy credentials also change upstream credential context.
        # Hash incrementally: never concatenate an unbounded retained value.
        digest = hmac.new(self._salt, digestmod=hashlib.sha256)
        for k, v in sorted((k.lower(), v) for k, v in headers
                           if k.lower() in ('authorization', 'cookie', 'proxy-authorization')):
            for part in (k, v):
                encoded = part.encode('utf-8', errors='surrogatepass')
                digest.update(len(encoded).to_bytes(8, 'big')); digest.update(encoded)
        return digest.hexdigest()

    def _scope_key(self, headers, version):
        """In-memory key of a stateless scope: version plus an HMAC over the
        credential and configured scope headers. Raw values never persist."""
        digest = hmac.new(self._salt, digestmod=hashlib.sha256)
        for part in ('scope', version):
            encoded = part.encode('utf-8', errors='surrogatepass')
            digest.update(len(encoded).to_bytes(8, 'big')); digest.update(encoded)
        for k, v in sorted((k.lower(), v) for k, v in headers
                           if k.lower() in _CREDENTIAL_NAMES + self.scope_headers):
            for part in (k, v):
                encoded = part.encode('utf-8', errors='surrogatepass')
                digest.update(len(encoded).to_bytes(8, 'big')); digest.update(encoded)
        return ('scope', version, digest.hexdigest())

    def _begin_scope(self, method, headers, version, patterns):
        """Route a 2026-07-28 POST to its stateless declaration scope."""
        names = [k.lower() for k, _ in headers]
        identity = _CREDENTIAL_NAMES + self.scope_headers
        diagnostic = None
        if any(names.count(n) > 1 for n in identity):
            diagnostic = 'http_invalid_credentials'
        elif not any(n in names for n in _CREDENTIAL_NAMES) and not self.public_surface:
            diagnostic = 'http_unproven_scope'
        key = None if diagnostic else self._scope_key(headers, version)
        now, cleanup = self.clock(), []
        with self._lock:
            for context in list(self._contexts.values()):
                if not context.active and now - context.last_used >= self.limits.idle_ttl:
                    self._retire_locked(context); cleanup.append(context)
            context = self._scopes.get(key) if key is not None else None
            if context is None:
                self._make_room_locked(cleanup)
                if len(self._contexts) >= self.limits.max_sessions or self._closed:
                    diagnostic = 'http_closed' if self._closed else 'http_capacity'
                else:
                    context = _Context(secrets.token_hex(16), key[2] if key else '', now,
                        MCPTraceBuilder(retain_events=False, limits=self.session_limits),
                        DetectorEngine(default_detectors(patterns)),
                        pii_patterns=patterns, shared=key is not None and not diagnostic)
                    if context.shared:
                        context.key = key
                        self._scopes[key] = context
                    self._contexts[context.epoch] = context
            if context is not None:
                context.active += 1
        self._close_idle(cleanup)
        lease = HTTPLease(self, context, method, diagnostic)
        lease.exchange = secrets.token_hex(8)
        if context is not None and diagnostic:
            lease.loss(diagnostic)
        elif context is None and diagnostic:
            self._emit(Observation(None, None, diagnostic=diagnostic))
        return lease

    def _make_room_locked(self, cleanup):
        """Free one slot for a new context, if the registry is full.

        Only an idle context that carries no declaration is ever evicted.
        Displacing one that does would let any caller who can open contexts
        (distinct bogus tokens cost nothing) switch enforcement off for an
        established session or scope. Under real pressure the newcomer gets
        `http_capacity` instead: observed, unenforced, and nobody's existing
        authority is touched.
        """
        if len(self._contexts) < self.limits.max_sessions:
            return
        idle = [c for c in self._contexts.values()
                if not c.active and c.builder.state.surface is None]
        if idle:
            victim = min(idle, key=lambda c: c.last_used)
            self._retire_locked(victim)
            cleanup.append(victim)

    def _retire_locked(self, context):
        context.retired = True
        if context.key is not None and self._bindings.get(context.key) is context:
            del self._bindings[context.key]
        if context.key is not None and self._scopes.get(context.key) is context:
            del self._scopes[context.key]
        if context.active == 0:
            self._contexts.pop(context.epoch, None)

    def _close_idle(self, contexts):
        for context in contexts:
            with context.lock:
                if context.log is not None:
                    context.log.close()

    def begin(self, method: str, headers, **_unused):
        headers = list(headers.items()) if hasattr(headers, 'items') else list(headers)
        # Use the same hop-header rules as forwarding, preserving duplicate
        # fields until ambiguity is checked instead of collapsing them to dict.
        from glassport.adapters.mcp_http import _hop_headers
        dropped = _hop_headers(headers)
        headers = [(k, v) for k, v in headers if k.lower() not in dropped]
        from glassport.adapters.mcp_http import MODERN_VERSIONS
        version, version_error = _single(headers, 'mcp-protocol-version',
                                         self.limits.max_identifier_chars)
        if method == 'POST' and version in MODERN_VERSIONS and not version_error:
            # 2026-07-28 has no sessions: Mcp-Session-Id and Last-Event-ID
            # carry no meaning, so the request routes by scope instead.
            return self._begin_scope(method, headers, version, snapshot_pii_patterns())
        token, diagnostic = _single(headers, 'mcp-session-id', self.limits.max_identifier_chars)
        cursor, cursor_error = _single(headers, 'last-event-id', self.limits.max_identifier_chars)
        ambiguous_credentials = any(sum(k.lower() == name for k, _ in headers) > 1
                                    for name in ('authorization', 'cookie', 'proxy-authorization'))
        if ambiguous_credentials:
            diagnostic = diagnostic or 'http_invalid_credentials'
        partition = self._partition(headers)
        # Snapshot the mutable PII registry outside the registry lock (it may
        # load the env pattern file on its first call). A new epoch keeps this
        # exact tuple for its whole life, so a mid-session register/clear can
        # never change what an already-recorded decision was computed from.
        patterns = snapshot_pii_patterns()
        now, cleanup, victims = self.clock(), [], []
        with self._lock:
            for context in list(self._contexts.values()):
                if not context.active and now - context.last_used >= self.limits.idle_ttl:
                    self._retire_locked(context); cleanup.append(context)
            if ambiguous_credentials and token is not None:
                # Upstream may select any of the ambiguous credentials. None
                # of this token's prior partitions can retain certainty about
                # traffic which may have affected it but could not be routed.
                victims = [c for key, c in self._bindings.items() if key[1] == token]
                for victim in victims:
                    self._retire_locked(victim)
            context = self._bindings.get((partition, token)) if token and diagnostic is None else None
            if context is None:
                if not diagnostic and (token or method != 'POST'):
                    diagnostic = 'http_unknown_identity' if token else 'http_missing_identity'
                self._make_room_locked(cleanup)
                if len(self._contexts) >= self.limits.max_sessions or self._closed:
                    diagnostic = 'http_closed' if self._closed else 'http_capacity'
                else:
                    context = _Context(secrets.token_hex(16), partition, now,
                        MCPTraceBuilder(retain_events=False, limits=self.session_limits),
                        DetectorEngine(default_detectors(patterns)),
                        pii_patterns=patterns)
                    self._contexts[context.epoch] = context
            if context is not None:
                context.active += 1
        for victim in victims:
            HTTPLease(self, victim, method, None).loss('http_invalid_credentials')
            if not victim.active:
                cleanup.append(victim)
        self._close_idle(cleanup)
        lease = HTTPLease(self, context, method, diagnostic,
                          provisional=method == 'POST' and token is None and diagnostic is None)
        if context is not None:
            if diagnostic:
                lease.loss(diagnostic)
            if cursor_error:
                lease.loss('http_invalid_resume')
            elif cursor:
                with context.lock:
                    retained = cursor in context.sse_ids
                if not retained:
                    self.reset(lease, 'http_resume_gap')
        elif diagnostic:
            self._emit(Observation(None, None, diagnostic=diagnostic))
        return lease

    def resume_verifiable(self, headers) -> bool:
        """True when a request's Last-Event-ID names an event this proxy
        delivered on the session it claims. Read-only: it never creates,
        retires or resets an epoch, so a gate can refuse an unverifiable
        resume instead of letting it reset the session's analysis."""
        headers = list(headers.items()) if hasattr(headers, 'items') else list(headers)
        limit = self.limits.max_identifier_chars
        token, token_error = _single(headers, 'mcp-session-id', limit)
        cursor, cursor_error = _single(headers, 'last-event-id', limit)
        if token is None or cursor is None or token_error or cursor_error:
            return False
        partition = self._partition(headers)
        with self._lock:
            context = self._bindings.get((partition, token))
        if context is None or context.retired or context.lost:
            return False
        with context.lock:
            return cursor in context.sse_ids

    def pattern_snapshot(self, epoch):
        """The frozen PII pattern tuple of a live epoch, or None if unknown.

        Decision recording reads this to describe the configuration profile a
        replay must match; it never mutates the registry to obtain it.
        """
        with self._lock:
            context = self._contexts.get(epoch)
            return context.pii_patterns if context is not None else None

    def _bind(self, lease, token):
        context = lease.context
        with self._lock:
            if context.retired or self._closed:
                return []
            key = (context.partition, token)
            prior = self._bindings.get(key)
            if prior is not None and prior is not context:
                self._retire_locked(prior); self._retire_locked(context)
                return [prior, context]
            context.key = key
            self._bindings[key] = context
        return []

    def reset(self, lease, reason='http_reset'):
        if reason not in ('http_reset', 'http_resume_gap', 'http_session_deleted', 'http_session_expired'):
            raise ValueError('unknown HTTP reset code')
        context = lease.context
        if context is None:
            return
        with self._lock:
            self._retire_locked(context)
        lease.loss(reason)

    def _emit(self, observation):
        if self.on_observation is not None:
            try:
                self.on_observation(observation)
            except Exception:
                pass
        return observation

    def close(self):
        with self._lock:
            self._closed = True
            contexts = list(self._contexts.values())
            for context in contexts:
                self._retire_locked(context)
        # Active requests own their logs until release; shutdown never closes
        # a file beneath a recording lease.
        self._close_idle(c for c in contexts if not c.active)


class HTTPLease:
    """Request-scoped routing handle. release is idempotent; disconnect is not cancellation."""
    def __init__(self, observer, context, method, diagnostic, provisional=False):
        self.observer, self.context, self.method = observer, context, method
        self.exchange = None
        self.diagnostic = diagnostic
        self.provisional = provisional
        self._released = False
        self._status = 0
        self._proposed = None
        self._initialize_id = None

    def response(self, status, headers):
        self._status = status
        if self.context is not None and self.context.shared:
            # A stateless scope has no session to bind, expire or delete; in
            # 2026 a 404 means method-not-found and any Mcp-Session-Id a
            # server mints is meaningless (the spec says ignore it).
            return
        self._proposed, error = _single(headers, 'mcp-session-id', self.observer.limits.max_identifier_chars)
        if error:
            self.loss('http_invalid_identity')
        elif (self.context is not None and self.context.key is not None
              and self._proposed is not None and self._proposed != self.context.key[1]):
            self.loss('http_identity_changed')
        if status == 404:
            self.observer.reset(self, 'http_session_expired')
        elif self.method == 'DELETE' and 200 <= status < 300:
            self.observer.reset(self, 'http_session_deleted')

    def _record_locked(self, direction, payload, *, metadata=None, observation=None, wire_bytes=None):
        context = self.context
        if not context.log_opened:
            context.log_opened = True
            context.log = open_session_log(self.observer.log_dir / f'{context.epoch}.jsonl')
        context.seq += 1
        facts = dict(observation or {}, epoch=context.epoch, order=context.seq)
        receipt = context.log.record(direction, payload, metadata=metadata,
            observation=facts, wire_bytes=payload if wire_bytes is None else wire_bytes,
            sequence=context.seq) if context.log is not None else None
        # Failed logging never pretends to provide persisted linkage. Feed the
        # same envelope locally so observation can continue without persistence.
        if receipt is None:
            try:
                frame = json.loads(payload.decode('utf-8', errors='replace').rstrip('\r\n'))
            except (ValueError, RecursionError, UnicodeError):
                frame = None
            # Stamp the wire clock too: declaration freshness (ttlMs) is
            # measured on it, and a disk failure must not retire a surface.
            entry = {'seq': context.seq, 'ts': _now_iso(), 'dir': direction, 'frame': frame,
                     'raw': payload.decode('utf-8', errors='replace'), 'http_observation': facts}
        else:
            entry = receipt
        event = context.builder.feed(entry)
        annotations = tuple(context.engine.on_event(event, context.builder.state)) if event else ()
        # A context that could not be trusted from the start (unproven scope,
        # missing or unknown identity) says so on every observation, so the
        # decision journal names the reason rather than a generic gap.
        inherited = self.diagnostic if context.lost else None
        return Observation(context.epoch, context.seq, event, annotations, receipt is not None,
                           facts.get('loss') or inherited
                           or ('http_log_failed' if receipt is None else None))

    def _loss_locked(self, reason):
        """Return the first loss observation; callers emit outside context locks."""
        context = self.context
        if context.shared:
            # A fault in one caller's exchange stays with that exchange: the
            # scope's declaration and correlation are shared by every caller,
            # so it is neither reset nor marked lost. The exchange's own
            # request has no provable observation and therefore forwards.
            marker = {'skip': True, 'fault': reason}
            if self.exchange is not None:
                marker['exchange'] = self.exchange
            self._record_locked('s2c', b'', observation=marker)
            return Observation(context.epoch, None, diagnostic=reason)
        if context.lost:
            return Observation(context.epoch, None, diagnostic=reason)
        context.lost = True
        return self._record_locked('s2c', b'', observation={'loss': reason})

    def loss(self, reason):
        allowed = {'http_invalid_identity', 'http_unknown_identity', 'http_missing_identity',
                   'http_invalid_resume', 'http_reset', 'http_resume_gap', 'http_session_deleted',
                   'http_session_expired', 'http_identity_collision', 'http_sse_collision',
                   'http_invalid_sse_id', 'http_frame_incomplete', 'http_analysis_failed',
                   'http_stale_epoch', 'http_identity_changed', 'http_sse_history_full',
                   'http_invalid_credentials', 'http_unproven_scope'}
        if reason not in allowed:
            raise ValueError('unknown HTTP observation code')
        context = self.context
        if context is None or self._released:
            return Observation(None, None, diagnostic=reason)
        with context.lock:
            result = self._loss_locked(reason)
        return self.observer._emit(result)

    def record(self, direction, payload, *, event_id=None, metadata=None,
               incomplete=False, wire_bytes=None, transport_only=False):
        context = self.context
        if context is None or self._released:
            return self.observer._emit(Observation(None, None, diagnostic=self.diagnostic or 'http_stale_epoch'))
        victims, losses = [], []
        try:
            if context.retired and not context.lost:
                self.loss('http_stale_epoch')
            shared = context.shared
            if incomplete or len(payload) > self.observer.limits.max_frame_bytes:
                if not shared:
                    self.loss('http_frame_incomplete')
                incomplete = True
            payload = payload[:self.observer.limits.max_frame_bytes]
            if wire_bytes is not None:
                wire_bytes = wire_bytes[:self.observer.limits.max_frame_bytes]
            with context.lock:
                facts = {'skip': True} if transport_only else {}
                if self.exchange is not None:
                    facts['exchange'] = self.exchange
                if context.shared:
                    event_id = None   # 2026 streams are not resumable
                if event_id is not None:
                    if (not isinstance(event_id, str) or not event_id
                            or len(event_id) > self.observer.limits.max_identifier_chars
                            or any(ord(c) < 32 or ord(c) > 126 for c in event_id)):
                        losses.append(self._loss_locked('http_invalid_sse_id'))
                    else:
                        digest = hashlib.sha256(payload).digest()
                        previous = context.sse_ids.get(event_id)
                        if previous == digest:
                            facts['skip'] = True
                        elif previous is not None:
                            losses.append(self._loss_locked('http_sse_collision'))
                        elif not context.lost:
                            if len(context.sse_ids) >= self.observer.limits.max_sse_ids:
                                # Forgetting an ID could replay an old response
                                # against a newly reused JSON-RPC request ID.
                                losses.append(self._loss_locked('http_sse_history_full'))
                            else:
                                context.sse_ids[event_id] = digest
                frame = _rpc_frame(payload)
                if (direction == 'c2s' and self.method != 'POST') or (
                        direction == 's2c' and not shared and (self.method == 'DELETE'
                        or (self._status and not 200 <= self._status < 300))):
                    frame = None
                if not incomplete and not facts.get('skip') and not isinstance(frame, dict):
                    if shared:
                        # One unreadable exchange must not reset a scope other
                        # callers depend on: record it uninterpreted. A listing
                        # it belonged to never completes, so the last complete
                        # declaration stays authority.
                        facts['uninterpreted'] = True
                    else:
                        losses.append(self._loss_locked('http_frame_incomplete'))
                if shared and incomplete:
                    facts['uninterpreted'] = True
                if context.lost or context.retired:
                    # Preserve wire, but never let an untrusted/old epoch regain
                    # exclusion through a late or uncorrelated declaration.
                    facts['uninterpreted'] = True
                if incomplete:
                    facts['incomplete'] = True
                result = self._record_locked(direction, payload, metadata=metadata,
                                             observation=facts, wire_bytes=wire_bytes)
                if not context.lost and isinstance(frame, dict):
                    rid = frame.get('id')
                    if (direction == 'c2s' and self.provisional and frame.get('method') == 'initialize'
                            and context.builder._valid_id(rid)):
                        self._initialize_id = (type(rid), rid)
                    value = frame.get('result')
                    if (direction == 's2c' and self.provisional and self._proposed
                            and 200 <= self._status < 300 and self._initialize_id == (type(rid), rid)
                            and result.event is not None
                            and result.event.metadata.get('method_replied_to') == '<initialize>'
                            and frame.get('jsonrpc') == '2.0' and 'error' not in frame
                            and isinstance(value, dict) and isinstance(value.get('protocolVersion'), str)
                            and bool(value['protocolVersion']) and isinstance(value.get('capabilities'), dict)
                            and isinstance(value.get('serverInfo'), dict)
                            and isinstance(value['serverInfo'].get('name'), str)
                            and isinstance(value['serverInfo'].get('version'), str)):
                        victims = self.observer._bind(self, self._proposed)
                        self.provisional = False
            for victim in victims:
                HTTPLease(self.observer, victim, self.method, None).loss('http_identity_collision')
                if not victim.active:
                    self.observer._close_idle([victim])
            for loss in losses:
                self.observer._emit(loss)
            return self.observer._emit(result)
        except Exception:
            try:
                self.loss('http_analysis_failed')
            except Exception:
                pass
            return self.observer._emit(Observation(context.epoch, None, diagnostic='http_analysis_failed'))

    def release(self):
        context = self.context
        if (context is not None and context.shared and self.exchange is not None
                and not self._released):
            # A 2026 reply only ever arrives on its own POST, so when the POST
            # ends its unanswered requests can never be answered. Purge them,
            # via a logged marker so a replay purges at the same point.
            try:
                with context.lock:
                    self._record_locked('s2c', b'', observation={
                        'skip': True, 'exchange': self.exchange, 'exchange_end': True})
            except Exception:
                pass
        with self.observer._lock:
            if self._released:
                return
            self._released = True
            if context is None:
                return
            context.active -= 1
            context.last_used = self.observer.clock()
            if context.key is None:
                self.observer._retire_locked(context)
            close = context.retired and not context.active
            if close:
                self.observer._contexts.pop(context.epoch, None)
        if close:
            self.observer._close_idle([context])
