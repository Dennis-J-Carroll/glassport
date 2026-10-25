"""
InteractionTrace — protocol-spanning data model for agent observability.
(Transcribed from Dennis J. Carroll's v0 schema. Status: v0.)

PLAY-BY-PLAY
------------
Everything glassport computes is computed over this shape. Read it in
the order the classes appear:

1. The enums are the closed vocabulary: who acted, what kind of part,
   what kind of event, what kind of finding. All are `str` enums, so a
   trace serializes to plain JSON with no custom encoder and a reader
   never has to decode an integer.
2. `Actor` is a participant, `Part` is one atom of payload, `Event` is
   one thing that happened, `Annotation` is one finding about an event.
3. `InteractionTrace` is the whole session: actors, events, findings.
4. `tool_declaration()` answers "did this event carry a usable tool
   list?" for one event.

Most of the difficulty in this file is not storage, it is a
three-valued question that shows up everywhere: is the server's
declared tool surface *known*, *known to be empty*, or *unknown*? The
type is Optional[set[str]]: None means unknown, set() means explicitly
empty, a populated set means known. Collapsing unknown into empty is
the mistake this model exists to prevent, because it would turn
"nobody told us" into "the server offers nothing".

WHAT THIS FILE DOES NOT DO
--------------------------
It does not parse wire formats, read files, or decide anything. The
tap adapter fills it in; detectors and reports read it. Nothing here
judges whether an event was good or bad.
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import json
import uuid


# PLAY: `str, Enum` rather than `StrEnum` (3.11+) keeps the package
# importable on 3.10, which is the declared floor. The str base is what
# makes json.dumps(asdict(trace)) work without a default= hook.
class ProtocolKind(str, Enum):
    USER_AGENT = "user_agent"
    AGENT_TOOL = "agent_tool"
    AGENT_AGENT = "agent_agent"
    HYBRID = "hybrid"


class ActorKind(str, Enum):
    USER = "user"
    AGENT = "agent"
    TOOL = "tool"
    EXTERNAL = "external"


class PartKind(str, Enum):
    TEXT = "text"
    JSON = "json"
    FILE = "file"
    TOOL_USE = "tool_use"
    TOOL_RESULT = "tool_result"
    REASONING = "reasoning"
    ARTIFACT = "artifact"
    ERROR = "error"


class EventKind(str, Enum):
    MESSAGE = "message"
    TOOL_CALL = "tool_call"
    TOOL_RESULT = "tool_result"
    STATE_CHANGE = "state_change"
    DELEGATION = "delegation"
    ARTIFACT = "artifact"


class TaskState(str, Enum):
    SUBMITTED = "submitted"
    WORKING = "working"
    INPUT_REQUIRED = "input-required"
    COMPLETED = "completed"
    CANCELED = "canceled"
    REJECTED = "rejected"
    FAILED = "failed"


class AnnotationKind(str, Enum):
    HALLUCINATION = "hallucination"
    DIVERGENCE = "divergence"
    ANOMALY = "anomaly"
    INFO = "info"


class HallucinationCategory(str, Enum):
    PLANNING = "planning"
    RETRIEVAL = "retrieval"
    REASONING = "reasoning"
    HUMAN_INTERACTION = "human_interaction"
    TOOL_USE = "tool_use"


def _now_iso() -> str:
    return datetime.now(timezone.utc).isoformat()


def _new_id(prefix: str = "id") -> str:
    # PLAY: 12 hex characters, not a full UUID. Ids land in every log
    # line and every report row; the prefix says what it names and the
    # short hex is long enough that a collision inside one session is
    # not a practical concern.
    return f"{prefix}_{uuid.uuid4().hex[:12]}"


@dataclass
class Actor:
    id: str
    kind: ActorKind
    name: str
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def user(cls, name: str = "user", **md) -> "Actor":
        return cls(id=_new_id("user"), kind=ActorKind.USER, name=name, metadata=md)

    # PLAY: The three constructors exist so callers cannot forget the
    # kind or the id prefix. `agent_card` and `tool_def` are only stored
    # when supplied, so "no card" stays distinguishable from "an empty
    # card" -- the same distinction the surface logic depends on.
    @classmethod
    def agent(cls, name: str, agent_card: Optional[dict] = None, **md) -> "Actor":
        meta = {**md, "agent_card": agent_card} if agent_card else dict(md)
        return cls(id=_new_id("agent"), kind=ActorKind.AGENT, name=name, metadata=meta)

    @classmethod
    def tool(cls, name: str, tool_def: Optional[dict] = None, **md) -> "Actor":
        meta = {**md, "tool_def": tool_def} if tool_def else dict(md)
        return cls(id=_new_id("tool"), kind=ActorKind.TOOL, name=name, metadata=meta)


@dataclass
class Part:
    kind: PartKind
    content: Any
    metadata: dict[str, Any] = field(default_factory=dict)


@dataclass
class Event:
    id: str
    timestamp: str
    actor_id: str
    kind: EventKind
    parts: list[Part]
    target_id: Optional[str] = None
    parent_event_id: Optional[str] = None
    context_id: Optional[str] = None
    task_id: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    @classmethod
    def message(cls, actor_id: str, text: str, **kw) -> "Event":
        return cls(id=_new_id("evt"), timestamp=_now_iso(), actor_id=actor_id,
                   kind=EventKind.MESSAGE,
                   parts=[Part(kind=PartKind.TEXT, content=text)], **kw)

    @classmethod
    def tool_call(cls, actor_id: str, tool_name: str, arguments: dict,
                  tool_use_id: Optional[str] = None, **kw) -> "Event":
        tuid = tool_use_id or _new_id("tu")
        return cls(id=_new_id("evt"), timestamp=_now_iso(), actor_id=actor_id,
                   kind=EventKind.TOOL_CALL,
                   parts=[Part(kind=PartKind.TOOL_USE,
                               content={"name": tool_name, "arguments": arguments,
                                        "tool_use_id": tuid})], **kw)

    @classmethod
    def tool_result(cls, actor_id: str, tool_use_id: str, output: Any,
                    is_error: bool = False, **kw) -> "Event":
        return cls(id=_new_id("evt"), timestamp=_now_iso(), actor_id=actor_id,
                   kind=EventKind.TOOL_RESULT,
                   parts=[Part(kind=PartKind.TOOL_RESULT,
                               content={"tool_use_id": tool_use_id, "output": output,
                                        "is_error": is_error})], **kw)


@dataclass
class Annotation:
    id: str
    event_id: str
    # PLAY: severity defaults to 1, not 0, so a finding that forgot to
    # set it still participates in warnings. Defaulting to 0 would make
    # an oversight look like "informational" and hide it. INFO is the
    # separate kind for genuinely informational records.
    kind: AnnotationKind
    category: Optional[HallucinationCategory] = None
    subcategory: Optional[str] = None
    severity: int = 1
    explanation: str = ""
    annotator: str = "human"
    metadata: dict[str, Any] = field(default_factory=dict)


def tool_declaration(event: Event) -> Optional[list[dict]]:
    """A usable, correlated tools/list result; None is unknown, [] is known.

    A malformed member invalidates the declaration, rather than silently
    turning a partially parsed surface into evidence of exclusion.
    """
    # PLAY: Correlation first. A tools/list-shaped payload that is not a
    # reply to a tools/list request proves nothing about this server's
    # surface, so it is unknown (None), not empty.
    if event.metadata.get("method_replied_to") != "<tools/list>":
        return None
    for part in event.parts:
        frame = part.content
        # PLAY: Error replies and non-JSON parts are skipped rather than
        # treated as an empty surface. A failed listing tells us nothing.
        if part.kind != PartKind.JSON or not isinstance(frame, dict) or "error" in frame:
            continue
        result = frame.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
        # PLAY: Every member must have a usable name, or the whole
        # declaration is rejected. Accepting the well-formed half would
        # turn a partially parsed surface into evidence that the missing
        # tools are excluded, which is the exact inference the doctrine
        # forbids.
        if isinstance(tools, list) and all(
            isinstance(t, dict) and isinstance(t.get("name"), str) and t["name"]
            for t in tools
        ):
            return tools
    return None


@dataclass
class InteractionTrace:
    id: str
    protocol: ProtocolKind
    actors: list[Actor]
    events: list[Event]
    annotations: list[Annotation] = field(default_factory=list)
    final_state: Optional[TaskState] = None
    intent: Optional[str] = None
    metadata: dict[str, Any] = field(default_factory=dict)

    def actor(self, actor_id: str) -> Optional[Actor]:
        return next((a for a in self.actors if a.id == actor_id), None)

    def declared_tools(self) -> set[str]:
        """Current names for collection consumers; use declared_surface() for knowledge."""
        # PLAY: This convenience is deliberately lossy: unknown becomes
        # set(). Anything that draws a conclusion must call
        # declared_surface() instead, because the two cases are not the
        # same question and only one of them can be answered.
        surface = self.declared_surface()
        return surface if surface is not None else set()

    def _initial_surface(self) -> Optional[set[str]]:
        # MCP actor metadata is a final snapshot, not prior knowledge. Replay
        # declarations from the evidence instead of applying future facts.
        # PLAY: This is the temporal-integrity rule. Actor metadata was
        # captured at the END of the session. Seeding the replay with it
        # would judge an early call against a list the server had not
        # sent yet, which is hindsight dressed up as evidence. For tap
        # traces the starting surface is therefore unknown, and only
        # observed declarations move it.
        if self.metadata.get("source") == "glassport_tap":
            return None
        names: set[str] = set()
        known = False
        for a in self.actors:
            if a.kind == ActorKind.AGENT:
                card = a.metadata.get("agent_card") or {}
                known |= isinstance(card.get("skills"), list)
                for skill in card.get("skills", []):
                    if "name" in skill:
                        names.add(skill["name"])
            if a.kind == ActorKind.TOOL:
                known = True
                names.add(a.name)
        return names if known else None

    def declared_surface(self) -> Optional[set[str]]:
        """None = unknown; set() = explicitly empty; nonempty = known names."""
        # PLAY: Imported inside the method because session imports this
        # module for its types. Module-scope here would be a cycle.
        from glassport.session import SessionState
        if self.metadata.get("history_retained") is False:
            surface = self.metadata.get("current_surface")
            return set(surface) if surface is not None else None
        state = SessionState.from_trace(self)
        for event in self.events:
            state.observe(event)
        return set(state.surface) if state.surface is not None else None

    def called_tools(self) -> list[tuple[str, str]]:
        out = []
        for e in self.events:
            if e.kind == EventKind.TOOL_CALL:
                for p in e.parts:
                    if p.kind == PartKind.TOOL_USE:
                        out.append((e.id, p.content["name"]))
        return out

    def fabricated_tool_calls(self) -> list[tuple[str, str]]:
        """Calls excluded by the declaration observed *at the time of the call*."""
        # PLAY: Fold then compare, inside the loop. The surface is
        # consulted after each event is observed, so a call is judged
        # against what had been declared before it -- not against the
        # final list, which may include a tool the server only added
        # afterwards.
        from glassport.session import SessionState
        state = SessionState.from_trace(self)
        out = []
        for event in self.events:
            state.observe(event)
            declared = state.surface
            if event.kind == EventKind.TOOL_CALL and declared is not None:
                for part in event.parts:
                    if part.kind == PartKind.TOOL_USE and part.content["name"] not in declared:
                        out.append((event.id, part.content["name"]))
        return out

    def to_json(self) -> str:
        # PLAY: asdict recurses through every dataclass; default=str keeps
        # an enum or a datetime from raising on the way out. Indented
        # because this output is meant to be read by a person.
        return json.dumps(asdict(self), indent=2, default=str)
