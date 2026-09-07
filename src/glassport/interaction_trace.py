"""
InteractionTrace — protocol-spanning data model for agent observability.
(Transcribed from Dennis J. Carroll's v0 schema. Status: v0.)
"""
from __future__ import annotations
from dataclasses import dataclass, field, asdict
from datetime import datetime, timezone
from enum import Enum
from typing import Any, Optional
import json
import uuid


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
    if event.metadata.get("method_replied_to") != "<tools/list>":
        return None
    for part in event.parts:
        frame = part.content
        if part.kind != PartKind.JSON or not isinstance(frame, dict) or "error" in frame:
            continue
        result = frame.get("result")
        tools = result.get("tools") if isinstance(result, dict) else None
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
        surface = self.declared_surface()
        return surface if surface is not None else set()

    def _initial_surface(self) -> Optional[set[str]]:
        # MCP actor metadata is a final snapshot, not prior knowledge. Replay
        # declarations from the evidence instead of applying future facts.
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
        return json.dumps(asdict(self), indent=2, default=str)
