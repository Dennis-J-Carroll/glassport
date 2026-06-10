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
        names: set[str] = set()
        for a in self.actors:
            if a.kind == ActorKind.AGENT:
                card = a.metadata.get("agent_card") or {}
                for skill in card.get("skills", []):
                    if "name" in skill:
                        names.add(skill["name"])
            if a.kind == ActorKind.TOOL:
                names.add(a.name)
        return names

    def called_tools(self) -> list[tuple[str, str]]:
        out = []
        for e in self.events:
            if e.kind == EventKind.TOOL_CALL:
                for p in e.parts:
                    if p.kind == PartKind.TOOL_USE:
                        out.append((e.id, p.content["name"]))
        return out

    def fabricated_tool_calls(self) -> list[tuple[str, str]]:
        declared = self.declared_tools()
        return [(eid, name) for eid, name in self.called_tools()
                if name not in declared]

    def to_json(self) -> str:
        return json.dumps(asdict(self), indent=2, default=str)
