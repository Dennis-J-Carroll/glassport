"""
Glassport — wire-level observability and enforcement for MCP servers.

    The glass before the port. Observe first. Enforce later.

A passive stdio tap, behavioral detectors, drift watch, and static
audit for Model Context Protocol servers. Zero dependencies, pure
stdlib, runs anywhere Python 3.10+ runs — including Termux.

Public API (typed; ships a py.typed marker):

    from glassport import InteractionTrace, from_mcp_session_file, \
        annotate, audit_path

Re-exports are lazy (PEP 562) so `import glassport` stays cheap for the
tap's hot startup path — the wrapped server's launch must not pay for
detector or audit imports it never uses.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

__version__ = "0.6.9"

__all__ = [
    "InteractionTrace",
    "from_mcp_session_file",
    "annotate",
    "audit_path",
    "__version__",
]

if TYPE_CHECKING:  # static analyzers see real symbols; runtime stays lazy
    from glassport.adapters.mcp_session import from_mcp_session_file
    from glassport.audit import audit_path
    from glassport.detectors import annotate
    from glassport.interaction_trace import InteractionTrace

_LAZY = {
    "InteractionTrace": ("glassport.interaction_trace", "InteractionTrace"),
    "from_mcp_session_file": ("glassport.adapters.mcp_session",
                              "from_mcp_session_file"),
    "annotate": ("glassport.detectors", "annotate"),
    "audit_path": ("glassport.audit", "audit_path"),
}


def __getattr__(name: str):
    try:
        module, attr = _LAZY[name]
    except KeyError:
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}") from None
    import importlib
    return getattr(importlib.import_module(module), attr)


def __dir__() -> list[str]:
    return sorted(set(globals()) | set(_LAZY))
