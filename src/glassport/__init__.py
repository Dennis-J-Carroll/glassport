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

PLAY-BY-PLAY
------------
`import glassport` is not a neutral act in this package: the tap imports
it for `__version__`, and the tap sits between an agent and its server,
so every millisecond spent importing is a millisecond the wrapped server
starts later. That single constraint explains this whole file.

Each public symbol is therefore declared three times, for three
readers who need it in three different forms:

1. `__all__` — what a wildcard import and the docs consider public.
2. The `TYPE_CHECKING` block — type checkers and IDEs resolve real
   modules here. It never executes, so it costs nothing at runtime.
3. `_LAZY` — the runtime map PEP 562 consults, module path plus
   attribute name, imported only on first access.

Untouched by design: `__version__` is set eagerly, because the tap
reads it immediately and there is nothing to save.

WHAT THIS FILE DOES NOT DO
--------------------------
It does not import the detector engine, the audit module, or the
trace model at import time, and it adds no convenience wrappers. If an
addition here is not a lazy re-export, it belongs in a real submodule.
"""
from __future__ import annotations

from typing import TYPE_CHECKING

__version__ = "0.7.1"

__all__ = [
    "InteractionTrace",
    "from_mcp_session_file",
    "annotate",
    "audit_path",
    "__version__",
]

# PLAY: A false branch at runtime, a real import to a type checker.
# This is the only place the four heavy modules are named together, which
# is why it doubles as the map of the public surface.
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
    # PLAY: PEP 562 calls this only when normal attribute lookup fails,
    # so it runs once per symbol per process and then the real module
    # stays cached in sys.modules.
    try:
        module, attr = _LAZY[name]
    except KeyError:
        # PLAY: `from None` drops the KeyError context so the caller
        # sees a clean AttributeError with a useful name in it, which is
        # what hasattr() and getattr(default) expect to catch.
        raise AttributeError(
            f"module {__name__!r} has no attribute {name!r}") from None
    import importlib
    return getattr(importlib.import_module(module), attr)


def __dir__() -> list[str]:
    # PLAY: Without this, dir() and tab-completion would miss every lazy
    # name, because module __dict__ really does not contain them.
    return sorted(set(globals()) | set(_LAZY))
