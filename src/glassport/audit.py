"""
audit.py — static pre-deployment audit of an MCP server's source.

The runtime tap watches what a server does; the audit reads what a
server *is* before you ever run it. Local-only by design: no registry
lookups, no network, no execution. Point it at a file or a checkout and
every claim in the result traces to a rule id and a file:line.

The score is not a vibe. It starts at 100 and loses a fixed, published
weight per rule that fired — each rule deducts once no matter how many
times it hit, so one noisy pattern can't zero a report on its own. The
full rubric ships in this file and prints with --rubric; an unexplained
trust score is the opacity this project exists to fight.

Python sources get a real AST pass (so `model_eval(x)` is not `eval`),
with a pattern fallback when the file doesn't parse. JavaScript and
TypeScript get pattern depth only, and the report says so.

What this can and cannot see: a static read catches embedded secrets,
dangerous capabilities, runtime installs, and model-directed text
planted in tool descriptions (tool poisoning). It cannot see what the
server does on the wire — that is the tap's job. The two compose:
audit before you install, wrap while you run, gate when trust runs out.

    python3 audit.py <path> [--json]
    python3 audit.py --rubric

Exit code 1 when any critical or high finding is present.
"""
from __future__ import annotations

import ast
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path

from glassport import detectors, provenance
from glassport.poison_patterns import POISON_PATTERNS, HIDDEN_UNICODE, _strip_invisible

RUBRIC_VERSION = "0.4"          # v0.3: capability-note tier (0 weight)
                                # v0.4: tool-poisoning severity by context;
                                #       shipped dist/ scanned; root identity
MAX_FILE_BYTES = 1_000_000
# A published package's main bundle is routinely over 1 MB (server-pdf
# ships a 1.9 MB index.js) and it IS the code, so files under an un-skipped
# shipped dir get a higher cap. Every pattern is bounded, so cost is linear.
MAX_SHIPPED_FILE_BYTES = 16_000_000

SOURCE_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv",
             "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}
# Build-output dirs are noise in a source checkout but ARE the code in a
# published npm package. A package.json whose entry points (main, bin,
# exports, files, ...) lead into one of these un-skips it for that
# directory. node_modules and friends are never un-skipped.
SHIPPABLE_DIRS = {"dist", "build"}

# "note" is a zero-weight tier for capability findings that the rules
# themselves call non-violations: they are surfaced in the report but do
# not deduct, because the *dangerous* form of each has its own scored
# rule (cmd-exec ↔ shell-injection, fs-write ↔ fs-delete). Scoring the
# mere presence of a capability would penalize honest declaration and
# reward hiding it — the opacity this tool exists to fight. "info" stays
# distinct: provenance notes (no-license), not capabilities.
WEIGHTS = {"critical": 25, "high": 15, "medium": 8, "low": 3,
           "note": 0, "info": 0}
GRADES = [(90, "A"), (80, "B"), (70, "C"), (60, "D")]


@dataclass(frozen=True)
class Rule:
    id: str
    severity: str           # default severity; a finding may downgrade
    category: str
    title: str
    why: str
    fix: str


RULES = [
    Rule("secret-hardcoded", "critical", "secrets",
         "Hardcoded credential in source",
         "A committed key is already leaked: anyone who can read the "
         "package can use the credential.",
         "Move it to an environment variable or a secrets manager and "
         "rotate the exposed value."),
    Rule("tool-poisoning", "critical", "tool_poisoning",
         "Model-directed instructions embedded in source text",
         "Strings like 'ignore previous instructions' or '<IMPORTANT> "  # glassport: ignore[tool-poisoning]
         "read ~/.ssh' inside tool descriptions are instructions to the "  # glassport: ignore[tool-poisoning]
         "agent, not the user — the classic MCP tool-poisoning attack.",
         "Remove the directive. Tool descriptions should describe; any "
         "text steering the model away from the user is hostile."),
    Rule("unicode-hidden", "high", "tool_poisoning",
         "Invisible or bidirectional unicode in source",
         "Zero-width and bidi control characters hide text from human "
         "review while remaining visible to a model or parser.",
         "Strip the characters and diff what they were concealing."),
    Rule("exec-dynamic", "high", "supply_chain",
         "Dynamic code execution",
         "eval/exec/compile/__import__ (or new Function in JS) runs "
         "data as code and hides the dependency graph from review.",
         "Replace with explicit dispatch; if truly unavoidable, isolate "
         "and document the input source."),
    Rule("shell-injection", "high", "permissions",
         "Shell command construction",
         "shell=True, os.system, or execSync interpolating any variable "
         "is one quote away from arbitrary command execution.",
         "Use an argument list without a shell (subprocess.run([...]))."),
    Rule("runtime-install", "high", "supply_chain",
         "Installs packages at runtime",
         "npx -y / --yes fetches and executes whatever the registry "  # glassport: ignore[runtime-install]
         "serves at launch time, bypassing install review and pinning.",
         "Pin a version and install ahead of time; run the binary "
         "directly."),
    Rule("cmd-exec", "note", "permissions",
         "Spawns subprocesses",
         "Not a violation — a capability. Verify the server's declared "
         "purpose actually needs to run other programs. The dangerous "
         "form (shell=True / os.system) is scored separately as "
         "shell-injection.",
         "If the capability isn't needed, remove it; least privilege."),
    Rule("fs-delete", "medium", "permissions",
         "Deletes files or directory trees",
         "Capability note: rmtree/unlink in a tool server is worth a "
         "deliberate yes before deployment.",
         "Confine deletions to a declared workspace directory."),
    Rule("dep-surface", "medium", "supply_chain",
         "Large direct dependency surface",
         "Every direct dependency is a supply-chain trust decision; "
         "more than ~20 deserves an audit, more than ~50 a reason.",
         "Run npm audit / pip-audit and prune what isn't used."),
    Rule("fs-write", "note", "permissions",
         "Writes files",
         "Capability note only. The dangerous form (deleting files / "
         "trees) is scored separately as fs-delete.",
         "Confine writes to a declared workspace directory."),
    Rule("net-egress", "low", "permissions",
         "Talks to the network",
         "Capability note: sockets or HTTP clients mean data can leave "
         "the machine. Pair with the tap's host fingerprinting (watch).",
         "Confirm the egress destinations match the declared purpose."),
    Rule("tool-shadowing", "high", "tool_poisoning",
         "Tool name collision across MCP servers",
         "A tool name is declared identically by two or more MCP "
         "servers in this registry scan. The MCP spec scopes tool-name "
         "uniqueness to a single server and recommends prefixing with a "
         "server identifier when aggregating — an unprefixed collision "
         "lets a rogue server's tool silently shadow a trusted one.",
         "Prefix tool names with a stable server identifier, or remove/"
         "rename one of the colliding servers from the registry."),
    Rule("unbounded-schema", "medium", "tool_poisoning",
         "Tool schema allows unreviewed extra arguments",
         "A tool's inputSchema sets additionalProperties: true (or "
         "leaves it unset, equally permissive), allowing arbitrary "
         "extra arguments beyond the documented schema.",
         "Set additionalProperties: false and declare every argument "
         "the tool actually accepts."),
    Rule("no-license", "info", "provenance",
         "No license file in the checkout",
         "Not a risk by itself; reduces accountability and makes "
         "due diligence harder.",
         "Prefer servers with an explicit license for production."),
]
RULES_BY_ID = {r.id: r for r in RULES}


@dataclass
class Finding:
    rule: str
    severity: str
    path: str               # relative to the audited root
    line: int
    detail: str
    count: int = 1
    fix: str = ""


@dataclass
class Report:
    profile: dict
    findings: list[Finding]
    deductions: list[dict]
    score: int
    grade: str
    rubric_version: str = RUBRIC_VERSION
    # H2.03: opt-in network-enriched findings. Holds provenance.ProvenanceFinding.
    # Default audit_path() never populates it, so every existing render path
    # stays byte-identical. Untyped list to avoid an import cycle.
    provenance: list = field(default_factory=list)


# ─────────────────────────────────────────────────────────────────
# Pattern rules (all file kinds) — secrets, poisoning, hidden unicode
# ─────────────────────────────────────────────────────────────────
# (label, regex); the secret value is always the last capture group
SECRET_PATTERNS = [
    ("possible hardcoded API key/secret",
     re.compile(r'(?i)\b(api[_-]?key|apikey|secret|token|password|passwd)'
                r'\s*[=:]\s*["\']([A-Za-z0-9_\-]{16,})["\']')),
    ("OpenAI-style secret key", re.compile(r'\b(sk-[A-Za-z0-9]{32,})')),
    ("Slack bot token", re.compile(r'\b(xoxb-[A-Za-z0-9\-]{10,})')),
    ("GitHub personal access token",
     re.compile(r'\b(ghp_[A-Za-z0-9]{36})')),
    ("AWS access key ID", re.compile(r'\b(AKIA[0-9A-Z]{16})')),
    ("hardcoded Bearer token",
     re.compile(r'(?i)\bbearer\s+([A-Za-z0-9\-_.]{20,})')),
]

NPX_AUTO_INSTALL = re.compile(r"\bnpx\s+(-y|--yes)\b")

# JavaScript/TypeScript — pattern depth only, and the report says so
JS_PATTERNS = [
    ("exec-dynamic", re.compile(r"\beval\s*\(")),
    ("exec-dynamic", re.compile(r"\bnew\s+Function\s*\(")),
    ("shell-injection", re.compile(r"\bexecSync\s*\(")),
    ("cmd-exec", re.compile(r"\bchild_process\b")),
    ("fs-delete", re.compile(r"\b(unlinkSync|rmSync|rmdirSync)\s*\(")),
    ("net-egress", re.compile(r"\brequire\(\s*['\"]https?['\"]\s*\)|"
                              r"\b(axios|node-fetch|undici)\b")),
]

NET_MODULES = {"socket", "requests", "aiohttp", "httpx", "ftplib",
               "smtplib", "websockets"}
NET_SUBMODULES = {"urllib.request", "http.client", "http.server"}


def _network_module(name: str) -> bool:
    return (name.split(".")[0] in NET_MODULES
            or any(name == module or name.startswith(module + ".")
                   for module in NET_SUBMODULES))


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


# ─────────────────────────────────────────────────────────────────
# Tool-poisoning context. The rule's threat is text a *model* reads, so
# where a directive sits decides how much it matters:
#   comment lines            → note    (Python, exact tokenizer) / low
#                                       (JS, small lexer: never free)
#   catalog / test / error   → medium  (security tools must quote attacks,
#                                       but a renamed hostile file must not
#                                       become free, so it stays scored)
#   anywhere else            → critical (string literals, docstrings —
#                                       FastMCP turns docstrings into tool
#                                       descriptions)
# ─────────────────────────────────────────────────────────────────
_CATALOG_PATH = re.compile(
    r"(?i)(^|/)(tests?|__tests__|spec|fixtures?)/|"
    r"(^|/)test_[^/]*\.py$|\.(test|spec)\.[cm]?[jt]s$|"
    # security-tooling data files only — never bare "catalog" (a server's
    # tools/catalog.ts IS its tool descriptions) or "injection" (DI code)
    r"(^|/)[^/]*(prompt-?)?(injection|jailbreak|attack)[-_]?"
    r"(catalog|patterns?|corpus|signatures?|payloads?)[^/]*$|"
    r"(^|/)[^/]*(adversarial|red-?team|aidefen[cs]e)[^/]*$")
# A file that registers MCP tools is model-facing by definition: no path or
# error-string downgrade applies to it. Real detection catalogs are data
# files and never match this; a hostile tool file renamed to look like one
# does.
_TOOL_REGISTRATION = re.compile(
    r"\.tool\s*\(|\bregisterTool\b|\bsetRequestHandler\b|"
    r"\bListToolsRequestSchema\b|\binputSchema\b|@\w+\.tool\b|"
    r"\bFastMCP\b")
_ERROR_CONTEXT = re.compile(
    r"\bthrow\b|\bError\s*\(|\braise\b|\bconsole\.(error|warn|log)\b|"
    r"\blogger\.\w+\(|\blog\.(error|warn|info|debug)\(|\bmessage\s*:")

# characters after which a `/` starts a regex literal rather than division
_REGEX_PRECEDERS = set("(,=:[!&|?{};+-*%<>~^") | {""}


def _py_comment_lines(text: str) -> set[int]:
    """Whole-line comments from the real tokenizer, so a `#` line inside a
    docstring (a FastMCP tool description) is never mistaken for one. On any
    tokenize error, demote nothing — fail toward critical."""
    import io
    import tokenize
    out: set[int] = set()
    try:
        for tok in tokenize.generate_tokens(io.StringIO(text).readline):
            if tok.type == tokenize.COMMENT and \
                    not tok.line[:tok.start[1]].strip():
                out.add(tok.start[0])
    except (tokenize.TokenError, IndentationError, SyntaxError):
        return set()
    return out


def _js_comment_lines(text: str) -> set[int]:
    """Whole-line comments in JS/TS: a line that *begins* (after
    whitespace) outside any string, template literal or regex, with `//` or
    `/*`, plus the continuation lines of such a block comment. A lexer this
    small can be desynced by exotic input, which is why JS comment hits are
    demoted only to `low`, never made free."""
    out: set[int] = set()
    lines = text.splitlines()
    state = "code"        # code | sq | dq | tpl | block | regex
    block_from_line_start = False
    for n, line in enumerate(lines, 1):
        i, L = 0, len(line)
        first = len(line) - len(line.lstrip())
        if state == "block" and block_from_line_start:
            out.add(n)
        elif state == "code" and line.lstrip().startswith(("//", "/*")):
            out.add(n)
        prev = ""          # last significant code character on this line
        while i < L:
            c = line[i]
            nxt = line[i + 1] if i + 1 < L else ""
            if state == "code":
                if c == "/" and nxt == "/":
                    break
                if c == "/" and nxt == "*":
                    state, block_from_line_start = "block", i == first
                    i += 2
                    continue
                if c == "'":
                    state = "sq"
                elif c == '"':
                    state = "dq"
                elif c == "`":
                    state = "tpl"
                elif c == "/" and prev in _REGEX_PRECEDERS:
                    state = "regex"
                if not c.isspace():
                    prev = c
            elif state == "block":
                if c == "*" and nxt == "/":
                    state = "code"
                    i += 2
                    continue
            elif state in ("sq", "dq", "tpl", "regex"):
                if c == "\\":
                    i += 2
                    continue
                close = {"sq": "'", "dq": '"', "tpl": "`", "regex": "/"}[state]
                if c == close:
                    state, prev = "code", c
            i += 1
        if state in ("sq", "dq", "regex"):
            state = "code"     # these never span lines; resync
    return out


def _comment_lines(text: str, rel: str) -> set[int]:
    if rel.endswith(".py"):
        return _py_comment_lines(text)
    return _js_comment_lines(text)


def _poison_severity(line_text: str, line: int, rel: str,
                     comments: set[int], tool_file: bool = False) -> str:
    if line in comments:
        # Python comments come from the real tokenizer: free. JS comments
        # come from a small lexer an attacker could try to desync: scored.
        return "note" if rel.endswith(".py") else "low"
    if not tool_file and (_CATALOG_PATH.search(rel.replace("\\", "/")) or
                          _ERROR_CONTEXT.search(line_text)):
        return "medium"
    return "critical"


# Inline suppression: `# nosec` (bandit-compatible) or `# glassport:
# ignore` drops every finding on the line; `# glassport: ignore[rule-id,
# rule-id]` drops only the named rules. This is how the rule catalog —
# which must quote attack strings to document them — audits clean.
_SUPPRESS_RE = re.compile(
    r"#\s*(?:nosec\b|glassport:\s*ignore(?:\[([a-z0-9,_\- ]+)\])?)", re.I)


def _is_suppressed(lines: list[str], line: int, rule: str) -> bool:
    if not 1 <= line <= len(lines):
        return False
    m = _SUPPRESS_RE.search(lines[line - 1])
    if not m:
        return False
    scope = m.group(1)
    if scope is None:                       # bare marker → all rules
        return True
    return rule in {s.strip() for s in scope.split(",")}


def _drop_suppressed(hits: list[dict], text: str) -> list[dict]:
    lines = text.splitlines()
    return [h for h in hits
            if not _is_suppressed(lines, h["line"], h["rule"])]


# ─────────────────────────────────────────────────────────────────
# Python AST pass — calls resolved through import aliases, so that
# model_eval() is not eval() and `import subprocess as sp` still counts.
# ─────────────────────────────────────────────────────────────────
class _PyVisitor(ast.NodeVisitor):
    def __init__(self) -> None:
        self.aliases: dict[str, str] = {}
        self.hits: list[tuple[str, int, str]] = []   # (rule, line, detail)

    def visit_Import(self, node: ast.Import) -> None:
        for n in node.names:
            self.aliases[n.asname or n.name.split(".")[0]] = n.name
            if _network_module(n.name):
                self.hits.append(("net-egress", node.lineno,
                                  f"imports {n.name}"))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for n in node.names:
            self.aliases[n.asname or n.name] = f"{mod}.{n.name}"
        if (_network_module(mod) or any(_network_module(f"{mod}.{n.name}")
                                        for n in node.names)):
            self.hits.append(("net-egress", node.lineno,
                              f"imports from {mod}"))
        self.generic_visit(node)

    def _qualified(self, func: ast.expr) -> str:
        parts: list[str] = []
        node = func
        while isinstance(node, ast.Attribute):
            parts.append(node.attr)
            node = node.value
        if isinstance(node, ast.Name):
            parts.append(self.aliases.get(node.id, node.id))
        else:
            return ""
        return ".".join(reversed(parts))

    def visit_Call(self, node: ast.Call) -> None:
        q = self._qualified(node.func)

        if q in ("eval", "exec", "compile", "__import__"):
            self.hits.append(("exec-dynamic", node.lineno, f"{q}()"))
        elif q in ("os.system", "os.popen"):
            self.hits.append(("shell-injection", node.lineno, f"{q}()"))
        elif q.startswith("subprocess."):
            shell = any(
                kw.arg == "shell" and
                isinstance(kw.value, ast.Constant) and kw.value.value
                for kw in node.keywords)
            self.hits.append(("cmd-exec", node.lineno, f"{q}()"))
            if shell:
                self.hits.append(("shell-injection", node.lineno,
                                  f"{q}(shell=True)"))
        elif q in ("shutil.rmtree", "os.remove", "os.unlink", "os.rmdir",
                   "os.removedirs"):
            self.hits.append(("fs-delete", node.lineno, f"{q}()"))
        elif q == "open":
            mode = None
            if len(node.args) >= 2 and isinstance(node.args[1], ast.Constant):
                mode = node.args[1].value
            for kw in node.keywords:
                if kw.arg == "mode" and isinstance(kw.value, ast.Constant):
                    mode = kw.value.value
            if isinstance(mode, str) and any(c in mode for c in "wax"):
                self.hits.append(("fs-write", node.lineno,
                                  f"open(mode={mode!r})"))
        self.generic_visit(node)


# ─────────────────────────────────────────────────────────────────
# Scanners — each yields raw hit dicts; aggregation happens later.
# ─────────────────────────────────────────────────────────────────
def _scan_common(text: str, rel: str) -> list[dict]:
    """Secrets, tool poisoning, hidden unicode — every file kind."""
    hits = []
    for label, rx in SECRET_PATTERNS:
        for m in rx.finditer(text):
            secret = m.group(m.lastindex or 0)
            # same non-reversible tag as the runtime detectors: no prefix,
            # because a few characters are not recognizable as a secret and
            # so survive every downstream scrubber (text, JSON, SARIF)
            hits.append({"rule": "secret-hardcoded", "path": rel,
                         "line": _line_of(text, m.start()),
                         "detail": detectors._redact(secret, label)})
    # poison patterns run on the invisible-stripped view (so a directive
    # split with zero-width chars is caught), then positions map back to
    # the original text for an exact line number
    stripped, index_map = _strip_invisible(text)
    seen_poison: set[tuple[int, str]] = set()
    lines = text.splitlines()
    comments = _comment_lines(text, rel)
    tool_file = bool(_TOOL_REGISTRATION.search(stripped))
    for rx in POISON_PATTERNS:
        for m in rx.finditer(stripped):
            orig_start = index_map[m.start()] if m.start() < len(index_map) \
                else len(text)
            line = _line_of(text, orig_start)
            key = (line, m.group(0))
            if key in seen_poison:
                continue
            seen_poison.add(key)
            line_text = lines[line - 1] if line <= len(lines) else ""
            hits.append({"rule": "tool-poisoning", "path": rel,
                         "line": line,
                         "severity": _poison_severity(line_text, line, rel,
                                                      comments, tool_file),
                         "detail": f"directive text: {m.group(0)[:60]!r}"})
    m = HIDDEN_UNICODE.search(text)
    if m:
        n = len(HIDDEN_UNICODE.findall(text))
        hits.append({"rule": "unicode-hidden", "path": rel,
                     "line": _line_of(text, m.start()),
                     "detail": f"{n} invisible/bidi character(s), first is "
                               f"U+{ord(m.group(0)):04X}"})
    m = NPX_AUTO_INSTALL.search(text)
    if m:
        hits.append({"rule": "runtime-install", "path": rel,
                     "line": _line_of(text, m.start()),
                     "detail": "npx auto-install flag (-y/--yes)"})
    return _drop_suppressed(hits, text)


def _scan_python(text: str, rel: str) -> tuple[list[dict], str]:
    """AST pass; on a syntax error fall back to pattern depth."""
    try:
        tree = ast.parse(text)
    except SyntaxError:
        return [], "pattern"
    v = _PyVisitor()
    v.visit(tree)
    hits = [{"rule": r, "path": rel, "line": ln, "detail": d}
            for r, ln, d in v.hits]
    return _drop_suppressed(hits, text), "ast"


def _scan_js(text: str, rel: str) -> list[dict]:
    hits = []
    for rule, rx in JS_PATTERNS:
        for m in rx.finditer(text):
            hits.append({"rule": rule, "path": rel,
                         "line": _line_of(text, m.start()),
                         "detail": f"pattern match: {m.group(0)[:40]!r}"})
    return _drop_suppressed(hits, text)


def _scan_package_json(text: str, rel: str) -> tuple[list[dict], dict]:
    hits, meta = [], {}
    try:
        data = json.loads(text)
    except json.JSONDecodeError:
        return hits, meta
    meta["package_name"] = data.get("name", "")
    meta["version"] = data.get("version", "")
    deps = data.get("dependencies") or {}
    meta["dependency_count"] = len(deps)
    n = len(deps)
    if n > 20:
        hits.append({"rule": "dep-surface", "path": rel, "line": 1,
                     "severity": "medium" if n > 50 else "low",
                     "detail": f"{n} direct dependencies declared"})
    return hits, meta


def _entry_strings(value) -> list[str]:
    """Every path string in a package.json entry field (str, list, or the
    nested condition maps that `exports` and `bin` allow)."""
    if isinstance(value, str):
        return [value]
    if isinstance(value, list):
        return [s for v in value for s in _entry_strings(v)]
    if isinstance(value, dict):
        return [s for v in value.values() for s in _entry_strings(v)]
    return []


def _shipped_dirs(pkg_json: Path) -> set[str]:
    """SHIPPABLE_DIRS this package.json's entry points lead into."""
    if pkg_json.is_symlink():
        return set()
    try:
        data = json.loads(pkg_json.read_text(encoding="utf-8"))
    except (OSError, ValueError):
        return set()
    if not isinstance(data, dict):
        return set()
    out: set[str] = set()
    for key in ("main", "module", "browser", "bin", "exports", "files"):
        for s in _entry_strings(data.get(key)):
            first = s.replace("\\", "/").lstrip("./").split("/", 1)[0]
            if first in SHIPPABLE_DIRS:
                out.add(first)
    return out


def _iter_source_files(root: Path):
    """Yield source files lazily. os.walk with in-place pruning of
    SKIP_DIRS means vendored trees (node_modules, .git) are never
    descended into — the old sorted(rglob("*")) walked them in full and
    then discarded the results. Order is deterministic (sorted per
    directory) so the report is stable run to run."""
    if root.is_file():
        yield root
        return
    # followlinks=False keeps os.walk from descending through a directory
    # symlink that points outside the audited tree.
    for dirpath, dirnames, filenames in os.walk(root, followlinks=False):
        base = Path(dirpath)
        shipped = (_shipped_dirs(base / "package.json")
                   if "package.json" in filenames else set())
        dirnames[:] = sorted(d for d in dirnames
                             if d not in SKIP_DIRS or d in shipped)
        for name in sorted(filenames):
            if Path(name).suffix in SOURCE_EXTS or name == "package.json":
                p = base / name
                # never read through a file symlink — it could point at an
                # arbitrary host file outside the root the caller asked for
                if p.is_symlink():
                    continue
                yield p


# ─────────────────────────────────────────────────────────────────
# The audit
# ─────────────────────────────────────────────────────────────────
def _finalize_findings(raw_hits: list[dict]
                        ) -> tuple[list[Finding], list[dict], int, str]:
    """Group raw hits into Finding objects (one per rule+file), compute
    per-rule deductions, and derive score/grade. Shared by audit_path
    and audit_tool_registry so both use one scoring formula."""
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3,
             "note": 4, "info": 5}
    grouped: dict[tuple[str, str], Finding] = {}
    for h in raw_hits:
        rule = RULES_BY_ID[h["rule"]]
        key = (h["rule"], h["path"])
        if key in grouped:
            f = grouped[key]
            f.count += 1
            # the worst hit in a file speaks for it: an earlier, milder hit
            # (a comment) must not mask a real one further down
            sev = h.get("severity", rule.severity)
            if order[sev] < order[f.severity]:
                f.severity, f.line, f.detail = sev, h["line"], h["detail"]
        else:
            grouped[key] = Finding(
                rule=rule.id,
                severity=h.get("severity", rule.severity),
                path=h["path"], line=h["line"], detail=h["detail"],
                fix=rule.fix)
    findings = sorted(grouped.values(),
                      key=lambda f: (order[f.severity], f.rule, f.path))

    worst_by_rule: dict[str, str] = {}
    counts_by_rule: dict[str, int] = {}
    for f in findings:
        counts_by_rule[f.rule] = counts_by_rule.get(f.rule, 0) + f.count
        if f.rule not in worst_by_rule or \
                order[f.severity] < order[worst_by_rule[f.rule]]:
            worst_by_rule[f.rule] = f.severity
    deductions = [{"rule": r, "severity": s, "points": WEIGHTS[s],
                   "hits": counts_by_rule[r]}
                  for r, s in sorted(worst_by_rule.items(),
                                     key=lambda kv: -WEIGHTS[kv[1]])
                  if WEIGHTS[s] > 0]

    score = max(0, 100 - sum(d["points"] for d in deductions))
    grade = next((g for floor, g in GRADES if score >= floor), "F")
    return findings, deductions, score, grade


def audit_path(path: str | Path) -> Report:
    root = Path(path).expanduser().resolve()
    base = root if root.is_dir() else root.parent

    raw_hits: list[dict] = []
    meta: dict = {"package_name": "", "version": "", "dependency_count": 0}
    n_py = n_js = n_files = n_large = 0
    # identity comes from the shallowest package.json (the root), never from
    # a vendored or nested one that happens to be read later
    meta_depth = None
    depth = {"ast": 0, "pattern": 0}

    for p in _iter_source_files(root):
        try:
            # only un-skipped shipped dirs (dist/, build/) can appear in the
            # path, so a shipped-dir segment means "published bundle"
            shipped = any(part in SHIPPABLE_DIRS
                          for part in p.relative_to(base).parts[:-1])
            cap = MAX_SHIPPED_FILE_BYTES if shipped else MAX_FILE_BYTES
            if p.stat().st_size > cap:
                n_large += 1
                continue
            text = p.read_text(encoding="utf-8", errors="replace")
        except OSError:
            continue
        rel = str(p.relative_to(base))
        n_files += 1

        raw_hits.extend(_scan_common(text, rel))
        if p.suffix == ".py":
            n_py += 1
            hits, d = _scan_python(text, rel)
            raw_hits.extend(hits)
            depth[d] += 1
        elif p.suffix in SOURCE_EXTS:
            n_js += 1
            depth["pattern"] += 1
            raw_hits.extend(_scan_js(text, rel))
        elif p.name == "package.json":
            hits, m = _scan_package_json(text, rel)
            raw_hits.extend(hits)
            depth_here = len(Path(rel).parts)
            if meta_depth is None or depth_here < meta_depth:
                meta_depth = depth_here
                meta.update({k: v for k, v in m.items() if v})

    # pyproject dependency surface (best-effort, stdlib tomllib if present)
    pyproject = (root if root.is_dir() else base) / "pyproject.toml"
    if pyproject.is_file():
        try:
            import tomllib
            data = tomllib.loads(pyproject.read_text(encoding="utf-8"))
            deps = (data.get("project") or {}).get("dependencies") or []
            meta.setdefault("package_name",
                            (data.get("project") or {}).get("name", ""))
            if len(deps) > meta.get("dependency_count", 0):
                meta["dependency_count"] = len(deps)
            if len(deps) > 20:
                raw_hits.append({
                    "rule": "dep-surface", "path": "pyproject.toml",
                    "line": 1,
                    "severity": "medium" if len(deps) > 50 else "low",
                    "detail": f"{len(deps)} direct dependencies declared"})
        except Exception:
            pass

    if root.is_dir() and not list(root.glob("LICENSE*")) \
            and not list(root.glob("COPYING*")):
        raw_hits.append({"rule": "no-license", "path": ".", "line": 0,
                         "detail": "no LICENSE/COPYING file found"})

    findings, deductions, score, grade = _finalize_findings(raw_hits)

    runtime = ("mixed" if n_py and (n_js or meta["package_name"]) else
               "python" if n_py else
               "node" if n_js or meta["package_name"] else "unknown")
    profile = {
        "path": str(root),
        "runtime": runtime,
        "package_name": meta.get("package_name", ""),
        "version": meta.get("version", ""),
        "dependency_count": meta.get("dependency_count", 0),
        "files_scanned": n_files,
        "depth": depth,
    }
    if n_large:
        # only present when it happened, so clean reports stay byte-identical
        profile["files_skipped_large"] = n_large
    return Report(profile=profile, findings=findings,
                  deductions=deductions, score=score, grade=grade)


def audit_tool_registry(session_paths: list[Path]) -> Report:
    """Cross-server static audit: tool-name shadowing and unbounded
    schemas, read from a set of tap session logs (each log's declared
    tools/list surface IS the registry entry for that server)."""
    from glassport.adapters.mcp_session import from_mcp_session_file

    raw_hits: list[dict] = []
    seen_names: dict[str, str] = {}   # tool name -> first session path seen
    for path in session_paths:
        trace = from_mcp_session_file(path)
        server = next((a for a in trace.actors
                        if a.metadata.get("role") == "mcp_server"), None)
        if server is None:
            continue
        for t in server.metadata.get("tools") or []:
            if not isinstance(t, dict) or "name" not in t:
                continue
            name = t["name"]
            prior = seen_names.get(name)
            if prior is not None and prior != str(path):
                raw_hits.append({
                    "rule": "tool-shadowing", "path": str(path), "line": 0,
                    "severity": RULES_BY_ID["tool-shadowing"].severity,
                    "detail": f"tool '{name}' also declared by {prior}"})
            else:
                seen_names[name] = str(path)
            schema = t.get("inputSchema")
            if isinstance(schema, dict) and \
                    schema.get("additionalProperties", True) is True:
                raw_hits.append({
                    "rule": "unbounded-schema", "path": str(path), "line": 0,
                    "severity": RULES_BY_ID["unbounded-schema"].severity,
                    "detail": f"tool '{name}' schema allows "
                              f"additionalProperties"})

    findings, deductions, score, grade = _finalize_findings(raw_hits)
    profile = {"path": "<tool registry>", "runtime": "registry",
               "package_name": "", "version": "", "dependency_count": 0,
               "files_scanned": len(session_paths),
               "depth": {"ast": 0, "pattern": 0}}
    return Report(profile=profile, findings=findings, deductions=deductions,
                  score=score, grade=grade)


# ─────────────────────────────────────────────────────────────────
# Rendering
# ─────────────────────────────────────────────────────────────────
def render_text(report: Report) -> str:
    p = report.profile
    out = [
        f"glassport audit — {p['path']}",
        f"profile:  {p['runtime']} · {p['files_scanned']} file(s) scanned "
        f"(ast: {p['depth']['ast']}, pattern: {p['depth']['pattern']})"
        + (f" · package {p['package_name']} {p['version']}".rstrip()
           if p['package_name'] else "")
        + (f" · {p['files_skipped_large']} file(s) over the size cap, "
           f"NOT scanned"
           if p.get('files_skipped_large') else ""),
        f"score:    {report.score}/100 ({report.grade})"
        + ("" if report.deductions else " — no deductions"),
    ]
    for d in report.deductions:
        out.append(f"  -{d['points']:<3} {d['rule']} ({d['severity']}) — "
                   f"{d['hits']} hit(s)")
    if report.findings:
        out.append("findings:")
        for f in report.findings:
            where = f"{f.path}:{f.line}" if f.line else f.path
            mult = f" (×{f.count})" if f.count > 1 else ""
            out.append(f"  [{f.severity}] {f.rule} {where}{mult}")
            out.append(f"      {f.detail}")
            if f.fix and f.severity in ("critical", "high"):
                out.append(f"      fix: {f.fix}")
    else:
        out.append("findings: none")
    # H2.03: opt-in network-enriched findings, appended only when present so
    # the default (offline) audit stays byte-identical. These never affect the
    # score — they live in a separate channel below the scored findings.
    if report.provenance:
        # Provenance fields come from the audited (possibly hostile) manifest.
        # Display text (package/detail) is scrubbed with the shared
        # detectors.redact_display; STRUCTURAL fields (rule/ecosystem/severity)
        # are validated against the same closed sets sarif.py uses — never the
        # free-text scrub, which can hand a non-string value to a str-only
        # method (that gap crashed this renderer before this fix) — so an
        # unrecognized or non-string value collapses to a safe sentinel instead
        # of being emitted raw. Benign npm/PyPI values are unaffected.
        out.append("provenance (network-enriched):")
        for pf in report.provenance:
            pkg = detectors.redact_display(pf.package)
            eco = provenance.safe_ecosystem(pf.ecosystem)
            rule = provenance.safe_rule(pf.rule)
            severity = provenance.safe_severity(pf.severity)
            detail = detectors.redact_display(pf.detail)
            where = f" [{eco}:{pkg}]" if pkg else ""
            line1 = f"  [{severity}] {rule}{where}"
            line2 = f"      {detail}"
            # Backstop, mirroring sarif.py's composed-message re-scrub: two
            # individually-clean fields could in principle join into a
            # scannable credential shape across the fixed delimiter. A no-op
            # on already-clean text (redact_secrets_strict returns benign
            # input unchanged), so this never touches ordinary npm/PyPI output.
            block = detectors.redact_secrets_strict(f"{line1}\n{line2}")
            out.extend(block.split("\n"))
    out.append(f"rubric:   v{report.rubric_version} · score = 100 − Σ "
               f"weight(rule), each rule deducted once · --rubric for "
               f"the full table")
    return "\n".join(out)


def render_json(report: Report) -> str:
    obj = {
        "rubric_version": report.rubric_version,
        "profile": report.profile,
        "score": report.score,
        "grade": report.grade,
        "deductions": report.deductions,
        "findings": [vars(f) for f in report.findings],
    }
    # H2.03: add the key only when non-empty so the default audit's JSON is
    # byte-identical with and without --provenance. `vars(pf)` would emit the
    # attacker-controlled fields verbatim. STRUCTURAL fields (rule/ecosystem/
    # severity) are validated against the same closed sets sarif.py and
    # render_text use — never emitted raw, never fed to the free-text scrub
    # (which assumes a string and isn't a closed-set validator) — so an
    # unrecognized or non-string value collapses to a safe sentinel. Display
    # text (package/detail) is scrubbed with the shared detectors.redact_display;
    # manifest -> redact_secrets_strict. Same keys, so the JSON shape is
    # unchanged; benign values pass through unaltered.
    if report.provenance:
        obj["provenance"] = [{
            "rule": provenance.safe_rule(pf.rule),
            "severity": provenance.safe_severity(pf.severity),
            "ecosystem": provenance.safe_ecosystem(pf.ecosystem),
            "package": detectors.redact_display(pf.package),
            "manifest": detectors.redact_secrets_strict(pf.manifest),
            "detail": detectors.redact_display(pf.detail),
        } for pf in report.provenance]
    return json.dumps(obj, indent=2, ensure_ascii=False)


def render_rubric() -> str:
    out = [f"glassport audit rubric v{RUBRIC_VERSION}",
           "score = 100 − Σ weight(rule); each rule deducts once, "
           "however many times it fired.",
           ""]
    for r in RULES:
        out.append(f"{r.id}  [{r.severity}, -{WEIGHTS[r.severity]}]  "
                   f"({r.category})")
        out.append(f"    {r.title}")
        out.append(f"    why: {r.why}")
        out.append(f"    fix: {r.fix}")
        out.append("")
    return "\n".join(out)


def main(argv: list[str]) -> int:
    args = list(argv)
    if "--rubric" in args:
        print(render_rubric())
        return 0
    as_json = "--json" in args
    if as_json:
        args.remove("--json")
    as_sarif = "--sarif" in args
    if as_sarif:
        args.remove("--sarif")
    if "--registry" in args:
        idx = args.index("--registry")
        session_paths = [Path(p) for p in args[idx + 1:]]
        if not session_paths:
            print("usage: audit.py --registry <session1.jsonl> [session2.jsonl ...]",
                  file=sys.stderr)
            return 2
        report = audit_tool_registry(session_paths)
        if as_sarif:
            from glassport.sarif import render_sarif
            print(render_sarif(report))
        else:
            print(render_json(report) if as_json else render_text(report))
        return 1 if any(f.severity in ("critical", "high")
                        for f in report.findings) else 0
    # H2.03 opt-in network enrichment. Off by default; the core audit below is
    # unchanged and offline. --provenance-refresh / --provenance-cache imply it.
    provenance = "--provenance" in args
    if provenance:
        args.remove("--provenance")
    refresh = "--provenance-refresh" in args
    if refresh:
        args.remove("--provenance-refresh")
        provenance = True
    cache_dir = None
    if "--provenance-cache" in args:
        i = args.index("--provenance-cache")
        try:
            cache_dir = args[i + 1]
            del args[i:i + 2]
            provenance = True
        except IndexError:
            print("usage: audit.py <path> --provenance-cache <dir>",
                  file=sys.stderr)
            return 2
    if len(args) != 1 or args[0] in ("-h", "--help"):
        print("usage: audit.py <path> [--json|--sarif] | audit.py --rubric",
              file=sys.stderr)
        return 2
    target = Path(args[0]).expanduser()
    if not target.exists():
        print(f"[glassport] path not found: {target}", file=sys.stderr)
        return 2

    report = audit_path(target)
    if provenance:
        from glassport.provenance import enrich
        report.provenance = enrich(target, cache_dir=cache_dir,
                                   refresh=refresh)
    if as_sarif:
        from glassport.sarif import render_sarif
        # base = the path as given, so result URIs resolve from repo root
        base = args[0] if not Path(args[0]).is_absolute() else ""
        print(render_sarif(report, base=base))
    else:
        print(render_json(report) if as_json else render_text(report))
    return 1 if any(f.severity in ("critical", "high")
                    for f in report.findings) else 0


if __name__ == "__main__":
    sys.exit(main(sys.argv[1:]))
