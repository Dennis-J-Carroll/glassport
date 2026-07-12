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

RUBRIC_VERSION = "0.3"          # v0.3: capability-note tier (0 weight)
MAX_FILE_BYTES = 1_000_000

SOURCE_EXTS = {".py", ".js", ".ts", ".mjs", ".cjs"}
SKIP_DIRS = {"node_modules", ".git", "__pycache__", "venv", ".venv",
             "dist", "build", ".tox", ".mypy_cache", ".pytest_cache"}

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

POISON_PATTERNS = [
    re.compile(r"(?i)ignore\s+(all\s+|any\s+)?(previous|prior|above|"
               r"earlier)\s+(instructions|messages|directives|context)"),
    re.compile(r"(?i)<\s*important\s*>"),
    re.compile(r"(?i)do\s+not\s+(tell|inform|mention|reveal|alert|"
               r"notify)\b[^.\n]{0,60}\b(user|human)"),
    re.compile(r"(?i)\b(read|cat|open)\b[^.\n]{0,60}"
               r"(\.ssh|id_rsa|\.env\b|credentials|api[_ ]?keys?)"),
    re.compile(r"(?i)\b(send|upload|post|forward|exfiltrate)\b[^.\n]{0,60}"
               r"(\.ssh|id_rsa|\.env\b|credentials|api[_ ]?keys?|"
               r"conversation|system prompt)"),
    re.compile(r"(?i)reveal\s+the\s+system\s+prompt"),
    re.compile(r"(?i)instead\s+of\s+(telling|showing|asking)\s+the\s+user"),
]

# zero-width (200B-200F, 2060-2064, FEFF) and bidi controls (202A-202E,
# 2066-2069) — escaped, not literal, so the audit never flags itself
HIDDEN_UNICODE = re.compile(
    "[\\u200b-\\u200f\\u2060-\\u2064\\u202a-\\u202e\\u2066-\\u2069\\ufeff]")

NPX_AUTO_INSTALL = re.compile(r"\bnpx\s+(-y|--yes)\b")


def _strip_invisible(text: str) -> tuple[str, list[int]]:
    """Return (text without invisible/bidi chars, index_map) where
    index_map[i] is the position of stripped char i in the original.

    A poisoning directive with a zero-width joiner between every letter
    matches no raw pattern, yet a model reads it whole. We scan the
    stripped view but map matches back so the reported line is exact.
    Deletion-only, so the map is a clean one-to-one."""
    kept: list[str] = []
    index_map: list[int] = []
    for i, ch in enumerate(text):
        if HIDDEN_UNICODE.match(ch):
            continue
        kept.append(ch)
        index_map.append(i)
    return "".join(kept), index_map

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

NET_MODULES = {"socket", "urllib", "http", "requests", "aiohttp", "httpx",
               "ftplib", "smtplib", "websockets"}


def _line_of(text: str, pos: int) -> int:
    return text.count("\n", 0, pos) + 1


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
            if n.name.split(".")[0] in NET_MODULES:
                self.hits.append(("net-egress", node.lineno,
                                  f"imports {n.name}"))
        self.generic_visit(node)

    def visit_ImportFrom(self, node: ast.ImportFrom) -> None:
        mod = node.module or ""
        for n in node.names:
            self.aliases[n.asname or n.name] = f"{mod}.{n.name}"
        if mod.split(".")[0] in NET_MODULES:
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
            hits.append({"rule": "secret-hardcoded", "path": rel,
                         "line": _line_of(text, m.start()),
                         "detail": f"{label}: '{secret[:4]}…(redacted)'"})
    # poison patterns run on the invisible-stripped view (so a directive
    # split with zero-width chars is caught), then positions map back to
    # the original text for an exact line number
    stripped, index_map = _strip_invisible(text)
    seen_poison: set[tuple[int, str]] = set()
    for rx in POISON_PATTERNS:
        for m in rx.finditer(stripped):
            orig_start = index_map[m.start()] if m.start() < len(index_map) \
                else len(text)
            line = _line_of(text, orig_start)
            key = (line, m.group(0))
            if key in seen_poison:
                continue
            seen_poison.add(key)
            hits.append({"rule": "tool-poisoning", "path": rel,
                         "line": line,
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
        dirnames[:] = sorted(d for d in dirnames if d not in SKIP_DIRS)
        base = Path(dirpath)
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
def audit_path(path: str | Path) -> Report:
    root = Path(path).expanduser().resolve()
    base = root if root.is_dir() else root.parent

    raw_hits: list[dict] = []
    meta: dict = {"package_name": "", "version": "", "dependency_count": 0}
    n_py = n_js = n_files = 0
    depth = {"ast": 0, "pattern": 0}

    for p in _iter_source_files(root):
        try:
            if p.stat().st_size > MAX_FILE_BYTES:
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

    # aggregate: one Finding per (rule, file); one deduction per rule
    grouped: dict[tuple[str, str], Finding] = {}
    for h in raw_hits:
        rule = RULES_BY_ID[h["rule"]]
        key = (h["rule"], h["path"])
        if key in grouped:
            grouped[key].count += 1
        else:
            grouped[key] = Finding(
                rule=rule.id,
                severity=h.get("severity", rule.severity),
                path=h["path"], line=h["line"], detail=h["detail"],
                fix=rule.fix)
    order = {"critical": 0, "high": 1, "medium": 2, "low": 3,
             "note": 4, "info": 5}
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
    return Report(profile=profile, findings=findings,
                  deductions=deductions, score=score, grade=grade)


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
           if p['package_name'] else ""),
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
