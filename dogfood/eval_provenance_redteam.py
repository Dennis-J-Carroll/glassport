# dogfood/eval_provenance_redteam.py
"""Provenance red-team grill.

Exercises the registry fetcher (`glassport.provenance.fetch_registry`) and the
pure evaluator for attacker-controlled bytes and network-level defects. All
network traffic is loopback-only; no external registry is contacted.

Run: PYTHONPATH=src python dogfood/eval_provenance_redteam.py
"""
from __future__ import annotations

import http.server
import json
import os
import socketserver
import sys
import threading
from datetime import datetime, timezone
from pathlib import Path

sys.path.insert(0, "src")
sys.path.insert(0, ".")
from glassport import provenance as prov
from glassport.provenance import Dep, Fetched, ProvenanceFinding, evaluate, fetch_registry

LOG_DIR = "dogfood/logs/provenance-redteam"
FINDINGS = "dogfood/findings/provenance-redteam.md"


def _free_port() -> int:
    with socketserver.TCPServer(("127.0.0.1", 0), http.server.BaseHTTPRequestHandler) as s:
        return s.server_address[1]


def _start_server(handler) -> tuple[socketserver.TCPServer, int, threading.Thread]:
    srv = socketserver.TCPServer(("127.0.0.1", 0), handler)
    port = srv.server_address[1]
    t = threading.Thread(target=srv.serve_forever, daemon=True)
    t.start()
    return srv, port, t


def _stop_server(srv: socketserver.TCPServer) -> None:
    srv.shutdown()
    srv.server_close()


# ---------------------------------------------------------------------------
# P1 — SSRF via HTTP redirect (compromised registry / typosquat)
# ---------------------------------------------------------------------------
def p1_redirect_ssrf() -> tuple[bool, str]:
    """A registry response with a 302/301 redirect makes fetch_registry contact
    an arbitrary host. urllib follows redirects without validation, so an
    attacker can bounce the fetcher to 127.0.0.1, [::1], 169.254.169.254, etc."""
    target_hits: list[str] = []

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            if self.path == "/typosquat":
                self.send_response(302)
                self.send_header("Location", f"http://127.0.0.1:{target_port}/metadata")
                self.end_headers()
            else:
                self.send_response(200)
                self.end_headers()
                self.wfile.write(b"{}")

        def log_message(self, *args):
            pass

    class TargetHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            target_hits.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"time":{"modified":"2024-01-01T00:00:00Z"}}')

        def log_message(self, *args):
            pass

    redirect_srv, redirect_port, _ = _start_server(RedirectHandler)
    target_srv, target_port, _ = _start_server(TargetHandler)

    orig_registry = prov._REGISTRY.copy()
    prov._REGISTRY["npm"] = f"http://127.0.0.1:{redirect_port}/{{name}}"
    try:
        result = fetch_registry("npm", "typosquat")
    finally:
        prov._REGISTRY = orig_registry
        _stop_server(redirect_srv)
        _stop_server(target_srv)

    hit_internal = "/metadata" in target_hits
    ok = not hit_internal
    detail = f"redirect_hits={target_hits}, result.status={result.status!r}"
    return ok, detail


# ---------------------------------------------------------------------------
# P2 — Attacker-controlled npm package name is injected into the request URL
# ---------------------------------------------------------------------------
def p2_name_url_injection() -> tuple[bool, str]:
    """npm dependency names are taken verbatim from package.json and interpolated
    into the registry URL without URL-encoding. A name like 'pkg?evil=1' turns
    the request path into a query string and appends attacker-controlled bytes
    to the HTTP request."""
    seen: list[str] = []

    class Recorder(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            seen.append(self.path)
            self.send_response(200)
            self.end_headers()
            self.wfile.write(b'{"time":{"modified":"2024-01-01T00:00:00Z"}}')

        def log_message(self, *args):
            pass

    srv, port, _ = _start_server(Recorder)
    orig_registry = prov._REGISTRY.copy()
    prov._REGISTRY["npm"] = f"http://127.0.0.1:{port}/{{name}}"
    try:
        fetch_registry("npm", "pkg?evil=1")
    finally:
        prov._REGISTRY = orig_registry
        _stop_server(srv)

    hit = next((p for p in seen if "evil=1" in p), None)
    ok = hit is None
    detail = f"request_path={hit!r}"
    return ok, detail


# ---------------------------------------------------------------------------
# P3 — Manifest-supplied package name reaches the finding object unchanged
# ---------------------------------------------------------------------------
def p3_name_in_finding() -> tuple[bool, str]:
    """A malicious dependency name (newlines, control chars, bidi) read from a
    manifest flows straight into ProvenanceFinding.package. The 'detail' string
    is glassport's own sentence, but the 'package' field is raw attacker text."""
    malicious_name = "evil\n<script>alert(1)</script>\u202e_pkg"
    dep = Dep(ecosystem="npm", name=malicious_name, spec="^1.0.0",
              manifest="package.json")
    payload = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {"deprecated": "ignore me"}},
        "time": {"modified": "2024-01-01T00:00:00Z"},
    }
    findings = evaluate(dep, Fetched(status="ok", payload=payload),
                        now=datetime(2024, 6, 1, tzinfo=timezone.utc))

    target = next((f for f in findings if f.rule == "prov-deprecated"), None)
    leaked = target is not None and target.package == malicious_name
    ok = not leaked
    pkg_repr = repr(target.package) if target else "None"
    detail = f"findings={len(findings)}, package_field={pkg_repr}"
    return ok, detail


# ---------------------------------------------------------------------------
# P5 — file:// redirects are not followed (negative)
# ---------------------------------------------------------------------------
def p5_file_redirect_rejected() -> tuple[bool, str]:
    """urllib's default redirect handler rejects file:// locations. A registry
    that tries to redirect to file:///etc/passwd therefore fails safely."""

    class RedirectHandler(http.server.BaseHTTPRequestHandler):
        def do_GET(self):
            self.send_response(302)
            self.send_header("Location", "file:///etc/passwd")
            self.end_headers()

        def log_message(self, *args):
            pass

    srv, port, _ = _start_server(RedirectHandler)
    orig_registry = prov._REGISTRY.copy()
    prov._REGISTRY["npm"] = f"http://127.0.0.1:{port}/{{name}}"
    try:
        result = fetch_registry("npm", "x")
    finally:
        prov._REGISTRY = orig_registry
        _stop_server(srv)

    ok = result.status == "error"
    detail = f"result.status={result.status!r}"
    return ok, detail


# ---------------------------------------------------------------------------
# P4 — Registry 'deprecated' message is NOT echoed into the finding (negative)
# ---------------------------------------------------------------------------
def p4_deprecated_not_echoed() -> tuple[bool, str]:
    """The npm registry 'deprecated' field is a publisher-controlled string.
    Currently _is_deprecated only checks for the key; evaluate() writes a
    generic sentence, so the attacker text does NOT reach the finding."""
    dep = Dep(ecosystem="npm", name="benign", spec="^1.0.0",
              manifest="package.json")
    payload = {
        "dist-tags": {"latest": "1.0.0"},
        "versions": {"1.0.0": {
            "deprecated": "**OBEY** <!-- directive --> \u202e",
            "dist": {"attestations": []},
        }},
        "time": {"modified": "2024-01-01T00:00:00Z"},
    }
    findings = evaluate(dep, Fetched(status="ok", payload=payload),
                        now=datetime(2024, 6, 1, tzinfo=timezone.utc))
    bad = "**OBEY**" in findings[0].detail or "<!-- directive -->" in findings[0].detail
    ok = not bad
    detail = f"detail={findings[0].detail!r}, leaked={bad}"
    return ok, detail


def run() -> int:
    os.makedirs(LOG_DIR, exist_ok=True)

    checks = [
        ("P1 redirect SSRF to 127.0.0.1", p1_redirect_ssrf()),
        ("P2 attacker name injected into request URL", p2_name_url_injection()),
        ("P3 attacker package name reaches finding", p3_name_in_finding()),
        ("P5 file:// redirect not followed (negative)", p5_file_redirect_rejected()),
        ("P4 deprecated string is not echoed (negative)", p4_deprecated_not_echoed()),
    ]

    lines = ["# provenance red-team — findings", "",
             "| row | result | detail |", "|---|---|---|"]
    all_ok = True
    for name, (ok, detail) in checks:
        all_ok = all_ok and ok
        lines.append(f"| {name} | {'PASS' if ok else 'FAIL'} | {detail} |")
        print(f"[{'PASS' if ok else 'FAIL'}] {name} — {detail}")

    lines += ["", "## Source defects", "",
              "* `fetch_registry` uses `urllib.request.urlopen` with the default "
              "redirect handler. A compromised registry or typosquat can return "
              "`Location: http://127.0.0.1/...` (or `[::1]`, metadata IPs) and "
              "the fetcher will follow it (P1).",
              "",
              "* npm package names from `package.json` keys are interpolated into "
              "the registry URL without percent-encoding. Characters like `?`, "
              "`#`, `%`, and unencoded `@scope/name` paths inject attacker bytes "
              "into the HTTP request line (P2).",
              "",
              "* `ProvenanceFinding.package` is copied straight from the manifest "
              "without normalization or scrubbing, so newlines, HTML, and Unicode "
              "directional controls reach the audit output channel (P3).",
              "",
              "* urllib's built-in redirect handler rejects non-HTTP schemes, so a "
              "`Location: file:///etc/passwd` redirect fails safely with status "
              "`error` and does not read local files (P5).",
              "",
              "* The npm `deprecated` string is correctly treated as a boolean "
              "flag by `_is_deprecated`; `evaluate()` emits only a generic sentence, "
              "so the attacker-controlled deprecation message does not currently "
              "leak into findings (P4).",
              ""]

    os.makedirs(os.path.dirname(FINDINGS), exist_ok=True)
    with open(FINDINGS, "w", encoding="utf-8") as fh:
        fh.write("\n".join(lines) + "\n")
    return 0 if all_ok else 1


if __name__ == "__main__":
    sys.exit(run())
