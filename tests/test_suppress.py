"""
Tests for inline finding suppression in the static audit.

A line carrying `# nosec` (bandit-compatible) or `# glassport: ignore`
drops findings on that line; the scoped `# glassport: ignore[rule-id]`
form drops only the named rule. This is what lets glassport audit its
own rule catalog — whose descriptions necessarily quote attack strings
like "ignore previous instructions" — without flagging itself.
"""
import unittest
from pathlib import Path

from glassport import audit


class TestSuppression(unittest.TestCase):
    def rules(self, hits):
        return {h["rule"] for h in hits}

    def test_unmarked_eval_is_flagged(self):
        hits, _ = audit._scan_python("eval(payload)\n", "x.py")
        self.assertIn("exec-dynamic", self.rules(hits))

    def test_nosec_suppresses_line(self):
        hits, _ = audit._scan_python("eval(payload)  # nosec\n", "x.py")
        self.assertNotIn("exec-dynamic", self.rules(hits))

    def test_glassport_ignore_bare_suppresses_line(self):
        hits, _ = audit._scan_python(
            "eval(payload)  # glassport: ignore\n", "x.py")
        self.assertNotIn("exec-dynamic", self.rules(hits))

    def test_scoped_ignore_suppresses_only_named_rule(self):
        hits, _ = audit._scan_python(
            "eval(payload)  # glassport: ignore[exec-dynamic]\n", "x.py")
        self.assertNotIn("exec-dynamic", self.rules(hits))

    def test_scoped_ignore_other_rule_leaves_hit(self):
        hits, _ = audit._scan_python(
            "eval(payload)  # glassport: ignore[net-egress]\n", "x.py")
        self.assertIn("exec-dynamic", self.rules(hits))

    def test_nosec_suppresses_poison_directive(self):
        clean = audit._scan_common(
            "desc = 'ignore previous instructions'  # nosec\n", "x.py")
        self.assertNotIn("tool-poisoning", self.rules(clean))
        flagged = audit._scan_common(
            "desc = 'ignore previous instructions'\n", "x.py")
        self.assertIn("tool-poisoning", self.rules(flagged))


class TestSelfAuditClean(unittest.TestCase):
    def test_package_source_has_no_tool_poisoning_false_positive(self):
        # the rule catalog quotes attack strings as documentation; with
        # the catalog lines marked, a self-scan must not flag them
        report = audit.audit_path(Path("src/glassport"))
        rules = {f.rule for f in report.findings}
        self.assertNotIn("tool-poisoning", rules)


if __name__ == "__main__":
    unittest.main()
