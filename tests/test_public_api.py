"""
Public-API lock (roadmap H1.07).

The README documents four typed entry points; this test pins the lazy
re-exports (PEP 562) and the py.typed marker so external Pyright/mypy
users resolve real types instead of Unknown.

Pure stdlib, run with:  python3 -m unittest tests.test_public_api
"""
import unittest
from pathlib import Path

import glassport


class TestPublicAPI(unittest.TestCase):
    def test_lazy_reexports_resolve(self):
        from glassport.adapters.mcp_session import from_mcp_session_file
        from glassport.audit import audit_path
        from glassport.detectors import annotate
        from glassport.interaction_trace import InteractionTrace
        self.assertIs(glassport.InteractionTrace, InteractionTrace)
        self.assertIs(glassport.from_mcp_session_file,
                      from_mcp_session_file)
        self.assertIs(glassport.annotate, annotate)
        self.assertIs(glassport.audit_path, audit_path)

    def test_unknown_attribute_raises(self):
        with self.assertRaises(AttributeError):
            glassport.no_such_symbol

    def test_dir_lists_public_api(self):
        for name in glassport.__all__:
            self.assertIn(name, dir(glassport))

    def test_py_typed_marker_ships(self):
        pkg = Path(glassport.__file__).parent
        self.assertTrue((pkg / "py.typed").exists())

    def test_import_glassport_stays_light(self):
        # the tap's startup path imports glassport for __version__ only;
        # detectors/audit must not load until an API symbol is touched
        import os
        import subprocess
        import sys
        code = ("import sys, glassport; "
                "sys.exit(1 if 'glassport.detectors' in sys.modules "
                "or 'glassport.audit' in sys.modules else 0)")
        # inherit the environment: a bare env breaks python startup on
        # Windows (SystemRoot) and can break venv resolution anywhere
        env = {**os.environ,
               "PYTHONPATH": "src" + os.pathsep
               + os.environ.get("PYTHONPATH", "")}
        rc = subprocess.run([sys.executable, "-c", code],
                            env=env).returncode
        self.assertEqual(rc, 0)


if __name__ == "__main__":
    unittest.main()
