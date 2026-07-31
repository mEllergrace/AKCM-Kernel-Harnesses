"""Tests for akcm_sources.py -- the bridge that gives Engine K's stage4 control identity
from the factory's OWN tested AICM 1.0.3 loader, instead of re-parsing
ZTAF-Primitive-Mapping-v2/catalog/sources.md (the superseded repo)."""
import json
import subprocess
import sys
import unittest
from pathlib import Path

HERE = Path(__file__).resolve().parent.parent
PYTHON = sys.executable


def run(*args):
    result = subprocess.run(
        [PYTHON, str(HERE / "akcm_sources.py"), *args],
        capture_output=True, text=True, cwd=HERE,
    )
    return result


class AkcmSourcesTests(unittest.TestCase):
    def test_domain_returns_only_that_domains_controls(self):
        result = run("--domain", "Universal Endpoint Management")
        self.assertEqual(result.returncode, 0, result.stderr)
        controls = json.loads(result.stdout)
        self.assertTrue(len(controls) > 0)
        for c in controls:
            self.assertEqual(c["domain"], "Universal Endpoint Management")
            self.assertIn("id", c)
            self.assertIn("title", c)

    def test_unknown_domain_returns_empty_list_not_an_error(self):
        result = run("--domain", "Not A Real Domain")
        self.assertEqual(result.returncode, 0, result.stderr)
        self.assertEqual(json.loads(result.stdout), [])

    def test_all_returns_243_aicm_1_0_3_controls(self):
        """docs/HANDOFF.md's own 'Factory operational' line: AICM 243 controls."""
        result = run("--all")
        self.assertEqual(result.returncode, 0, result.stderr)
        controls = json.loads(result.stdout)
        self.assertEqual(len(controls), 243)

    def test_missing_domain_arg_is_a_usage_error(self):
        result = run()
        self.assertEqual(result.returncode, 2)

    def test_ssm_factory_root_env_var_overrides_the_default_location(self):
        """akcm_sources.py is moving to a different repo than the factory it reads from --
        FACTORY_ROOT must be overridable, not hardcoded to a fixed relative hop count."""
        result = subprocess.run(
            [PYTHON, str(HERE / "akcm_sources.py"), "--domain", "Not A Real Domain"],
            capture_output=True, text=True, cwd=HERE,
            env={**__import__("os").environ, "SSM_FACTORY_ROOT": "/nonexistent/path"},
        )
        self.assertNotEqual(result.returncode, 0, "a bogus override must actually be used, not ignored")


if __name__ == "__main__":
    unittest.main()
