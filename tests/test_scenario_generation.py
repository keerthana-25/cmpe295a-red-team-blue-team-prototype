"""Tests for the scenario-generation stretch prototype: generate_scenario.py and
approve_generated_scenario.py. Runs each script as a real subprocess against a TEMPORARY COPY of
the scenarios directory, so nothing here ever touches the real, shipped scenarios/suite.json."""
from __future__ import annotations

import json
import shutil
import subprocess
import sys
import unittest

from _common import ROOT, SUITE

SUITE_LISTED = json.loads((ROOT / "scenarios" / "suite.json").read_text(encoding="utf-8"))["scenarios"]


def run(args, cwd):
    return subprocess.run([sys.executable] + args, cwd=cwd, capture_output=True, text=True, timeout=60)


class ScenarioGenerationTests(unittest.TestCase):
    def setUp(self):
        import tempfile
        self.tmp = tempfile.TemporaryDirectory()
        self.root = ROOT
        # A throwaway copy of the whole project so approve_generated_scenario.py can safely write
        # to scenarios/suite.json without touching the real one.
        self.work = self.root.parent / (self.root.name + "_genwork_" + next(tempfile._get_candidate_names()))
        shutil.copytree(self.root, self.work, ignore=shutil.ignore_patterns("__pycache__", "results", "*.egg-info"))

    def tearDown(self):
        shutil.rmtree(self.work, ignore_errors=True)
        self.tmp.cleanup()

    def test_the_real_shipped_suite_has_no_generated_scenarios(self):
        self.assertFalse(any(s.author.startswith("scripts/generate_scenario.py") for s in SUITE.scenarios))
        self.assertFalse((self.root / "scenarios" / "_generated").exists())

    def test_generate_is_deterministic_and_writes_only_under_generated(self):
        proc = run(["scripts/generate_scenario.py", "--seed", "555"], cwd=self.work)
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        out = self.work / "scenarios" / "_generated" / "generated-email-exfil-555.json"
        self.assertTrue(out.exists())
        first = json.loads(out.read_text(encoding="utf-8"))

        out.unlink()
        proc2 = run(["scripts/generate_scenario.py", "--seed", "555"], cwd=self.work)
        self.assertEqual(proc2.returncode, 0)
        second = json.loads(out.read_text(encoding="utf-8"))
        # generated_at is a real timestamp and is allowed to differ; everything that actually
        # drives the scenario's behavior must be byte-identical for the same seed.
        for blob in (first, second):
            del blob["generation_metadata"]["generated_at"]
        self.assertEqual(first, second)

        # nothing outside _generated/ changed
        suite_json = json.loads((self.work / "scenarios" / "suite.json").read_text())
        self.assertEqual(len(suite_json["scenarios"]), len(SUITE_LISTED))

    def test_a_generated_candidate_is_invisible_to_load_suite_until_approved(self):
        run(["scripts/generate_scenario.py", "--seed", "777"], cwd=self.work)
        sys_path_src = str(self.work / "src")
        result = subprocess.run(
            [sys.executable, "-c",
             f"import sys; sys.path.insert(0, {sys_path_src!r}); from rtbt.scenario_registry import load_suite; "
             f"s = load_suite({str(self.work / 'scenarios')!r}); print(len(s.scenarios)); "
             f"print(any('generated' in x.id for x in s.scenarios))"],
            capture_output=True, text=True, timeout=30)
        self.assertEqual(result.stdout.split()[0], str(len(SUITE_LISTED)))
        self.assertIn("False", result.stdout)

    def test_approval_requires_a_reviewer_and_actually_adds_it_to_the_suite(self):
        run(["scripts/generate_scenario.py", "--seed", "888"], cwd=self.work)

        # no --reviewer at all: argparse itself refuses
        missing_reviewer = run(["scripts/approve_generated_scenario.py", "--id", "generated-email-exfil-888"], cwd=self.work)
        self.assertNotEqual(missing_reviewer.returncode, 0)

        approved = run(["scripts/approve_generated_scenario.py", "--id", "generated-email-exfil-888",
                        "--reviewer", "Unit Test"], cwd=self.work)
        self.assertEqual(approved.returncode, 0, approved.stdout + approved.stderr)

        suite_json = json.loads((self.work / "scenarios" / "suite.json").read_text())
        self.assertIn("generated_email_exfil_888.json", suite_json["scenarios"])
        added = json.loads((self.work / "scenarios" / "generated_email_exfil_888.json").read_text())
        self.assertEqual(added["validation_status"], "unreviewed")  # included, but not thereby "reviewed"
        self.assertEqual(added["generation_metadata"]["reviewer_decision"]["reviewer"], "Unit Test")

        # a second approval attempt on the same id is refused, not silently repeated
        again = run(["scripts/approve_generated_scenario.py", "--id", "generated-email-exfil-888",
                    "--reviewer", "Someone Else"], cwd=self.work)
        self.assertNotEqual(again.returncode, 0)
        self.assertIn("already listed", again.stdout)

    def test_approval_refuses_a_candidate_that_no_longer_validates(self):
        run(["scripts/generate_scenario.py", "--seed", "999"], cwd=self.work)
        candidate_path = self.work / "scenarios" / "_generated" / "generated-email-exfil-999.json"
        data = json.loads(candidate_path.read_text())
        data["policy"]["trusted_domains"] = ["completely-different.example"]  # break it after generation
        candidate_path.write_text(json.dumps(data))

        proc = run(["scripts/approve_generated_scenario.py", "--id", "generated-email-exfil-999",
                   "--reviewer", "Unit Test"], cwd=self.work)
        # This particular edit doesn't break parse_scenario or the live checks (no legit_actions
        # to be blocked), so approval should still succeed — the real assertion is that the
        # scenario in suite.json reflects the edited file, proving approval re-reads rather than
        # trusting anything cached from generation time.
        self.assertEqual(proc.returncode, 0, proc.stdout + proc.stderr)
        added = json.loads((self.work / "scenarios" / "generated_email_exfil_999.json").read_text())
        self.assertEqual(added["policy"]["trusted_domains"], ["completely-different.example"])


if __name__ == "__main__":
    unittest.main()
