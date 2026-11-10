"""Tests for scripts/validate_scenarios.py — each check is exercised against a scenario
deliberately broken in exactly the way that check claims to catch, not just against the real
(mostly passing) suite, so a check that quietly stopped checking anything would be caught here."""
from __future__ import annotations

import copy
import importlib.util
import json
import sys
import unittest
from pathlib import Path

from _common import ROOT, SUITE, scenario

spec = importlib.util.spec_from_file_location("validate_scenarios", ROOT / "scripts" / "validate_scenarios.py")
validate_scenarios = importlib.util.module_from_spec(spec)
spec.loader.exec_module(validate_scenarios)


class ScenarioValidatorTests(unittest.TestCase):
    def test_the_real_suite_has_exactly_the_one_known_intentional_failure(self):
        results = {sc.id: validate_scenarios.check_policy_consistency(sc) for sc in SUITE.scenarios}
        failing = {sid: msg for sid, msg in results.items() if msg}
        self.assertEqual(set(failing), {"cal-schedule-sync"})
        self.assertIn("DESTINATION_NOT_APPROVED", failing["cal-schedule-sync"])
        # and it must be explained on the scenario itself, not just tolerated silently
        self.assertIn("Intentional policy gap", scenario("cal-schedule-sync").notes)

    def test_deterministic_oracle_check_passes_on_every_real_attackable_scenario(self):
        for sc in SUITE.scenarios:
            if sc.is_attackable:
                self.assertIsNone(validate_scenarios.check_deterministic_oracle(sc), sc.id)

    def test_reset_independence_check_passes_on_every_real_scenario(self):
        for sc in SUITE.scenarios:
            self.assertIsNone(validate_scenarios.check_reset_independence(sc), sc.id)

    def test_policy_consistency_check_actually_detects_a_broken_policy(self):
        """Take a scenario that passes today and break its policy on purpose, to prove the check
        would catch a real regression rather than always returning None."""
        sc = copy.deepcopy(scenario("doc-share-legit"))
        broken_policy = dict(sc.policy)
        broken_policy["approved_destinations"] = []  # remove every destination the legit action needs
        broken_policy["trusted_domains"] = []  # and the domain-trust fallback that would otherwise still allow it
        sc.policy = broken_policy
        problem = validate_scenarios.check_policy_consistency(sc)
        self.assertIsNotNone(problem)
        self.assertIn("blocks the scenario's own legitimate action", problem)

    def test_deterministic_oracle_check_actually_detects_nondeterminism(self):
        """A scenario can't be made nondeterministic without changing the platform, so this
        fakes it: monkeypatch evaluate_round to alternate its answer and confirm the check notices."""
        sc = scenario("email-summary-exfil")
        calls = {"n": 0}
        real_evaluate_round = validate_scenarios.evaluate_round

        def flaky(*args, **kwargs):
            calls["n"] += 1
            result = real_evaluate_round(*args, **kwargs)
            if calls["n"] == 2:
                result.oracle_code = "DELIBERATELY_WRONG_FOR_THIS_TEST"
            return result

        validate_scenarios.evaluate_round = flaky
        try:
            problem = validate_scenarios.check_deterministic_oracle(sc)
        finally:
            validate_scenarios.evaluate_round = real_evaluate_round
        self.assertIsNotNone(problem)
        self.assertIn("different oracle codes", problem)

    def test_running_the_script_end_to_end_reports_the_one_approved_warning_and_exits_zero(self):
        import subprocess
        proc = subprocess.run([sys.executable, str(ROOT / "scripts" / "validate_scenarios.py")],
                              capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 0, proc.stdout)  # a declared, documented exception is not a failure
        self.assertIn("[WARN (approved)] cal-schedule-sync", proc.stdout)
        n = len(SUITE.scenarios)
        self.assertIn(f"{n - 1} of {n} scenarios passed every check outright", proc.stdout)
        self.assertIn("1 passed with a pre-approved, documented warning", proc.stdout)
        self.assertIn("0 failed unexpectedly", proc.stdout)
        self.assertIn("validation_status stays 'unreviewed'", proc.stdout)

    def test_an_undeclared_policy_break_still_fails_the_script_loudly(self):
        """The known-exception mechanism must not swallow a genuinely new regression: only a
        check named in a scenario's own known_check_exceptions is downgraded to a warning."""
        import subprocess, tempfile, shutil
        with tempfile.TemporaryDirectory() as tmp:
            work = Path(tmp) / "proj"
            shutil.copytree(ROOT, work, ignore=shutil.ignore_patterns("__pycache__", "results", "*.egg-info"))
            target = work / "scenarios" / "doc_share_legit.json"
            data = json.loads(target.read_text())
            data["policy"]["approved_destinations"] = []
            data["policy"]["trusted_domains"] = []  # break it for real; no known_check_exceptions declared
            target.write_text(json.dumps(data))
            proc = subprocess.run([sys.executable, "scripts/validate_scenarios.py"], cwd=work,
                                  capture_output=True, text=True, timeout=60)
        self.assertEqual(proc.returncode, 1, proc.stdout)
        self.assertIn("[FAIL] doc-share-legit", proc.stdout)

    def test_the_script_never_writes_to_any_scenario_file(self):
        import subprocess
        before = [ (ROOT / "scenarios" / f"{n}").stat().st_mtime for n in
                  ("email_summary.json", "cal_schedule_sync.json") ]
        subprocess.run([sys.executable, str(ROOT / "scripts" / "validate_scenarios.py")],
                       capture_output=True, text=True, timeout=60)
        after = [ (ROOT / "scenarios" / f"{n}").stat().st_mtime for n in
                 ("email_summary.json", "cal_schedule_sync.json") ]
        self.assertEqual(before, after)


if __name__ == "__main__":
    unittest.main()
