"""The solvability / oracle hand-trace script is part of the test suite: every scenario must pass
it, and it must actually catch a broken scenario rather than pass everything."""
from __future__ import annotations

import copy
import sys
import unittest
from dataclasses import replace

from _common import ROOT, SUITE

sys.path.insert(0, str(ROOT / "scripts"))
import check_solvability  # noqa: E402


class HandTrace(unittest.TestCase):
    def test_every_scenario_matches_its_hand_trace(self):
        rows = [r for sc in SUITE.scenarios for r in check_solvability.check(sc)]
        bad = [r for r in rows if not r["ok"]]
        self.assertEqual(bad, [])
        attackable = sum(sc.is_attackable for sc in SUITE.scenarios)
        benign = len(SUITE.scenarios) - attackable
        self.assertEqual(len(rows), 4 * attackable + 4 * benign)

    def test_suite_covers_every_effect_kind_and_environment(self):
        kinds = {sc.objective.kind for sc in SUITE.scenarios if sc.objective}
        self.assertEqual(kinds, {"email_sent", "document_shared", "document_modified", "attendee_added", "event_created"})
        self.assertEqual({sc.environment for sc in SUITE.scenarios if not sc.is_attackable}, {"email", "documents"})
        self.assertGreaterEqual(len(SUITE.scenarios), 16)

    def test_an_unsolvable_scenario_is_reported(self):
        sc = SUITE.get("doc-share-legit")
        broken_behavior = copy.deepcopy(sc.simulated_behavior)
        broken_behavior["legit_actions"] = []  # the agent never shares with Priya
        rows = check_solvability.check(replace(sc, simulated_behavior=broken_behavior))
        t1 = next(r for r in rows if r["trace"].startswith("T1"))
        self.assertFalse(t1["ok"])
        self.assertIn("NOT SOLVABLE", t1["note"])

    def test_an_unreachable_objective_is_reported(self):
        sc = SUITE.get("doc-handbook-editor-grant")
        # Make the objective demand a role no tool call in the trace will ever grant.
        objective = replace(sc.objective, params={**sc.objective.params, "role": "owner"})
        rows = check_solvability.check(replace(sc, objective=objective))
        self.assertFalse(next(r for r in rows if r["trace"].startswith("T2"))["ok"])


if __name__ == "__main__":
    unittest.main()
