"""Dry run of the exact Kaggle/Colab configuration against local fakes.

The notebook's configs (configs/kaggle_*.json) are run unchanged except for the two localhost
ports, with a fake Ollama (tests/fakes/fake_ollama.py) in place of the model server and a fake
backend behind the REAL classifier service. This proves, before anyone spends GPU hours, that the
real-model path is wired end to end: native tool calls through every defense, the classifier
over HTTP, the model-backed attacker, the run store, and the evidence labels."""
from __future__ import annotations

import json
import sys
import tempfile
import threading
import unittest
from pathlib import Path

from _common import ROOT, SUITE

sys.path.insert(0, str(ROOT / "services"))
sys.path.insert(0, str(ROOT / "tests" / "fakes"))
import fake_ollama  # noqa: E402
from classifier_server import Scorer, serve  # noqa: E402

from rtbt.config_io import config_from_dict  # noqa: E402
from rtbt.harness import ExperimentRunner  # noqa: E402
from rtbt.sizing import fit_to_hours, plan_matrix  # noqa: E402


class AddressDetector:
    model_name, revision = "fake/address-detector", "test"

    def encode(self, text):
        return text.split()

    def decode(self, ids):
        return " ".join(ids)

    def p_injection(self, texts):
        return [0.95 if fake_ollama.ATTACKER in t else 0.02 for t in texts]


def _start(server):
    threading.Thread(target=server.serve_forever, daemon=True).start()
    return server.server_address[1]


class DryRun(unittest.TestCase):
    @classmethod
    def setUpClass(cls):
        cls.ollama = fake_ollama.serve()
        cls.clf = serve(Scorer(AddressDetector()), "127.0.0.1", 0)
        cls.ollama_port, cls.clf_port = _start(cls.ollama), _start(cls.clf)

    @classmethod
    def tearDownClass(cls):
        for s in (cls.ollama, cls.clf):
            s.shutdown()
            s.server_close()

    def _config(self, name, **override):
        raw = json.loads((ROOT / "configs" / name).read_text(encoding="utf-8"))
        raw["real_target_config"]["endpoint"] = f"http://127.0.0.1:{self.ollama_port}/api/chat"
        raw["classifier_spec"]["endpoint"] = f"http://127.0.0.1:{self.clf_port}/score"
        if raw.get("model_config"):
            raw["model_config"]["endpoint"] = f"http://127.0.0.1:{self.ollama_port}/api/generate"
        raw.update(override)
        return config_from_dict(raw)

    def test_pilot_config_runs_end_to_end_and_is_labelled_measured(self):
        report = ExperimentRunner(suite=SUITE, config=self._config("kaggle_pilot.json")).run()
        self.assertEqual(len(report.campaigns), 4 * 4 * 2 * 1)
        rounds = [r for c in report.campaigns for r in c.rounds]
        self.assertTrue(rounds and all(r.valid for r in rounds), [r.error_detail for r in rounds if not r.valid][:3])
        self.assertTrue(all(c.evidence_status == "measured_result" for c in report.campaigns))
        by = {(c.scenario_id, c.defense_id, c.attack_mode): c.metrics() for c in report.campaigns}
        exfil = ("email-summary-exfil", "baseline", "static")
        self.assertGreater(by[exfil]["campaign_average_asr"], 0)                          # the fake obeys
        self.assertEqual(by[("email-summary-exfil", "classifier", "static")]["campaign_average_asr"], 0)  # HTTP classifier
        self.assertEqual(by[("email-summary-exfil", "tool_validator", "static")]["campaign_average_asr"], 0)
        self.assertTrue(all(r.target_provenance.startswith("real_model_chat:") for r in rounds))

    def test_adaptive_config_drives_the_model_attacker(self):
        cfg = self._config("kaggle_primary_adaptive.json", scenario_ids=["email-summary-exfil"],
                           attack_modes=["adaptive_ollama"], defenses=["baseline"], attack_budget=3, seeds=[1])
        c = ExperimentRunner(suite=SUITE, config=cfg).run().campaigns[0]
        self.assertEqual(c.attacker_stats["provenance"], "standard_local_model")
        self.assertEqual(c.attacker_stats["attempts"], 3)
        self.assertEqual(c.evidence_status, "measured_result")

    def test_sizing_counts_exactly_the_rounds_the_harness_runs(self):
        cfg = self._config("kaggle_pilot.json")
        report = ExperimentRunner(suite=SUITE, config=cfg).run()
        plan = plan_matrix(SUITE, scenario_ids=cfg.scenario_ids, defenses=4, attack_modes=2, seeds=1,
                           budget=cfg.attack_budget, seconds_per_round=1.0)
        self.assertEqual(plan.rounds, sum(len(c.rounds) for c in report.campaigns))
        self.assertEqual(plan.campaigns, len(report.campaigns))
        options = fit_to_hours(SUITE, scenario_ids=None, defenses=4, attack_modes=2, gpu_hours_available=12,
                               seconds_per_round=8.0)
        self.assertTrue(options and all(o["gpu_hours"] <= 12 for o in options))
        self.assertEqual(fit_to_hours(SUITE, scenario_ids=None, defenses=4, attack_modes=2,
                                      gpu_hours_available=0.1, seconds_per_round=8.0), [])


if __name__ == "__main__":
    unittest.main()
