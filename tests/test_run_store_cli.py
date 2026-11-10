"""Checkpointing and resuming runs from the command line, and the shared config/report
round-trips that make a run started in one process (a Kaggle/Colab session, run_demo.py --db)
readable and resumable in another (a laptop dashboard, the next GPU session)."""
from __future__ import annotations

import json
import sqlite3
import subprocess
import sys
import tempfile
import unittest
from pathlib import Path

from _common import ROOT, SUITE

from rtbt.attackers.local_model import ModelConfig
from rtbt.config_io import config_from_dict, config_to_dict
from rtbt.harness import ExperimentConfig, ExperimentRunner
from rtbt.persistence import RunStore, rebuild_report
from rtbt.reporting import campaign_from_dict, report_from_dict

SMALL = ["--scenarios", "email-summary-exfil,doc-share-legit", "--defenses", "baseline,tool_validator",
         "--attack-modes", "static,adaptive_demo", "--budget", "6", "--seeds", "1,2"]


def _cli(*args: str, cwd: Path) -> subprocess.CompletedProcess:
    return subprocess.run([sys.executable, str(ROOT / "run_demo.py"), *args, "--out-dir", str(cwd)],
                          capture_output=True, text=True, timeout=300, cwd=cwd)


def _metrics_by_campaign(report) -> dict:
    """Every metric except wall-clock latency, which differs between two runs of the same campaign."""
    return {c.campaign_id: {k: v for k, v in c.metrics().items() if "latency" not in k} for c in report.campaigns}


class ConfigRoundTrip(unittest.TestCase):
    def test_every_field_survives_json(self):
        cfg = ExperimentConfig(defenses=("baseline", "classifier"), attack_modes=("static",), attack_budget=7,
                               seeds=(4, 5), scenario_ids=("email-summary-exfil",),
                               model_config=ModelConfig(name="llama3.1:8b", abliterated=True),
                               final_window_fraction=0.25, final_window_minimum=2,
                               model_failure_policy="abort_campaign")
        again = config_from_dict(json.loads(json.dumps(config_to_dict(cfg))))
        self.assertEqual(config_to_dict(again), config_to_dict(cfg))

    def test_missing_keys_take_defaults_but_explicit_empty_lists_do_not(self):
        self.assertEqual(config_from_dict({}).attack_budget, 20)
        self.assertEqual(config_from_dict({}, default_budget=15).attack_budget, 15)
        self.assertEqual(len(config_from_dict({}).defenses), 4)
        self.assertEqual(config_from_dict({"defenses": []}).defenses, ())  # validate() rejects it later

    def test_unknown_model_config_keys_from_a_newer_version_are_ignored(self):
        cfg = config_from_dict({"attack_modes": ["adaptive_ollama"],
                                "model_config": {"name": "m", "field_added_later": 1}})
        self.assertEqual(cfg.model_config.name, "m")


class ReportRoundTrip(unittest.TestCase):
    def test_rebuilt_report_has_identical_metrics_and_tables(self):
        cfg = ExperimentConfig(defenses=("baseline", "classifier"), attack_modes=("static", "adaptive_demo"),
                               attack_budget=6, seeds=(1,), scenario_ids=("email-summary-exfil", "doc-vendor-tamper"))
        report = ExperimentRunner(suite=SUITE, config=cfg).run()
        again = report_from_dict(json.loads(json.dumps(report.to_dict())))
        self.assertEqual(again.to_dict(), report.to_dict())
        self.assertEqual(again.comparison_table(), report.comparison_table())

    def test_a_stored_evidence_label_cannot_upgrade_a_simulated_campaign(self):
        cfg = ExperimentConfig(defenses=("baseline",), attack_modes=("static",), attack_budget=3, seeds=(1,),
                               scenario_ids=("email-summary-exfil",))
        d = ExperimentRunner(suite=SUITE, config=cfg).run().campaigns[0].to_dict()
        d["evidence_status"], d["eligible_as_research_evidence"] = "measured_result", True  # tampered
        self.assertEqual(campaign_from_dict(d).evidence_status, "simulated_result")


class CliCheckpointAndResume(unittest.TestCase):
    def setUp(self):
        self.tmp = Path(tempfile.mkdtemp())
        self.db = self.tmp / "runs.db"

    def test_db_run_checkpoints_every_campaign_and_can_be_rebuilt(self):
        p = _cli(*SMALL, "--db", str(self.db), "--run-id", "r1", cwd=self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        store = RunStore(self.db)
        self.assertEqual(store.get_run("r1")["status"], "complete")
        rows = store.get_campaigns("r1")
        self.assertEqual(len(rows), 2 * 2 * 2 * 2)
        self.assertTrue(all(r["status"] == "complete" for r in rows))
        rebuilt = rebuild_report(store, "r1")
        exported = report_from_dict(json.loads(next(self.tmp.glob("exp-*.json")).read_text()))
        self.assertEqual(_metrics_by_campaign(rebuilt), _metrics_by_campaign(exported))

    def test_resume_reruns_only_unfinished_campaigns_and_matches_an_uninterrupted_run(self):
        self.assertEqual(_cli(*SMALL, "--db", str(self.db), "--run-id", "full", cwd=self.tmp).returncode, 0)
        self.assertEqual(_cli(*SMALL, "--db", str(self.db), "--run-id", "cut", cwd=self.tmp).returncode, 0)
        # Simulate a GPU session dying part-way: 5 of the 16 campaigns never finished.
        conn = sqlite3.connect(self.db)
        ids = [r[0] for r in conn.execute("SELECT campaign_id FROM campaigns WHERE run_id='cut' ORDER BY campaign_id")]
        lost = ids[:5]
        conn.executemany("UPDATE campaigns SET status='started', result_json=NULL WHERE run_id='cut' AND campaign_id=?",
                         [(i,) for i in lost])
        conn.execute("UPDATE runs SET status='interrupted' WHERE run_id='cut'")
        conn.execute("DELETE FROM run_manifests WHERE run_id='cut'")
        conn.commit()
        conn.close()

        p = _cli("--db", str(self.db), "--resume", "cut", cwd=self.tmp)
        self.assertEqual(p.returncode, 0, p.stderr)
        self.assertIn("11 campaign(s) already complete and reused", p.stdout)
        store = RunStore(self.db)
        self.assertEqual(store.get_run("cut")["status"], "complete")
        self.assertEqual(_metrics_by_campaign(rebuild_report(store, "cut")),
                         _metrics_by_campaign(rebuild_report(store, "full")))
        self.assertTrue(any(e["decision"] == "resume" for e in store.get_recovery_log("cut")))

    def test_resume_refuses_finished_or_unknown_runs(self):
        _cli(*SMALL, "--db", str(self.db), "--run-id", "done", cwd=self.tmp)
        self.assertNotEqual(_cli("--db", str(self.db), "--resume", "done", cwd=self.tmp).returncode, 0)
        self.assertNotEqual(_cli("--db", str(self.db), "--resume", "nope", cwd=self.tmp).returncode, 0)
        self.assertNotEqual(_cli("--resume", "done", cwd=self.tmp).returncode, 0)  # --db required


class DashboardImportsStoredRuns(unittest.TestCase):
    def test_finished_cli_runs_appear_in_the_dashboard_and_interrupted_ones_do_not(self):
        tmp = Path(tempfile.mkdtemp())
        db = tmp / "runs.db"
        _cli(*SMALL, "--db", str(db), "--run-id", "ok", cwd=tmp)
        store = RunStore(db)
        store.create_run("half", config_to_dict(config_from_dict({})))
        store.update_run_status("half", "interrupted")
        import run_web
        run_web.RUNS.clear()
        imported = run_web.load_persisted_runs(store)
        self.assertEqual(imported, ["ok"])
        self.assertEqual(len(run_web.RUNS["ok"]["report"].campaigns), 16)
        self.assertTrue(run_web.RUNS["ok"]["imported_from_store"])
        run_web.RUNS.clear()


if __name__ == "__main__":
    unittest.main()
