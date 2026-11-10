"""Local, single-user crash recovery via SQLite (stdlib only — no external database server).

Persists enough about a run to answer, after a hard restart, three questions: which campaigns
already finished (never repeat those), which campaign was in flight when the process died (a
genuine interruption, distinct from a normal finish), and what the person decided to do about it
— recorded permanently, next to everything else, not just acted on and forgotten.

The smallest unit this persists is one whole CampaignResult, not one round. A campaign that had
not finished when the process died is always re-run from its first round rather than resumed
mid-way, because a partially-run adaptive attacker's in-memory history (which strategy it is on,
what it has already tried) cannot be reconstructed from the database — attempting a partial
resume would be exactly the kind of silently-combined, logically-incompatible state this platform
is built to avoid everywhere else. What IS safe, and what this module actually does: a campaign
whose attacker is deterministic (static, adaptive_demo) is a pure function of its seed and attempt
number, so re-running it from round 1 under its original id reproduces precisely what would have
happened anyway — there is nothing incompatible to combine. A campaign whose attacker is
model-backed and stateful is instead re-run under a brand-new campaign id, exactly like a
model_failure_policy restart-as-separate-demo-campaign fallback, and this is always logged.
"""
from __future__ import annotations

import json
import sqlite3
import threading
from pathlib import Path
from typing import Any

from .util import utc_now_iso

SCHEMA = """
CREATE TABLE IF NOT EXISTS runs (
    run_id TEXT PRIMARY KEY,
    config_json TEXT NOT NULL,
    status TEXT NOT NULL,  -- running | complete | cancelled | error | interrupted | abandoned
    created_at TEXT NOT NULL,
    updated_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS campaigns (
    run_id TEXT NOT NULL,
    campaign_id TEXT NOT NULL,
    scenario_id TEXT, defense_id TEXT, attack_mode TEXT, target_mode TEXT, seed INTEGER, attack_budget INTEGER,
    status TEXT NOT NULL,  -- started | complete
    result_json TEXT,      -- full CampaignResult.to_dict(); present only once status = complete
    started_at TEXT, ended_at TEXT,
    PRIMARY KEY (run_id, campaign_id)
);
CREATE TABLE IF NOT EXISTS run_manifests (
    run_id TEXT PRIMARY KEY,   -- one row per finished run, written after the report is built
    experiment_id TEXT NOT NULL,
    manifest_json TEXT NOT NULL,
    saved_at TEXT NOT NULL
);
CREATE TABLE IF NOT EXISTS recovery_log (
    id INTEGER PRIMARY KEY AUTOINCREMENT,
    run_id TEXT NOT NULL,
    decision TEXT NOT NULL,  -- resume | restart | abandon | marked_interrupted_on_startup
    note TEXT,
    decided_at TEXT NOT NULL
);
"""

# Attackers whose behavior depends on in-memory history across rounds. See the module docstring
# for exactly what this changes about how a recovered run is handled.
STATEFUL_ATTACK_MODES = ("adaptive_ollama",)
RUN_STATUSES = ("running", "complete", "cancelled", "error", "interrupted", "abandoned")


class RunStore:
    def __init__(self, db_path: str | Path):
        self.db_path = Path(db_path)
        self.db_path.parent.mkdir(parents=True, exist_ok=True)
        self._lock = threading.Lock()
        # check_same_thread=False: the background run thread and the request-handling threads
        # both use this store; _lock is what actually makes that safe, not sqlite3 alone.
        self._conn = sqlite3.connect(str(self.db_path), check_same_thread=False)
        with self._lock:
            self._conn.executescript(SCHEMA)
            self._conn.commit()

    def close(self) -> None:
        with self._lock:
            self._conn.close()

    # ------------------------------------------------------------------ writes
    def create_run(self, run_id: str, config_dict: dict[str, Any]) -> None:
        now = utc_now_iso()
        with self._lock:
            self._conn.execute(
                "INSERT INTO runs (run_id, config_json, status, created_at, updated_at) VALUES (?, ?, 'running', ?, ?)",
                (run_id, json.dumps(config_dict), now, now))
            self._conn.commit()

    def update_run_status(self, run_id: str, status: str) -> None:
        assert status in RUN_STATUSES, status
        with self._lock:
            self._conn.execute("UPDATE runs SET status = ?, updated_at = ? WHERE run_id = ?", (status, utc_now_iso(), run_id))
            self._conn.commit()

    def record_campaign_start(self, run_id: str, campaign_id: str, *, scenario_id: str, defense_id: str,
                              attack_mode: str, target_mode: str, seed: int, attack_budget: int) -> None:
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO campaigns "
                "(run_id, campaign_id, scenario_id, defense_id, attack_mode, target_mode, seed, attack_budget, status, started_at) "
                "VALUES (?, ?, ?, ?, ?, ?, ?, ?, 'started', ?)",
                (run_id, campaign_id, scenario_id, defense_id, attack_mode, target_mode, seed, attack_budget, utc_now_iso()))
            self._conn.commit()

    def record_campaign_complete(self, run_id: str, campaign_id: str, result_dict: dict[str, Any]) -> None:
        with self._lock:
            self._conn.execute(
                "UPDATE campaigns SET status = 'complete', result_json = ?, ended_at = ? WHERE run_id = ? AND campaign_id = ?",
                (json.dumps(result_dict), utc_now_iso(), run_id, campaign_id))
            self._conn.commit()

    def log_recovery_decision(self, run_id: str, decision: str, note: str = "") -> None:
        with self._lock:
            self._conn.execute("INSERT INTO recovery_log (run_id, decision, note, decided_at) VALUES (?, ?, ?, ?)",
                              (run_id, decision, note, utc_now_iso()))
            self._conn.commit()

    def save_manifest(self, run_id: str, experiment_id: str, manifest: dict[str, Any]) -> None:
        """Store the reproducibility manifest of a finished run so another process (e.g. a laptop
        dashboard opening a runs.db copied from a GPU session) can rebuild the full report."""
        with self._lock:
            self._conn.execute(
                "INSERT OR REPLACE INTO run_manifests (run_id, experiment_id, manifest_json, saved_at) VALUES (?, ?, ?, ?)",
                (run_id, experiment_id, json.dumps(manifest), utc_now_iso()))
            self._conn.commit()

    # ------------------------------------------------------------------ reads
    def get_manifest(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT experiment_id, manifest_json FROM run_manifests WHERE run_id = ?", (run_id,)).fetchone()
        return {"experiment_id": row[0], "manifest": json.loads(row[1])} if row else None

    def get_run(self, run_id: str) -> dict[str, Any] | None:
        with self._lock:
            row = self._conn.execute(
                "SELECT run_id, config_json, status, created_at, updated_at FROM runs WHERE run_id = ?", (run_id,)).fetchone()
        if not row:
            return None
        return {"run_id": row[0], "config": json.loads(row[1]), "status": row[2], "created_at": row[3], "updated_at": row[4]}

    def list_runs(self, status: str | None = None) -> list[dict[str, Any]]:
        with self._lock:
            if status:
                rows = self._conn.execute(
                    "SELECT run_id, status, created_at, updated_at FROM runs WHERE status = ? ORDER BY created_at DESC", (status,)).fetchall()
            else:
                rows = self._conn.execute("SELECT run_id, status, created_at, updated_at FROM runs ORDER BY created_at DESC").fetchall()
        return [{"run_id": r[0], "status": r[1], "created_at": r[2], "updated_at": r[3]} for r in rows]

    def get_campaigns(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT campaign_id, scenario_id, defense_id, attack_mode, target_mode, seed, attack_budget, status, result_json "
                "FROM campaigns WHERE run_id = ?", (run_id,)).fetchall()
        return [{
            "campaign_id": r[0], "scenario_id": r[1], "defense_id": r[2], "attack_mode": r[3], "target_mode": r[4],
            "seed": r[5], "attack_budget": r[6], "status": r[7], "result": json.loads(r[8]) if r[8] else None,
        } for r in rows]

    def get_recovery_log(self, run_id: str) -> list[dict[str, Any]]:
        with self._lock:
            rows = self._conn.execute(
                "SELECT decision, note, decided_at FROM recovery_log WHERE run_id = ? ORDER BY id", (run_id,)).fetchall()
        return [{"decision": r[0], "note": r[1], "decided_at": r[2]} for r in rows]

    # ------------------------------------------------------------------ recovery
    def mark_stale_running_as_interrupted(self) -> list[str]:
        """Call once, right after opening the store at process startup. Any run still 'running'
        at that moment cannot genuinely be running — this process only just started — so it was
        interrupted by whatever ended the previous one. Returns the affected run ids."""
        with self._lock:
            rows = self._conn.execute("SELECT run_id FROM runs WHERE status = 'running'").fetchall()
            for (run_id,) in rows:
                self._conn.execute("UPDATE runs SET status = 'interrupted', updated_at = ? WHERE run_id = ?", (utc_now_iso(), run_id))
            self._conn.commit()
        run_ids = [r[0] for r in rows]
        for run_id in run_ids:
            self.log_recovery_decision(run_id, "marked_interrupted_on_startup",
                                       "This run was still 'running' when the server started; the previous process "
                                       "must have ended (crash, kill, restart) without finishing it.")
        return run_ids

    def recovery_plan(self, run_id: str) -> dict[str, Any]:
        """What resuming this run would actually do, computed without doing it, so a person (or a
        test) can inspect the plan before committing to it."""
        campaigns = self.get_campaigns(run_id)
        completed = [c for c in campaigns if c["status"] == "complete"]
        incomplete = [c for c in campaigns if c["status"] != "complete"]
        return {
            "completed_campaign_ids": [c["campaign_id"] for c in completed],
            "incomplete_needs_new_id": [c["campaign_id"] for c in incomplete if c["attack_mode"] in STATEFUL_ATTACK_MODES],
            "incomplete_safe_same_id": [c["campaign_id"] for c in incomplete if c["attack_mode"] not in STATEFUL_ATTACK_MODES],
        }


def rebuild_report(store: RunStore, run_id: str):
    """Rebuild an ExperimentReport for ``run_id`` from the run store alone: every completed
    campaign's stored result plus the saved manifest. Campaigns that never completed are left out
    (they have no result) and the manifest says how many were missing, so an imported partial run
    can never pass itself off as a finished one."""
    from .reporting import ExperimentReport, campaign_from_dict  # local import: reporting must not depend on this module

    run = store.get_run(run_id)
    if run is None:
        raise KeyError(run_id)
    rows = store.get_campaigns(run_id)
    campaigns = [campaign_from_dict(c["result"]) for c in rows if c["status"] == "complete" and c["result"]]
    saved = store.get_manifest(run_id)
    if saved:
        experiment_id, manifest = saved["experiment_id"], dict(saved["manifest"])
    else:
        experiment_id = f"exp-rebuilt-{run_id}"
        manifest = {"note": "No manifest was saved for this run (it did not finish); rebuilt from stored campaigns only.",
                    "config": run["config"]}
    manifest["rebuilt_from_run_store"] = {
        "db_path": str(store.db_path), "run_id": run_id, "run_status": run["status"],
        "campaigns_complete": len(campaigns), "campaigns_incomplete": len(rows) - len(campaigns),
    }
    return ExperimentReport(experiment_id=experiment_id, manifest=manifest, campaigns=campaigns)
