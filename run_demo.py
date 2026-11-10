#!/usr/bin/env python3
"""Command-line entrypoint for AgentGuard / Red Team vs. Blue Team for Tool-Using Agents.

Usage:
    python3 run_demo.py                                   # default demo sweep
    python3 run_demo.py --config configs/quick_demo.json   # from a config file
    python3 run_demo.py --scenarios email-summary-exfil --defenses baseline,classifier \
        --attack-modes static,adaptive_demo --budget 20 --seeds 1,2,3
    python3 run_demo.py --config configs/quick_demo.json --db results/runs.db      # checkpoint every campaign
    python3 run_demo.py --db results/runs.db --resume <run_id>                      # finish an interrupted run
    python3 run_demo.py --db results/runs.db --list-runs                            # see what the store holds

With --db, every finished campaign is written to the SQLite run store immediately, so a run that
dies part-way (a closed laptop, an expired Kaggle/Colab GPU session) can be resumed later with
--resume, on the same or a different machine, without repeating finished campaigns.

Always prints the "Demonstration data only" warning unless every campaign used real
model components. Exports full JSON and a flat CSV comparison table to results/.
"""
from __future__ import annotations

import argparse
import csv
import json
import sys
import uuid
from pathlib import Path

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from rtbt.attackers.local_model import ModelConfig  # noqa: E402
from rtbt.config_io import config_from_dict, config_to_dict  # noqa: E402
from rtbt.persistence import STATEFUL_ATTACK_MODES, RunStore  # noqa: E402
from rtbt.reporting import ExperimentReport, campaign_from_dict  # noqa: E402
from rtbt.harness import ExperimentConfig, ExperimentRunner  # noqa: E402
from rtbt.scenario_registry import load_suite  # noqa: E402
from rtbt.util import sha256_file, use_utf8_output, utc_now_iso  # noqa: E402
from rtbt.statistics import comparison_by_scenario_defense, excluded_runs_report, static_vs_adaptive  # noqa: E402
from rtbt.target_agents.real_model import RealTargetConfig  # noqa: E402

DEFAULT_SCENARIOS_DIR = ROOT / "scenarios"
DEFAULT_RESULTS_DIR = ROOT / "results"


def parse_args() -> argparse.Namespace:
    p = argparse.ArgumentParser(description=__doc__, formatter_class=argparse.RawDescriptionHelpFormatter)
    p.add_argument("--config", type=str, default=None, help="Path to a JSON experiment config.")
    p.add_argument("--scenarios", type=str, default=None, help="Comma-separated scenario ids (default: suite primary set).")
    p.add_argument("--defenses", type=str, default="baseline,defensive_prompt,classifier,tool_validator")
    p.add_argument("--attack-modes", type=str, default="static,adaptive_demo")
    p.add_argument("--budget", type=int, default=20)
    p.add_argument("--seeds", type=str, default="1,2,3")
    p.add_argument("--target-mode", type=str, default="simulated", choices=["simulated", "real_model"])
    p.add_argument("--suite-dir", type=str, default=str(DEFAULT_SCENARIOS_DIR))
    p.add_argument("--out-dir", type=str, default=str(DEFAULT_RESULTS_DIR))
    p.add_argument("--ollama-model", type=str, default=None, help="Enable adaptive_ollama with this model name.")
    p.add_argument("--ollama-abliterated", action="store_true")
    p.add_argument("--model-failure-policy", type=str, default="mark_invalid",
                   choices=["mark_invalid", "abort_campaign", "restart_as_separate_demo_campaign"],
                   help="What to do when a model-backed attacker becomes unavailable mid-campaign.")
    p.add_argument("--db", type=str, default=None,
                   help="SQLite run store. Each finished campaign is saved immediately so the run can be resumed.")
    p.add_argument("--run-id", type=str, default=None, help="Name for a new run in --db (default: random 12-hex id).")
    p.add_argument("--resume", type=str, default=None, metavar="RUN_ID",
                   help="Finish an unfinished run stored in --db: completed campaigns are reused, the rest are run.")
    p.add_argument("--list-runs", action="store_true", help="List runs stored in --db and exit.")
    return p.parse_args()


def build_config(args: argparse.Namespace) -> ExperimentConfig:
    if args.config:
        return config_from_dict(json.loads(Path(args.config).read_text(encoding="utf-8")))

    attack_modes = tuple(args.attack_modes.split(","))
    model_config = None
    if args.ollama_model or "adaptive_ollama" in attack_modes:
        model_config = ModelConfig(name=args.ollama_model or "unspecified", abliterated=args.ollama_abliterated)
    return ExperimentConfig(
        defenses=tuple(args.defenses.split(",")), attack_modes=attack_modes, attack_budget=args.budget,
        seeds=tuple(int(s) for s in args.seeds.split(",")), target_mode=args.target_mode,
        scenario_ids=tuple(args.scenarios.split(",")) if args.scenarios else None, model_config=model_config,
        model_failure_policy=args.model_failure_policy,
    )


def run_with_store(store: RunStore, run_id: str, runner: ExperimentRunner, *, reused: list,
                   skip_ids: frozenset, force_ids: frozenset) -> ExperimentReport:
    """Run the experiment, checkpointing every campaign into the store as it finishes. A Ctrl-C
    or a killed GPU session leaves the run 'running'/'interrupted' with every finished campaign
    already saved; --resume picks up from there."""
    def emit(event: dict) -> None:
        if event.get("type") == "campaign_start":
            store.record_campaign_start(
                run_id, event["campaign_id"], scenario_id=event["scenario_id"], defense_id=event["defense_id"],
                attack_mode=event["attack_mode"], target_mode=runner.config.target_mode, seed=event["seed"],
                attack_budget=event["attack_budget"])

    def on_campaign_complete(campaign) -> None:
        store.record_campaign_complete(run_id, campaign.campaign_id, campaign.to_dict())

    try:
        fresh = runner.run(emit=emit, on_campaign_complete=on_campaign_complete,
                           skip_campaign_ids=skip_ids, force_new_id_for=force_ids)
    except KeyboardInterrupt:
        store.update_run_status(run_id, "interrupted")
        store.log_recovery_decision(run_id, "marked_interrupted_on_startup",
                                    "CLI run stopped by KeyboardInterrupt; finished campaigns are saved. "
                                    f"Resume with: run_demo.py --db {store.db_path} --resume {run_id}")
        print(f"\nInterrupted. Finished campaigns are saved. Resume with:\n  "
              f"python3 run_demo.py --db {store.db_path} --resume {run_id}")
        raise SystemExit(130)
    manifest = dict(fresh.manifest)
    manifest["run_store"] = {"db_path": str(store.db_path), "run_id": run_id,
                             "reused_campaign_ids": sorted(c.campaign_id for c in reused)}
    report = ExperimentReport(experiment_id=fresh.experiment_id, manifest=manifest, campaigns=list(reused) + fresh.campaigns)
    store.save_manifest(run_id, report.experiment_id, report.manifest)
    store.update_run_status(run_id, "cancelled" if runner.cancel_token.is_cancelled() else "complete")
    return report


def prepare_resume(store: RunStore, run_id: str) -> tuple[ExperimentConfig, list, frozenset, frozenset]:
    run = store.get_run(run_id)
    if run is None:
        raise SystemExit(f"No run '{run_id}' in {store.db_path}. Use --list-runs to see stored runs.")
    if run["status"] in ("complete", "abandoned"):
        raise SystemExit(f"Run '{run_id}' is {run['status']!r}; there is nothing to resume.")
    config = config_from_dict(run["config"])
    plan = store.recovery_plan(run_id)
    rows = {c["campaign_id"]: c for c in store.get_campaigns(run_id)}
    reused = [campaign_from_dict(rows[cid]["result"]) for cid in plan["completed_campaign_ids"] if rows[cid]["result"]]
    skip_ids = frozenset(c.campaign_id for c in reused)
    force_ids = frozenset(plan["incomplete_needs_new_id"])
    store.log_recovery_decision(
        run_id, "resume",
        f"Resumed in place by run_demo.py: reused {len(skip_ids)} completed campaign(s); "
        f"{len(force_ids)} incomplete stateful campaign(s) ({', '.join(STATEFUL_ATTACK_MODES)}) re-run under a new id.")
    store.update_run_status(run_id, "running")
    return config, reused, skip_ids, force_ids


def print_comparison_table(rows: list[dict]) -> None:
    headers = ["scenario_id", "attack_mode", "defense_id", "campaign_average_asr", "final_window_asr",
               "legitimate_task_completion_rate", "safe_utility_rate", "benign_block_rate",
               "unauthorized_action_attempted_rate", "unauthorized_action_blocked_rate", "unauthorized_action_executed_rate"]
    widths = {h: max(len(h), 8) for h in headers}
    print(" | ".join(h.ljust(widths[h]) for h in headers))
    print("-+-".join("-" * widths[h] for h in headers))
    for row in rows:
        cells = []
        for h in headers:
            v = row.get(h)
            cells.append((f"{v:.3f}" if isinstance(v, float) else str(v)).ljust(widths[h]))
        print(" | ".join(cells))


def export(report, out_dir: Path) -> tuple[Path, Path]:
    out_dir.mkdir(parents=True, exist_ok=True)
    json_path = out_dir / f"{report.experiment_id}.json"
    json_path.write_text(json.dumps(report.to_dict(), separators=(",", ":")), encoding="utf-8")  # compact: full audit detail is large

    csv_path = out_dir / f"{report.experiment_id}.csv"
    rows = report.comparison_table()
    if rows:
        with csv_path.open("w", newline="", encoding="utf-8") as f:
            writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
            writer.writeheader()
            writer.writerows(rows)

    # Hashes recorded in a SEPARATE sidecar file, never inside the artifact each hash covers —
    # hashing a file and then writing that hash back into the same file is circular and would
    # make the recorded hash describe a version of the file that no longer exists.
    sidecar_path = out_dir / f"{report.experiment_id}.hashes.json"
    sidecar_path.write_text(json.dumps({
        "json_report": {"path": json_path.name, "sha256": sha256_file(json_path)},
        "csv_comparison": {"path": csv_path.name, "sha256": sha256_file(csv_path)} if csv_path.exists() else None,
        "generated_at": utc_now_iso(),
    }, indent=2), encoding="utf-8")
    return json_path, csv_path


def main() -> None:
    use_utf8_output()
    args = parse_args()
    if (args.resume or args.list_runs or args.run_id) and not args.db:
        raise SystemExit("--resume, --list-runs and --run-id need --db PATH (the SQLite run store).")
    store = RunStore(args.db) if args.db else None
    if args.list_runs:
        for r in store.list_runs():
            done = sum(1 for c in store.get_campaigns(r["run_id"]) if c["status"] == "complete")
            print(f"{r['run_id']}  {r['status']:11}  campaigns_complete={done}  updated={r['updated_at']}")
        return

    suite = load_suite(args.suite_dir)
    reused: list = []
    skip_ids: frozenset = frozenset()
    force_ids: frozenset = frozenset()
    if args.resume:
        run_id = args.resume
        config, reused, skip_ids, force_ids = prepare_resume(store, run_id)
        print(f"Resuming run {run_id}: {len(reused)} campaign(s) already complete and reused.")
    else:
        config = build_config(args)
        run_id = args.run_id or uuid.uuid4().hex[:12]
        if store:
            config.validate(suite)
            store.create_run(run_id, config_to_dict(config))
            print(f"Run id {run_id} — checkpointing every campaign to {store.db_path}")

    print(f"Suite '{suite.suite_id}' v{suite.version} — {len(suite.scenarios)} scenario(s) loaded "
          f"({len(suite.primary())} in the primary set).")
    print(f"Running: defenses={config.defenses} attack_modes={config.attack_modes} "
          f"budget={config.attack_budget} seeds={config.seeds} target_mode={config.target_mode}\n")

    runner = ExperimentRunner(suite=suite, config=config)
    if store:
        report = run_with_store(store, run_id, runner, reused=reused, skip_ids=skip_ids, force_ids=force_ids)
    else:
        report = runner.run()

    prov = report.provenance_summary()
    if prov["demonstration_warning"]:
        print("=" * 78)
        print(prov["demonstration_warning"].upper())
        print(f"Component mix: {prov['component_mix']} "
              f"(simulated_target={prov['simulated_target_campaigns']}, "
              f"real_target={prov['real_target_campaigns']}, real_attacker={prov['real_attacker_campaigns']})")
        demo = [f"{c['role']}: {c['name']}" for c in prov["components"] if c["is_demonstration"]]
        print("Demonstration components: " + "; ".join(demo))
        n_measured = sum(1 for c in report.campaigns if c.evidence_status == "measured_result")
        print(f"Evidence status: {n_measured} of {len(report.campaigns)} campaigns are eligible as research evidence (measured_result); the rest are simulated_result.")
        print("=" * 78 + "\n")

    unmatched = [m for m in report.matched_budget_report() if not m["matched"]]
    if unmatched:
        print("WARNING — matched-budget check FAILED for:")
        for m in unmatched:
            print(f"  {m['scenario_id']} / {m['attack_mode']}: {m['detail']}")
        print()

    print_comparison_table(report.comparison_table())

    if len(config.seeds) >= 1:
        print("\n-- Aggregated ASR across seeds (campaign_average_asr) --")
        for row in comparison_by_scenario_defense(report.primary_campaigns, "campaign_average_asr"):
            ci = f"[{row['ci_95_low']:.3f}, {row['ci_95_high']:.3f}] ({row['ci_method']})" if row["ci_95_low"] is not None else "n/a"
            mean_s = f"{row['mean']:.3f}" if row["mean"] is not None else "n/a"
            print(f"  {row['scenario_id']:28} {row['attack_mode']:14} {row['defense_id']:16} "
                 f"n={row['n']} mean={mean_s} 95% CI={ci}")

        if len(set(config.attack_modes) & {"static", "adaptive_demo", "adaptive_ollama"}) >= 2 and "static" in config.attack_modes:
            adaptive_mode = next((m for m in config.attack_modes if m != "static"), None)
            if adaptive_mode:
                print(f"\n-- H1: static vs {adaptive_mode} (paired by seed, matched budget) --")
                for row in static_vs_adaptive(report.primary_campaigns, adaptive_mode=adaptive_mode):
                    print(f"  {row['scenario_id']:28} {row['defense_id']:16} {row['direction']}")

    excluded = excluded_runs_report(report.campaigns)  # fallbacks included here: audit visibility
    if report.fallback_campaigns:
        print(f"Demonstration-fallback campaigns (excluded from every comparison above): {[c.campaign_id for c in report.fallback_campaigns]}\n")
    if excluded:
        print(f"\n-- {len(excluded)} campaign(s) had invalid/excluded rounds --")
        for e in excluded:
            print(f"  {e['campaign_id']}: {e['attack_rounds_invalid']} invalid, status={e['status']}, errors={e['error_counts']}")

    json_path, csv_path = export(report, Path(args.out_dir))
    print(f"\nFull report:  {json_path}")
    print(f"Comparison CSV: {csv_path}")


if __name__ == "__main__":
    main()
