#!/usr/bin/env python3
"""Web API and dashboard for AgentGuard / Red Team vs. Blue Team for Tool-Using Agents.

    python3 run_web.py [--port 8000]

Then open http://127.0.0.1:8000. Zero third-party dependencies — the API is built on
``http.server`` from the standard library, matching the rest of the platform's
dependency policy (see docs/LIMITATIONS.md for the tradeoffs of that choice).
"""
from __future__ import annotations

import argparse
import csv
import io
import json
import mimetypes
import os
import re
import sys
import threading
import time
import uuid
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from pathlib import Path
from urllib.parse import parse_qs, unquote, urlparse

ROOT = Path(__file__).resolve().parent
sys.path.insert(0, str(ROOT / "src"))

from rtbt.harness import CancelToken, ExperimentConfig, ExperimentRunner, derive_campaign_id  # noqa: E402
from rtbt.config_io import config_from_dict, config_to_dict  # noqa: E402
from rtbt.persistence import RunStore, rebuild_report  # noqa: E402
from rtbt.reporting import ExperimentReport, campaign_from_dict  # noqa: E402
from rtbt.scenario_registry import load_suite  # noqa: E402
from rtbt.schemas import ConfigurationError  # noqa: E402
from rtbt.statistics import excluded_runs_report, static_vs_adaptive, summarize  # noqa: E402

WEB_DIR = ROOT / "web"
SUITE_DIR = ROOT / "scenarios"
DB_PATH = Path(os.environ.get("RTBT_RUNS_DB", str(ROOT / "results" / "runs.db")))

_LOCK = threading.Lock()
RUNS: dict[str, dict] = {}  # run_id -> {"status", "events", "report", "error", "cancel_token", "campaigns_total"}
STORE = RunStore(DB_PATH)  # crash recovery: see src/rtbt/persistence.py


def _suite():
    return load_suite(str(SUITE_DIR))


def _new_run() -> str:
    return uuid.uuid4().hex[:12]


def _config_from_payload(payload: dict) -> ExperimentConfig:
    # One parser for both entry points (see rtbt/config_io.py). The dashboard's default budget
    # stays 15, as before; the CLI's is 20.
    return config_from_dict(payload, default_budget=15)


def load_persisted_runs(store: RunStore = None) -> list[str]:
    """Make finished runs from earlier processes visible again. A run that completed in a
    headless CLI or Kaggle/Colab session (run_demo.py --db) or before the dashboard was
    restarted is rebuilt from the run store, so every comparison, stats and CSV endpoint works on
    it exactly as on a live run. Only 'complete' and 'cancelled' runs are imported; interrupted
    runs stay on the recovery path instead of being shown as if they were finished."""
    store = store or STORE
    imported = []
    for r in store.list_runs():
        if r["status"] not in ("complete", "cancelled") or r["run_id"] in RUNS:
            continue
        try:
            report = rebuild_report(store, r["run_id"])
        except Exception as exc:  # one corrupt row must not stop the dashboard from starting
            print(f"Skipped stored run {r['run_id']}: {exc}", flush=True)
            continue
        with _LOCK:
            RUNS[r["run_id"]] = {"status": r["status"], "events": [], "report": report, "error": None,
                                 "cancel_token": CancelToken(), "campaigns_total": len(report.campaigns),
                                 "imported_from_store": True}
        imported.append(r["run_id"])
    return imported


def _background_run(run_id: str, config: ExperimentConfig, *, skip_campaign_ids=frozenset(), force_new_id_for=frozenset()) -> None:
    state = RUNS[run_id]
    suite = _suite()
    try:
        config.validate(suite)
        total = len(config.resolved_scenario_ids(suite)) * len(config.attack_modes) * len(config.seeds) * len(config.defenses)
        state["campaigns_total"] = total - len(skip_campaign_ids)  # a resume's skipped campaigns were already done before the crash

        def emit(event: dict) -> None:
            with _LOCK:
                state["events"].append({"ts": time.time(), **event})
            if event.get("type") == "campaign_start":
                STORE.record_campaign_start(
                    run_id, event["campaign_id"], scenario_id=event["scenario_id"], defense_id=event["defense_id"],
                    attack_mode=event["attack_mode"], target_mode=config.target_mode, seed=event["seed"],
                    attack_budget=event["attack_budget"])

        def on_campaign_complete(campaign) -> None:
            STORE.record_campaign_complete(run_id, campaign.campaign_id, campaign.to_dict())

        runner = ExperimentRunner(suite=suite, config=config, cancel_token=state["cancel_token"])
        report = runner.run(emit=emit, on_campaign_complete=on_campaign_complete,
                            skip_campaign_ids=skip_campaign_ids, force_new_id_for=force_new_id_for)
        if skip_campaign_ids:
            # A resumed run's report must include the campaigns reused from before the
            # interruption (copied into this run's own rows by the recover handler); before this
            # fix the report silently held only the campaigns re-run after the crash.
            reused = [campaign_from_dict(c["result"]) for c in STORE.get_campaigns(run_id)
                      if c["campaign_id"] in skip_campaign_ids and c["result"]]
            manifest = {**report.manifest, "reused_campaign_ids": sorted(c.campaign_id for c in reused)}
            report = ExperimentReport(experiment_id=report.experiment_id, manifest=manifest,
                                      campaigns=reused + report.campaigns)
        STORE.save_manifest(run_id, report.experiment_id, report.manifest)
        with _LOCK:
            state["report"] = report
            state["status"] = "cancelled" if state["cancel_token"].is_cancelled() else "complete"
        STORE.update_run_status(run_id, state["status"])
    except ConfigurationError as exc:
        with _LOCK:
            state["status"] = "error"
            state["error"] = str(exc)
        STORE.update_run_status(run_id, "error")
    except Exception as exc:  # pragma: no cover - defensive: surface any unexpected failure to the dashboard
        with _LOCK:
            state["status"] = "error"
            state["error"] = f"{type(exc).__name__}: {exc}"
        STORE.update_run_status(run_id, "error")


ROUTES: list[tuple[str, str, re.Pattern]] = [
    ("GET", "suite", re.compile(r"^/api/suite$")),
    ("GET", "run_list", re.compile(r"^/api/experiments$")),
    ("POST", "run_create", re.compile(r"^/api/experiments$")),
    ("GET", "run_status", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/status$")),
    ("GET", "run_events", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/events$")),
    ("GET", "run_comparison", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/comparison$")),
    ("GET", "run_stats", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/stats$")),
    ("GET", "run_summary", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/summary$")),
    ("GET", "run_csv", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/comparison\.csv$")),
    ("GET", "run_campaign", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/campaigns/(?P<campaign_id>[^/]+)$")),
    ("POST", "run_cancel", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/cancel$")),
    ("GET", "run_interrupted", re.compile(r"^/api/experiments/interrupted$")),
    ("GET", "run_recovery_info", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/recovery_info$")),
    ("POST", "run_recover", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)/recover$")),
    ("GET", "run_report", re.compile(r"^/api/experiments/(?P<run_id>[\w-]+)$")),
]


class Handler(BaseHTTPRequestHandler):
    server_version = "AgentGuardHTTP/0.2.2"

    def log_message(self, fmt: str, *args) -> None:  # quieter default logging
        sys.stderr.write(f"[web] {self.address_string()} - {fmt % args}\n")

    def _send_json(self, obj, status: int = 200) -> None:
        body = json.dumps(obj, default=str).encode("utf-8")
        self.send_response(status)
        self.send_header("Content-Type", "application/json")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    def _send_error_json(self, status: int, message: str) -> None:
        self._send_json({"error": message}, status=status)

    def _read_json_body(self) -> dict:
        length = int(self.headers.get("Content-Length", 0))
        if length == 0:
            return {}
        return json.loads(self.rfile.read(length).decode("utf-8"))

    def _match(self, method: str):
        path = urlparse(self.path).path
        for route_method, name, pattern in ROUTES:
            if route_method != method:
                continue
            m = pattern.match(path)
            if m:
                return name, m.groupdict()
        return None, {}

    # ---------------------------------------------------------------- static files
    def _serve_static(self) -> None:
        path = urlparse(self.path).path
        rel = "index.html" if path == "/" else path.lstrip("/")
        file_path = (WEB_DIR / rel).resolve()
        if WEB_DIR.resolve() not in file_path.parents and file_path != WEB_DIR.resolve():
            self._send_error_json(403, "Forbidden")
            return
        if not file_path.exists() or not file_path.is_file():
            self._send_error_json(404, "Not found")
            return
        content_type, _ = mimetypes.guess_type(str(file_path))
        body = file_path.read_bytes()
        self.send_response(200)
        self.send_header("Content-Type", content_type or "application/octet-stream")
        self.send_header("Content-Length", str(len(body)))
        self.end_headers()
        self.wfile.write(body)

    # ---------------------------------------------------------------- GET
    def do_GET(self) -> None:
        name, params = self._match("GET")
        if name is None:
            self._serve_static()
            return
        try:
            if name == "suite":
                suite = _suite()
                self._send_json({
                    "suite_id": suite.suite_id, "version": suite.version, "content_hash": suite.content_hash(),
                    "scenarios": [s.summary() for s in suite.scenarios],
                    "primary_ids": [s.id for s in suite.primary()],
                })
            elif name == "run_list":
                with _LOCK:
                    self._send_json([{"run_id": rid, "status": s["status"],
                                     "campaigns_done": len(s.get("report").campaigns) if s.get("report") else 0}
                                    for rid, s in RUNS.items()])
            elif name == "run_status":
                run_id = params["run_id"]
                state = RUNS.get(run_id)
                if state is None:
                    self._send_error_json(404, "Unknown run_id")
                    return
                with _LOCK:
                    self._send_json({
                        "run_id": run_id, "status": state["status"], "error": state.get("error"),
                        "campaigns_total": state.get("campaigns_total"),
                        "campaigns_done": len(state["report"].campaigns) if state.get("report") else None,
                        "events_count": len(state["events"]),
                        "recovered_from": state.get("recovered_from"), "reused_campaign_ids": state.get("reused_campaign_ids", []),
                    })
            elif name == "run_events":
                run_id = params["run_id"]
                state = RUNS.get(run_id)
                if state is None:
                    self._send_error_json(404, "Unknown run_id")
                    return
                since = int(parse_qs(urlparse(self.path).query).get("since", ["0"])[0])
                wanted = parse_qs(urlparse(self.path).query).get("types", [""])[0]
                wanted_types = {t for t in wanted.split(",") if t}
                with _LOCK:
                    raw = state["events"][since:]
                events = [e for e in raw if e.get("type") in wanted_types] if wanted_types else raw
                self._send_json({"events": events, "next_since": since + len(raw), "status": state["status"]})
            elif name == "run_report":
                run_id = params["run_id"]
                state = RUNS.get(run_id)
                if state is None:
                    self._send_error_json(404, "Unknown run_id")
                    return
                if state["status"] == "running":
                    self._send_json({"status": "running"})
                    return
                if state["status"] == "error":
                    self._send_error_json(500, state.get("error", "unknown error"))
                    return
                self._send_json(state["report"].to_dict())
            elif name == "run_comparison":
                state = self._require_report(params["run_id"])
                if state is None:
                    return
                self._send_json(state["report"].comparison_table())
            elif name == "run_interrupted":
                runs = STORE.list_runs(status="interrupted")
                for r in runs:
                    r["recovery_plan"] = STORE.recovery_plan(r["run_id"])
                    r["recovery_log"] = STORE.get_recovery_log(r["run_id"])
                self._send_json({"runs": runs})
            elif name == "run_recovery_info":
                run_id = params["run_id"]
                persisted = STORE.get_run(run_id)
                if persisted is None:
                    self._send_error_json(404, "Unknown run_id")
                    return
                state = RUNS.get(run_id, {})
                self._send_json({
                    "run_id": run_id, "recovered_from": state.get("recovered_from"),
                    "reused_campaign_ids": state.get("reused_campaign_ids", []),
                    "reused_campaigns_full_data": [c for c in STORE.get_campaigns(run_id) if c["campaign_id"] in state.get("reused_campaign_ids", [])],
                    "recovery_log": STORE.get_recovery_log(state.get("recovered_from")) if state.get("recovered_from") else STORE.get_recovery_log(run_id),
                    "note": "Reused campaigns are preserved here and in the full JSON export's underlying database, "
                            "but are not merged into this run's live Compare/statistics views — see docs/LIMITATIONS.md.",
                })
            elif name == "run_stats":
                state = self._require_report(params["run_id"])
                if state is None:
                    return
                report = state["report"]
                primary = report.primary_campaigns
                modes = {c.attack_mode for c in primary}
                adaptive = next((m for m in sorted(modes) if m != "static"), None)
                self._send_json({
                    **summarize(primary),
                    "static_vs_adaptive": static_vs_adaptive(primary, adaptive_mode=adaptive) if adaptive and "static" in modes else [],
                    "excluded_runs": excluded_runs_report(report.campaigns),  # fallbacks included: audit visibility, not comparison
                })
            elif name == "run_summary":
                state = self._require_report(params["run_id"])
                if state is None:
                    return
                report = state["report"]
                self._send_json({
                    "experiment_id": report.experiment_id, "manifest": report.manifest,
                    "provenance": report.provenance_summary(), "matched_budget": report.matched_budget_report(),
                    "campaigns": [{
                        "campaign_id": c.campaign_id, "scenario_id": c.scenario_id, "environment": c.environment,
                        "defense_id": c.defense_id, "attack_mode": c.attack_mode, "target_mode": c.target_mode,
                        "seed": c.seed, "attack_budget": c.attack_budget, "status": c.status, "metrics": c.metrics(),
                        "is_demo_fallback": c.is_demo_fallback, "fallback_of": c.fallback_of, "abort_reason": c.abort_reason,
                        "evidence_status": c.evidence_status, "eligible_as_research_evidence": c.eligible_as_research_evidence,
                        "cost": c.cost,
                    } for c in report.campaigns],
                    "fallback_campaigns": [c.campaign_id for c in report.fallback_campaigns],
                })
            elif name == "run_csv":
                state = self._require_report(params["run_id"])
                if state is None:
                    return
                rows = state["report"].comparison_table()
                buf = io.StringIO()
                if rows:
                    writer = csv.DictWriter(buf, fieldnames=list(rows[0].keys()))
                    writer.writeheader()
                    writer.writerows(rows)
                body = buf.getvalue().encode("utf-8")
                self.send_response(200)
                self.send_header("Content-Type", "text/csv; charset=utf-8")
                self.send_header("Content-Disposition", 'attachment; filename="comparison.csv"')
                self.send_header("Content-Length", str(len(body)))
                self.end_headers()
                self.wfile.write(body)
            elif name == "run_campaign":
                state = self._require_report(params["run_id"])
                if state is None:
                    return
                match = next((c for c in state["report"].campaigns if c.campaign_id == unquote(params["campaign_id"])), None)
                if match is None:
                    self._send_error_json(404, "Unknown campaign_id")
                    return
                self._send_json(match.to_dict())
            else:
                self._send_error_json(404, "Not found")
        except Exception as exc:  # pragma: no cover
            self._send_error_json(500, f"{type(exc).__name__}: {exc}")

    def _require_report(self, run_id: str):
        state = RUNS.get(run_id)
        if state is None:
            self._send_error_json(404, "Unknown run_id")
            return None
        if state["status"] == "running":
            self._send_error_json(409, "Run still in progress")
            return None
        if state["status"] == "error":
            self._send_error_json(500, state.get("error", "unknown error"))
            return None
        return state

    # ---------------------------------------------------------------- POST
    def do_POST(self) -> None:
        name, params = self._match("POST")
        try:
            if name == "run_create":
                payload = self._read_json_body()
                config = _config_from_payload(payload)
                config.validate(_suite())  # reject bad configs with a 400 now, not a silent failure later
                run_id = _new_run()
                STORE.create_run(run_id, config_to_dict(config))  # same shape the CLI writes, so either can resume it
                with _LOCK:
                    RUNS[run_id] = {"status": "running", "events": [], "report": None, "error": None,
                                    "cancel_token": CancelToken(), "campaigns_total": None}
                thread = threading.Thread(target=_background_run, args=(run_id, config), daemon=True)
                thread.start()
                self._send_json({"run_id": run_id, "status": "running"}, status=202)
            elif name == "run_cancel":
                run_id = params["run_id"]
                state = RUNS.get(run_id)
                if state is None:
                    self._send_error_json(404, "Unknown run_id")
                    return
                state["cancel_token"].cancel()
                self._send_json({"run_id": run_id, "cancelling": True})
            elif name == "run_recover":
                run_id = params["run_id"]
                old = STORE.get_run(run_id)
                if old is None:
                    self._send_error_json(404, "Unknown run_id")
                    return
                if old["status"] != "interrupted":
                    self._send_error_json(409, f"Run status is {old['status']!r}, not 'interrupted' — nothing to recover.")
                    return
                payload = self._read_json_body()
                decision = payload.get("decision")
                if decision not in ("resume", "restart", "abandon"):
                    self._send_error_json(400, "decision must be 'resume', 'restart', or 'abandon'")
                    return

                if decision == "abandon":
                    STORE.update_run_status(run_id, "abandoned")
                    STORE.log_recovery_decision(run_id, "abandon", "No new run started.")
                    self._send_json({"run_id": run_id, "decision": "abandon"})
                    return

                config = _config_from_payload(old["config"])
                config.validate(_suite())
                new_run_id = _new_run()
                skip_ids: frozenset = frozenset()
                force_ids: frozenset = frozenset()
                note = f"Recovered as new run {new_run_id}."
                if decision == "resume":
                    plan = STORE.recovery_plan(run_id)
                    skip_ids = frozenset(plan["completed_campaign_ids"])
                    force_ids = frozenset(plan["incomplete_needs_new_id"])
                    note += (f" Reused {len(skip_ids)} already-completed campaign(s) from before the interruption; "
                            f"{len(force_ids)} stateful campaign(s) restarted under a new id rather than continued.")
                STORE.log_recovery_decision(run_id, decision, note)
                STORE.create_run(new_run_id, old["config"])

                # Recovered campaigns that are simply being reused (skip_ids) never re-run, but the
                # new run's own record still needs them so its own audit trail is complete — never
                # silently borrowed from the old run's row without a copy of its own.
                for c in STORE.get_campaigns(run_id):
                    if c["campaign_id"] in skip_ids and c["result"]:
                        STORE.record_campaign_start(new_run_id, c["campaign_id"], scenario_id=c["scenario_id"],
                                                    defense_id=c["defense_id"], attack_mode=c["attack_mode"],
                                                    target_mode=c["target_mode"], seed=c["seed"], attack_budget=c["attack_budget"])
                        STORE.record_campaign_complete(new_run_id, c["campaign_id"], c["result"])

                with _LOCK:
                    RUNS[new_run_id] = {"status": "running", "events": [], "report": None, "error": None,
                                        "cancel_token": CancelToken(), "campaigns_total": None,
                                        "recovered_from": run_id, "reused_campaign_ids": list(skip_ids)}
                thread = threading.Thread(target=_background_run, args=(new_run_id, config),
                                          kwargs={"skip_campaign_ids": skip_ids, "force_new_id_for": force_ids}, daemon=True)
                thread.start()
                self._send_json({"run_id": new_run_id, "status": "running", "recovered_from": run_id,
                                 "decision": decision, "reused_campaigns": len(skip_ids)}, status=202)
            else:
                self._send_error_json(404, "Not found")
        except ConfigurationError as exc:
            self._send_error_json(400, str(exc))
        except Exception as exc:  # pragma: no cover
            self._send_error_json(500, f"{type(exc).__name__}: {exc}")


class Server(ThreadingHTTPServer):
    # On Windows this option lets a second server silently share a busy port, so keep it off there.
    allow_reuse_address = sys.platform != "win32"


def main() -> None:
    from rtbt.util import use_utf8_output
    use_utf8_output()
    parser = argparse.ArgumentParser()
    parser.add_argument("--port", type=int, default=8000)
    parser.add_argument("--host", type=str, default="127.0.0.1")
    parser.add_argument("--open", action="store_true", help="Open the dashboard in your browser once the server is ready.")
    args = parser.parse_args()

    try:
        server = Server((args.host, args.port), Handler)
    except OSError as exc:
        print(f"Could not start the dashboard on port {args.port}: {exc.strerror or exc}.")
        print(f"Another program is probably using that port. Try a different one, for example: --port {args.port + 1}")
        sys.exit(1)
    recovered = STORE.mark_stale_running_as_interrupted()
    if recovered:
        print(f"Found {len(recovered)} run(s) left 'running' from a previous process that did not "
              f"finish cleanly: {recovered}. See the Provenance view's recovery options, or "
              f"POST /api/experiments/<id>/recover with {{\"decision\": \"resume\"|\"restart\"|\"abandon\"}}.",
              flush=True)
    imported = load_persisted_runs()
    if imported:
        print(f"Loaded {len(imported)} finished run(s) from {DB_PATH}.", flush=True)
    url = f"http://{args.host}:{args.port}"
    print(f"Red Team vs. Blue Team prototype dashboard running at {url}", flush=True)
    print("Ctrl+C to stop.", flush=True)
    if args.open:
        # The socket is already listening, so the browser cannot arrive too early. It opens from a
        # background thread so a launcher that blocks can never stop the server from serving.
        threading.Thread(target=webbrowser.open, args=(url,), daemon=True).start()
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        # serve_forever() is running on this thread. Calling shutdown() here would deadlock,
        # because shutdown() waits for serve_forever() to finish on a different thread.
        print("\nShutting down.")
    finally:
        server.server_close()


if __name__ == "__main__":
    main()
