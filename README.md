# Red Team vs. Blue Team for Tool-Using Agents

SJSU CMPE 295A capstone. Advisor: Prof. Vijay Eranti. Team: Yashaswini Dinesh, Prachi Gupta, Jaya Vyas, Keerthana Muralidharan.

**Repository name:** `cmpe295a-red-team-blue-team-prototype`

"AgentGuard" is the prototype platform/codebase name used inside the repository; the official project title above and the CMPE 295A repository name identify the work in university-facing materials.

This repository is a reproducible harness for comparing defenses against prompt injection in tool-using agents. Its research contribution is the comparison protocol, not any single attack or defense: every defense faces the same attacker under the same attempt budget, the attacker learns only whether its last attempt worked, and attack success is always reported next to how much legitimate work the defense still allows.

**Read this before quoting any number.** With the default settings every result is produced by a simulated target agent and a demonstration classifier. Those runs show that the machinery works and that the metrics behave sensibly. They are not evidence about how real models or real defenses perform, and the platform says so on every screen and every export.

## What is real, simulated, and untested

| Part | Status |
| --- | --- |
| Environments (email, documents, calendar), tool permissions, state snapshots | Implemented and tested. In-memory simulations; nothing touches a real account. |
| Scenario schema, validator, 9 hand-authored scenarios | Implemented and tested. Scenarios are unreviewed. |
| Oracle (decides success from environment state only) | Implemented and tested, including attempts to fool it with text. |
| Four defenses: baseline, defensive prompt, classifier, tool validator | Implemented and tested. The classifier is a hand-tuned regex demonstration, not a trained model. |
| Feedback-only attacker boundary, matched budgets, independent histories | Implemented and enforced by tests. |
| Static attacker and adaptive demo attacker | Implemented. The adaptive one is a deterministic fixture, labeled as such. |
| Target agent | Simulated by default (deterministic, calibrated to six known payload styles). |
| Statistics, reporting, reproducibility manifest, CLI, web dashboard | Implemented and tested. Dashboard flow verified in headless Chromium. |
| Local-model attacker (Ollama), real-model target, hosted classifier adapter | Implemented and unit-tested against mocked responses. **Never run against a live model server.** |
| Trained classifier, real model results, hosted-classifier pricing, a model-adapter health-check, authentication | Not built. |
| A scenario-generation prototype (`scripts/generate_scenario.py`), quarantined from the reviewed suite until a human approves it (`scripts/approve_generated_scenario.py`) | Built and tested; see `docs/SCENARIO_REVIEW.md`. |
| Local run persistence and crash recovery (SQLite, no external server) | Built and tested; see below. |

`docs/LIMITATIONS.md` explains each of these in detail.

## Quick start

Open a terminal inside this folder and run one command. On macOS use `python3 start.py`. On Windows use `py -3 start.py`.

It checks your Python version, runs the automated tests, runs a sample experiment, and opens the dashboard in your browser. Leave that terminal window open while you use the dashboard, and press Control+C in it to stop. If port 8000 is busy it picks the next free one and tells you.

There are shortcuts for the individual steps: `python3 start.py dashboard` opens the dashboard without the checks (the fast way back in), `python3 start.py test` runs only the tests, and `python3 start.py demo` runs only the sample experiment. Add `--no-browser` to stop it opening a tab, or `--port 8001` to choose where to start looking for a free port.

## Requirements and setup

Python 3.9 or newer. There is nothing else to install: the platform uses only the standard library. Check what you have with `python3 --version` (`py -3 --version` on Windows). If macOS does not find `python3`, or reports a version older than 3.9, install a current Python from python.org. On Windows, install Python from python.org and tick "Add python.exe to PATH" during setup.

It was tested on Linux under Python 3.9, 3.10 and 3.12, and under a non-UTF-8 default text encoding as a stand-in for Windows. It has not yet been run on macOS or Windows themselves. `pip install .` makes the `rtbt` package importable but does not install entry-point scripts, so run everything from this folder.

The commands below use `python3`. On Windows, type `py -3` instead (or `python` if the `py` command is missing). Paste one command at a time and without any trailing notes: the macOS Terminal treats a `#` note on the same line as extra arguments and fails with "unrecognized arguments".

## Run the tests

```
python3 -m unittest discover -s tests
```

The report should end with `OK` (currently 156 tests, about eight seconds). The tests cover the feedback boundary, matched budgets, seed reproducibility, environment reset, oracle correctness, failure handling, adversarial payloads, the network allowlist, the web API, the launcher, crash recovery, the scenario validator and generator, cost accounting, and the evidence-status taxonomy.

## Run an experiment from the command line

The first command below runs the default sweep over every scenario, and the second runs the small sample from a config file:

```
python3 run_demo.py
python3 run_demo.py --config configs/quick_demo.json
```

You can also choose everything yourself, on one line:

```
python3 run_demo.py --scenarios email-summary-exfil,cal-schedule-sync --defenses baseline,classifier,tool_validator --attack-modes static,adaptive_demo --budget 20 --seeds 1,2,3,4,5
```

The run prints a matched-budget check, a comparison table, aggregated statistics with confidence intervals, and the static-versus-adaptive comparison. It writes a full JSON report and a CSV table to `results/`. The JSON keeps every round and tool call for audit, so a full sweep of 360 campaigns is about 23 MB (under 1 MB gzipped); the CSV is the compact one-row-per-campaign table.

## Run the dashboard

```
python3 run_web.py --port 8000 --open
```

The `--open` option opens your browser once the server is ready; leave it off to open http://127.0.0.1:8000 yourself. The server binds to 127.0.0.1 only and has no authentication, so do not expose it to a network.

Every run is also persisted to a local SQLite database (`results/runs.db` by default, or wherever `RTBT_RUNS_DB` points). If the server is killed mid-run, restarting it will find that run marked `interrupted` (visible via `GET /api/experiments/interrupted`) and let you resume it (skipping whatever already completed), restart it from scratch, or abandon it, via `POST /api/experiments/<id>/recover`. This is API-only for now — there is no dashboard button for it yet. Downloading the JSON report from the Provenance view remains the easiest way to keep a copy of a finished run.

The dashboard has five views. Configure chooses scenarios, defenses, attackers, budget and seeds. Live run shows every round as it happens. Compare shows the security-versus-usability trade-off, all metrics with intervals, and whether adaptation helped the attacker. Audit opens any campaign and any round down to the payload, each tool call, and each defense decision. Provenance lists which components were simulated and holds the reproducibility manifest.

## Using real models

Install Ollama separately, pull a model, and start it. Then copy `configs/local_model_attacker_example.json` or `configs/real_target_example.json`, replace the placeholder model name, and fill in the manifest fields (revision, license, quantization, hardware). The platform will only talk to `127.0.0.1`, `localhost` and `::1` unless you extend the allowlist with the `RTBT_NETWORK_ALLOWLIST` environment variable. Because these paths have only been tested against mocks, expect to debug the first live run, and check the Audit view to confirm the model is producing what you think it is.

## Layout

```
start.py                    one-command launcher (checks, tests, sample run, dashboard)
run_demo.py, run_web.py     command-line and dashboard entry points
Prototype_Setup_and_Run_Guide.docx    non-technical setup walkthrough (macOS/Windows)
src/rtbt/                   the platform (see docs/ARCHITECTURE.md)
scenarios/                  16 scenario files and suite.json (suite 0.2.0)
scripts/                    scenario validation, generation, and human-approval helpers
configs/                    example experiment configs
web/                        dashboard (plain HTML, CSS, JavaScript)
tests/                      unittest suite
docs/                       architecture, threat model, protocol, schema, limitations
results/                    sample exports
```

## Where each team member's work plugs in

The attacker work (Yashaswini) goes in `src/rtbt/attackers/`: subclass `Attacker`, and receive only an `AttackBrief` and a boolean. The harness and comparison engine (Prachi) are `harness.py`, `metrics.py`, `statistics.py` and `reporting.py`. Defenses (Jaya) go in `defenses.py` by implementing the three hooks on `Defense`. Environments and scenarios (Keerthana) are `src/rtbt/environments/` and `scenarios/`, documented in `docs/SCENARIO_SCHEMA.md`.

## Documents

- `docs/EXPERIMENT_PROTOCOL.md`: what an experiment is, what is measured, and how conclusions are drawn.
- `docs/THREAT_MODEL.md`: attacker capabilities, what defenses may see, and what is out of scope.
- `docs/ARCHITECTURE.md`: how the pieces fit and why the boundaries are where they are.
- `docs/SCENARIO_SCHEMA.md`: field-by-field scenario reference and how to add a scenario.
- `docs/SCENARIO_REVIEW.md`: how a scenario goes from unreviewed to reviewed, and what `scripts/validate_scenarios.py` checks.
- `docs/LIMITATIONS.md`: what this platform cannot yet tell you.
- `docs/ROADMAP.md`: what's done, what's next, and what's future work, kept distinct.
- `docs/RESEARCH_QUESTIONS.md` and `docs/HYPOTHESES.md`: the questions this platform is built to answer, and what would count as an answer.
- `docs/STATISTICAL_ANALYSIS_PLAN.md`: exactly which interval method is used where, and why.
- `docs/REAL_MODEL_VALIDATION_PLAN.md`: the checklist for the biggest remaining gap — nothing has been run against a live model yet.
- `docs/RESULT_INTERPRETATION_GUIDE.md`: how to read what this platform produces without over- or under-claiming.
- `docs/PORTABILITY_CHECKLIST.md`: signable proof (currently unsigned) that macOS and Windows actually work.
- `docs/REQUIREMENTS_TRACEABILITY.md`: section-by-section status against the full build specification.
- `CHANGELOG.md`: what changed from the original prototype this was rebuilt from.
