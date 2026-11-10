# Limitations

This document lists what the platform cannot yet tell you. It is meant to be read alongside any result, and to be quoted in the report.

## The simulated target agent is not a model

The default target agent, `SimulatedTargetAgent`, decides whether to follow an injected instruction by comparing the retrieved text against six known payload styles (direct override, authority spoof, workflow justification, encoded address, multi-step redirect, task continuation) and rolling a deterministic hash-based die against a hand-set compliance probability for that style. Anything it does not recognize gets a generic probability of 0.30, and text with no signal at all gets a floor near zero.

Two consequences follow. First, the simulation was calibrated against the same six templates the static and adaptive demo attackers generate, so it will look better at "understanding" them than any real model would understand free-form text from a language-model attacker. Second, the compliance numbers are assumptions, not measurements. A result such as "the defensive prompt reduced attack success by 30 points" is partly a statement about the size of the penalty coded into the simulation. The harness, oracle, and statistics are exercised honestly by this agent; the numbers it produces say nothing about real susceptibility.

## The demonstration classifier is a regex list

The default classifier scores retrieved text against six weighted regular-expression groups and blocks above a threshold of 3.0. The weights were tuned by hand on the demonstration payloads. It will catch layered, obvious injections and miss quiet ones, and how it fares against the adaptive demo attacker mostly reflects how the fixture's tactics line up with those patterns. A real content classifier is a different object with different failure modes. `HttpClassifierAdapter` can call a hosted classifier on an allowlisted local endpoint, and it refuses to fall back to the demo regex if the call fails, but it has never been pointed at a real classifier.

## Model integrations are untested against live models

The local-model attacker (`attackers/local_model.py`), the real-model target (`target_agents/real_model.py`) and the HTTP classifier adapter were written against the Ollama-style request and response format. They are covered by unit tests using mocked network responses, including timeouts, refusals, empty and oversized output. None of them has been run against a running model server. The real-model target extracts tool calls from model output with a JSON pattern match, which is fragile and will need adjustment for whichever model is used. Treat the first live run as debugging, not data collection.

## The adaptive attacker is a fixture

`AdaptiveDemoAttacker` walks through its six tactics in order, moving on after each failure and staying put after a success. It exists so the harness can demonstrate adaptation deterministically. It is not a research attacker, and the H1 comparison it produces (adaptive versus static) is a demonstration of the paired analysis, not a finding.

## Scenarios are few, hand-written, and unreviewed

There are sixteen scenarios (suite 0.2.0: fourteen attackable, two benign-only) across three simulated environments, all written by the team and marked `unreviewed`; every one passes scripts/check_solvability.py (docs/ORACLE_HAND_TRACE.md). They have not been checked against a published benchmark or reviewed by anyone outside the team. Three were designed to show specific effects: a calendar policy that omits a legitimate external partner (so the tool validator stops the attack but also blocks the real task), an email look-alike address inside a trusted domain (so a domain-based policy fails exactly like no defense), and a document-sharing scenario with a correct policy (so the validator stops the attack at no utility cost). Those effects are pinned by tests and are properties of the scenario design, not discoveries.

A scenario-generation prototype now exists (`scripts/generate_scenario.py`, `scripts/approve_generated_scenario.py`) but is deliberately quarantined: it writes only to `scenarios/_generated/`, which the platform cannot see, until a named human reviewer explicitly approves a candidate. See `docs/SCENARIO_REVIEW.md`. Only one template exists, and no generated scenario has been used in a real comparison.

## Environments are in-memory simulations

Sending an email appends to a list; sharing a document edits a dictionary. This keeps runs fast, deterministic and safe, but it also means there is no latency, no partial failure, no rate limiting and no real permission model to reason about. Scopes are checked by the environment, not by a real identity system.

## Statistics are deliberately modest

Confidence intervals use a normal approximation (with an optional bootstrap) and appear only when at least three independent campaigns exist; below that the platform reports the mean and says why there is no interval. Each seeded campaign counts as one observation and the rounds inside it are never treated as independent. There is no correction for comparing many defenses and scenarios at once. The pooled "all scenarios" view counts each scenario and seed once, so its intervals include scenario-to-scenario spread as well as run-to-run noise. The paired adaptive-versus-static comparison reports a direction only when its interval excludes zero and otherwise reports "no detectable difference", which with five seeds usually means "not enough data", not "no effect".

## Metric definitions to keep in mind

The benign block rate counts harmless control rounds in which a defense withheld content or refused a write. Blocked legitimate work during attack rounds shows up in the legitimate-task-completion rate instead. Attempts to first success is `None` (censored) when an attacker never succeeded within its budget; it is never reported as zero. Invalid rounds, such as an attacker timeout, are excluded from every rate and counted separately, and campaigns with invalid rounds are listed under Provenance.

## Reproducibility has limits

With the simulated target and the built-in attackers, the same configuration and seeds reproduce identical rounds; the test suite checks this. Runs with real models are only as reproducible as the model, its sampling settings, and its hardware allow, even with a fixed seed. The manifest records model revision, quantization, temperature and hardware so that differences can be explained, but it cannot make them disappear.

## Threat coverage is narrow

The platform models one attack path: a single injected string inside content the agent retrieves with a read tool, aimed at getting the agent to perform one unauthorized write. Multi-turn social engineering, attacks through web browsing, memory poisoning, tool-description poisoning, and attackers who can see defense internals are out of scope. See `docs/THREAT_MODEL.md`.

## Dashboard and server

The server keeps active run objects in memory and persists run state to a local SQLite database for restart recovery. It has no authentication and binds to 127.0.0.1 only. The standard-library HTTP server and local database are suitable for one person on one machine, not a shared or production deployment. The dashboard flow was verified in headless Chromium on Linux at desktop and phone widths; it has not been tested in other browsers. The whole platform was tested on Linux under Python 3.9, 3.10 and 3.12, and under a non-UTF-8 default text encoding as a stand-in for Windows, but it has not been run on macOS or Windows themselves, so the launcher and the commands in the README are unproven on those systems.

## Zero third-party dependencies is a choice

NumPy and SciPy were available in the development environment and were deliberately not used. Keeping the platform standard-library-only means a teammate can run it with nothing installed and no version conflicts, and it keeps the trusted code small enough to audit. The cost is hand-written statistics that are simpler than what SciPy offers. If the analysis outgrows them, adding a dependency for the analysis layer only (not the harness) is the sensible next step.
