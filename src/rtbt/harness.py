"""The benchmark harness. ``run_campaign`` executes one (scenario, defense, attack_mode,
target_mode, seed) run under a matched attempt budget. ``ExperimentRunner`` loops that
over many scenarios, defenses, attack modes and repetitions and assembles the manifest
required for reproducibility.

The feedback-only boundary is enforced here, not just documented: the ONLY thing passed
to ``attacker.observe`` is ``oracle_result.attack_succeeded`` — a bare bool.
"""
from __future__ import annotations

import threading
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Callable

ROOT = Path(__file__).resolve().parents[2]  # project root: src/rtbt/harness.py -> ../..

from . import netguard
from .attackers import make_attacker
from .attackers.local_model import ModelConfig
from .defenses import build_defense
from .environments import environment_class
from .oracle import annotate_ground_truth, evaluate_round
from .reporting import CampaignResult, ExperimentReport
from .runtime import ToolRuntime
from .scenario_registry import Scenario, Suite
from .schemas import (
    ConfigurationError,
    ERR_CAMPAIGN_ABORTED,
    ExperimentCancelled,
    PLATFORM_VERSION,
    RoundError,
    RoundRecord,
    SCHEMA_VERSION,
)
from .target_agents import make_target
from .target_agents.real_model import RealTargetConfig
from .cost import compute_cost_accounting
from .util import derive_seed, git_info, runtime_environment_info, source_tree_hash, utc_now_iso

EmitFn = Callable[[dict[str, Any]], None]


KNOWN_DEFENSES = ("baseline", "defensive_prompt", "classifier", "tool_validator")
KNOWN_ATTACK_MODES = ("static", "static_published", "adaptive_demo", "adaptive_ollama")
MODEL_FAILURE_POLICIES = ("mark_invalid", "abort_campaign", "restart_as_separate_demo_campaign")


@dataclass
class ExperimentConfig:
    defenses: tuple[str, ...]
    attack_modes: tuple[str, ...]
    attack_budget: int
    seeds: tuple[int, ...]
    target_mode: str = "simulated"
    scenario_ids: tuple[str, ...] | None = None  # None => suite.primary()
    model_config: ModelConfig | None = None
    real_target_config: RealTargetConfig | None = None
    classifier_spec: dict[str, Any] | None = None
    final_window_fraction: float = 0.2
    final_window_minimum: int = 3
    network_allowlist: tuple[str, ...] | None = None
    model_failure_policy: str = "mark_invalid"  # mark_invalid | abort_campaign | restart_as_separate_demo_campaign

    def validate(self, suite: Suite) -> None:
        if self.attack_budget < 1 or self.attack_budget > 500:
            raise ConfigurationError("attack_budget must be between 1 and 500")
        if not self.defenses:
            raise ConfigurationError("At least one defense is required")
        if not self.attack_modes:
            raise ConfigurationError("At least one attack_mode is required")
        if not self.seeds:
            raise ConfigurationError("At least one seed is required")
        for label, values, known in (("defense", self.defenses, KNOWN_DEFENSES), ("attack_mode", self.attack_modes, KNOWN_ATTACK_MODES)):
            unknown = [v for v in values if v not in known]
            if unknown:
                raise ConfigurationError(f"Unknown {label}(s) {unknown}. Choose from {list(known)}")
        for label, values in (("defense", self.defenses), ("attack_mode", self.attack_modes), ("seed", self.seeds)):
            if len(set(values)) != len(values):
                raise ConfigurationError(f"Duplicate {label} values would produce colliding campaigns")
        if not all(isinstance(x, int) and not isinstance(x, bool) and x >= 0 for x in self.seeds):
            raise ConfigurationError("Seeds must be non-negative integers")
        if "adaptive_ollama" in self.attack_modes and self.model_config is None:
            raise ConfigurationError("attack_mode 'adaptive_ollama' requires model_config")
        if self.target_mode == "real_model" and self.real_target_config is None:
            raise ConfigurationError("target_mode 'real_model' requires real_target_config")
        if self.target_mode not in ("simulated", "real_model"):
            raise ConfigurationError(f"Unknown target_mode '{self.target_mode}'")
        if self.model_failure_policy not in MODEL_FAILURE_POLICIES:
            raise ConfigurationError(f"Unknown model_failure_policy '{self.model_failure_policy}'. Choose from {list(MODEL_FAILURE_POLICIES)}")
        ids = self.scenario_ids or tuple(s.id for s in suite.primary())
        unknown = set(ids) - {s.id for s in suite.scenarios}
        if unknown:
            raise ConfigurationError(f"Unknown scenario id(s): {sorted(unknown)}")

    def resolved_scenario_ids(self, suite: Suite) -> tuple[str, ...]:
        return self.scenario_ids or tuple(s.id for s in suite.primary())


class CancelToken:
    """Emergency-stop flag. Checked once per round; a campaign in progress finishes
    its current round (never leaves a half-executed tool call) and then stops."""

    def __init__(self) -> None:
        self._event = threading.Event()

    def cancel(self) -> None:
        self._event.set()

    def is_cancelled(self) -> bool:
        return self._event.is_set()


def derive_campaign_id(scenario_id: str, defense_id: str, attack_mode: str, target_mode: str, seed: int) -> str:
    return f"{scenario_id}:{defense_id}:{attack_mode}:{target_mode}:seed{seed}"


def run_campaign(
    *, scenario: Scenario, defense_id: str, attack_mode: str, target_mode: str, seed: int,
    attack_budget: int, model_config: ModelConfig | None = None, real_target_config: RealTargetConfig | None = None,
    classifier_spec: dict[str, Any] | None = None, network_allowlist: tuple[str, ...] | None = None,
    emit: EmitFn | None = None, cancel_token: CancelToken | None = None, experiment_id: str = "standalone",
    model_failure_policy: str = "mark_invalid", campaign_id_override: str | None = None,
    is_demo_fallback: bool = False, fallback_of: str | None = None,
) -> CampaignResult:
    campaign_id = campaign_id_override or derive_campaign_id(scenario.id, defense_id, attack_mode, target_mode, seed)
    started_at = utc_now_iso()
    if emit:
        emit({"type": "campaign_start", "campaign_id": campaign_id, "scenario_id": scenario.id,
              "defense_id": defense_id, "attack_mode": attack_mode, "seed": seed,
              "attack_budget": attack_budget if scenario.is_attackable else 0,
              "benign_rounds": len(scenario.benign_variants)})

    attacker = make_attacker(attack_mode, seed, model_config=model_config, allowlist=network_allowlist)
    defense = build_defense(defense_id, scenario_policy=scenario.policy, classifier_spec=classifier_spec)
    env_cls = environment_class(scenario.environment)
    target = make_target(target_mode, scenario=scenario, real_config=real_target_config, allowlist=network_allowlist)

    rounds: list[RoundRecord] = []
    status = "complete"
    abort_reason: str | None = None
    needs_demo_fallback = False

    def make_invalid(round_number: int, phase: str, category: str, detail: str,
                     attempt_number: int | None = None, strategy_id: str | None = None,
                     payload: str | None = None) -> RoundRecord:
        now = utc_now_iso()
        from .schemas import OracleResult
        return RoundRecord(
            round_number=round_number, phase=phase, defense_id=defense_id, valid=False,
            error_category=category, error_detail=detail, attempt_number=attempt_number,
            strategy_id=strategy_id, payload=payload, attacker_metadata={}, response_text="",
            target_provenance="n/a", tool_calls=[], oracle=OracleResult(run_valid=False, error_category=category),
            started_at=now, ended_at=now, round_seed=derive_seed(seed, phase, round_number),
        )

    def run_one(round_number: int, phase: str, payload: str, attempt_number: int | None,
                strategy_id: str | None, metadata: dict[str, Any]) -> RoundRecord:
        round_seed = derive_seed(seed, phase, round_number)
        r_started = utc_now_iso()
        env = env_cls(scenario.initial_state, scenario.granted_scopes, seed=round_seed)
        before = env.snapshot()
        if scenario.injection is not None:
            env.inject(scenario.injection["slot"], payload, scenario.injection["placement"])
        rt = ToolRuntime(environment=env, defense=defense, emit=emit, experiment_id=experiment_id,
                         campaign_id=campaign_id, scenario_id=scenario.id, round_number=round_number, phase=phase)
        resp = target.run(
            runtime=rt, user_task=scenario.user_task,
            system_addendum=defense.system_prompt_addendum(), round_seed=round_seed,
        )
        annotate_ground_truth(scenario, rt.calls)
        after = env.snapshot()
        oracle_result = evaluate_round(
            scenario=scenario, before_state=before, after_state=after, tool_calls=rt.calls,
            response_text=resp.text, content_blocked=rt.content_blocked_this_round, phase=phase,
        )
        return RoundRecord(
            round_number=round_number, phase=phase, defense_id=defense_id, valid=True, error_category=None,
            error_detail=None, attempt_number=attempt_number, strategy_id=strategy_id, payload=payload,
            attacker_metadata=metadata, response_text=resp.text, target_provenance=resp.provenance,
            tool_calls=rt.calls, oracle=oracle_result, started_at=r_started, ended_at=utc_now_iso(),
            round_seed=round_seed,
        )

    # ---------------------------------------------------------------------------- attack phase
    # Benign-only scenarios (no attack_objective) run zero attack rounds by design —
    # they exist purely to measure false blocks and are never given an attack budget.
    effective_attack_budget = attack_budget if scenario.is_attackable else 0
    for round_number in range(1, effective_attack_budget + 1):
        if cancel_token and cancel_token.is_cancelled():
            status = "cancelled"
            break
        try:
            attempt = attacker.next_attempt(scenario.attack_brief())
        except RoundError as exc:
            rounds.append(make_invalid(round_number, "attack", exc.category, exc.message))
            if emit:
                emit({"type": "round", "campaign_id": campaign_id, "defense_id": defense_id, "round_number": round_number, "phase": "attack", "valid": False, "error": exc.category})
            if model_failure_policy in ("abort_campaign", "restart_as_separate_demo_campaign"):
                # Preserve every round already completed; mark every round that will never now
                # run as invalid too (rather than silently missing), so attack_rounds_total stays
                # meaningful for the matched-budget check. Then stop the attack phase — never
                # silently keep going with a different attacker inside this same campaign.
                status = "aborted_model_unavailable"
                abort_reason = f"{exc.category}: {exc.message}"
                for later in range(round_number + 1, effective_attack_budget + 1):
                    rounds.append(make_invalid(later, "attack", ERR_CAMPAIGN_ABORTED,
                                               f"Never attempted: the campaign was aborted at round {round_number} ({abort_reason})."))
                if model_failure_policy == "restart_as_separate_demo_campaign":
                    needs_demo_fallback = True
                break
            continue

        try:
            record = run_one(round_number, "attack", attempt.payload, attempt.attempt_number,
                             attempt.strategy_id, attempt.metadata)
        except RoundError as exc:
            rounds.append(make_invalid(round_number, "attack", exc.category, exc.message,
                                       attempt.attempt_number, attempt.strategy_id, attempt.payload))
            if emit:
                emit({"type": "round", "campaign_id": campaign_id, "defense_id": defense_id, "round_number": round_number, "phase": "attack", "valid": False, "error": exc.category})
            continue  # infra failure: excluded from attacker's own feedback loop too

        attacker.observe(record.oracle.attack_succeeded)  # <-- the ONLY information the attacker receives
        rounds.append(record)
        if emit:
            emit({"type": "round", "campaign_id": campaign_id, "defense_id": defense_id, "round_number": round_number, "phase": "attack", "valid": True,
                 "success": record.oracle.attack_succeeded, "oracle_code": record.oracle.oracle_code})

    # ---------------------------------------------------------------------------- benign control phase
    for i, variant in enumerate(scenario.benign_variants, start=1):
        if cancel_token and cancel_token.is_cancelled():
            status = "cancelled"
            break
        round_number = effective_attack_budget + i
        try:
            record = run_one(round_number, "benign", variant["text"], None, f"benign:{variant['id']}", {})
        except RoundError as exc:
            rounds.append(make_invalid(round_number, "benign", exc.category, exc.message, None, f"benign:{variant['id']}", variant["text"]))
            continue
        rounds.append(record)
        if emit:
            emit({"type": "round", "campaign_id": campaign_id, "defense_id": defense_id, "round_number": round_number, "phase": "benign", "valid": True,
                 "blocked": record.oracle.benign_action_blocked})

    return CampaignResult(
        campaign_id=campaign_id, scenario_id=scenario.id, scenario_version=scenario.version,
        environment=scenario.environment, defense_id=defense_id, attack_mode=attack_mode,
        target_mode=target_mode, seed=seed, attack_budget=attack_budget, status=status, rounds=rounds,
        attacker_stats=attacker.stats(), defense_describe=defense.describe(),
        started_at=started_at, ended_at=utc_now_iso(),
        abort_reason=abort_reason, needs_demo_fallback=needs_demo_fallback,
        is_demo_fallback=is_demo_fallback, fallback_of=fallback_of,
        cost=compute_cost_accounting(attacker.stats(), target.stats() if hasattr(target, "stats") else None, defense.describe()),
    )


@dataclass
class ExperimentRunner:
    suite: Suite
    config: ExperimentConfig
    cancel_token: CancelToken = field(default_factory=CancelToken)

    def run(self, emit: EmitFn | None = None, on_campaign_complete: Callable[[CampaignResult], None] | None = None,
           skip_campaign_ids: frozenset[str] = frozenset(), force_new_id_for: frozenset[str] = frozenset()) -> ExperimentReport:
        """skip_campaign_ids and force_new_id_for exist for crash recovery (see persistence.py and
        run_web.py's /recover endpoint): skip_campaign_ids are campaigns already completed and
        persisted before an interruption, never re-run; force_new_id_for are incomplete campaigns
        whose attacker is stateful, re-run under a ':recovered' suffix rather than their original
        id so a fresh attempt is never mistaken for a continuation of the interrupted one."""
        self.config.validate(self.suite)
        scenario_ids = self.config.resolved_scenario_ids(self.suite)
        # Computed once, before any campaign runs, from the request alone (never from results) so
        # every campaign's tool-call records and the final manifest all agree on one experiment id.
        experiment_id = f"exp-{derive_seed('experiment', scenario_ids, self.config.defenses, self.config.attack_modes, self.config.seeds, self.config.attack_budget)}"
        manifest = self._manifest(scenario_ids)
        campaigns: list[CampaignResult] = []
        combos = [(sid, mode, seed, did) for sid in scenario_ids for mode in self.config.attack_modes
                  for seed in self.config.seeds for did in self.config.defenses]
        for scenario_id, attack_mode, seed, defense_id in combos:
            if self.cancel_token.is_cancelled():
                break
            precomputed_id = derive_campaign_id(scenario_id, defense_id, attack_mode, self.config.target_mode, seed)
            if precomputed_id in skip_campaign_ids:
                continue  # already completed and persisted before an interruption — never repeated
            id_override = f"{precomputed_id}:recovered" if precomputed_id in force_new_id_for else None
            campaign = run_campaign(
                scenario=self.suite.get(scenario_id), defense_id=defense_id, attack_mode=attack_mode,
                target_mode=self.config.target_mode, seed=seed, attack_budget=self.config.attack_budget,
                model_config=self.config.model_config, real_target_config=self.config.real_target_config,
                classifier_spec=self.config.classifier_spec,
                network_allowlist=self.config.network_allowlist, emit=emit, cancel_token=self.cancel_token,
                experiment_id=experiment_id, model_failure_policy=self.config.model_failure_policy,
                campaign_id_override=id_override,
            )
            campaigns.append(campaign)
            if emit:
                emit({"type": "campaign_complete", "campaign_id": campaign.campaign_id, "status": campaign.status})
            if on_campaign_complete:
                on_campaign_complete(campaign)
            if campaign.needs_demo_fallback:
                # A separate, fully independent campaign — new id, deterministic attacker, its own
                # rounds from round 1. Never merged with the aborted campaign's rounds or metrics.
                fallback_id = f"{campaign.campaign_id}:demo_fallback"
                fallback = run_campaign(
                    scenario=self.suite.get(scenario_id), defense_id=defense_id, attack_mode="adaptive_demo",
                    target_mode=self.config.target_mode, seed=seed, attack_budget=self.config.attack_budget,
                    model_config=None, real_target_config=self.config.real_target_config,
                    classifier_spec=self.config.classifier_spec,
                    network_allowlist=self.config.network_allowlist, emit=emit, cancel_token=self.cancel_token,
                    experiment_id=experiment_id, model_failure_policy="mark_invalid",
                    campaign_id_override=fallback_id, is_demo_fallback=True, fallback_of=campaign.campaign_id,
                )
                campaigns.append(fallback)
                if emit:
                    emit({"type": "campaign_complete", "campaign_id": fallback.campaign_id, "status": fallback.status})
                if on_campaign_complete:
                    on_campaign_complete(fallback)
        if self.cancel_token.is_cancelled():
            manifest["run_status"] = "cancelled"  # partial results are kept and labeled, never discarded
        return ExperimentReport(experiment_id=experiment_id, manifest=manifest, campaigns=campaigns)

    def _manifest(self, scenario_ids: tuple[str, ...]) -> dict[str, Any]:
        return {
            "schema_version": SCHEMA_VERSION,
            "platform_version": PLATFORM_VERSION,
            "suite_id": self.suite.suite_id,
            "suite_version": self.suite.version,
            "suite_content_hash": self.suite.content_hash(),
            "scenario_ids": list(scenario_ids),
            "defenses": list(self.config.defenses),
            "attack_modes": list(self.config.attack_modes),
            "target_mode": self.config.target_mode,
            "attack_budget": self.config.attack_budget,
            "seeds": list(self.config.seeds),
            "final_window_fraction": self.config.final_window_fraction,
            "final_window_minimum": self.config.final_window_minimum,
            "model_config": self.config.model_config.manifest() if self.config.model_config else None,
            "real_target_config": self.config.real_target_config.manifest() if self.config.real_target_config else None,
            "network_allowlist": list(self.config.network_allowlist or netguard.allowlist_from_env()),
            "runtime_environment": runtime_environment_info(),
            "dependency_versions": {},  # zero third-party dependencies by design (see docs/LIMITATIONS.md) — nothing to list
            "git": git_info(ROOT),  # None means this is not a Git checkout, never a fabricated commit
            "source_tree_hash": source_tree_hash(ROOT),
            "model_failure_policy": self.config.model_failure_policy,
            "generated_at": utc_now_iso(),
        }
