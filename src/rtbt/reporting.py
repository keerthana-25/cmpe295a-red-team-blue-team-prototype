"""Report structures. A CampaignResult is one (scenario, defense, attack_mode, seed)
run. An ExperimentReport bundles many campaigns and carries the reproducibility
manifest plus the provenance labeling the spec requires on every simulated report.
"""
from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from .metrics import compute_campaign_metrics, matched_budget_ok
from .schemas import (PLATFORM_VERSION, SCHEMA_VERSION, OracleResult, RoundRecord, ToolCallRecord,
                      eligible_as_research_evidence, evidence_status_for_campaign)

DEMO_WARNING = "Demonstration data only. These results are not research evidence."
DEMO_PROVENANCE = {"simulated_deterministic_v1", "deterministic_demo_v1", "demonstration"}


@dataclass
class CampaignResult:
    campaign_id: str
    scenario_id: str
    scenario_version: str
    environment: str
    defense_id: str
    attack_mode: str
    target_mode: str
    seed: int
    attack_budget: int
    status: str  # "complete" | "cancelled" | "error"
    rounds: list[RoundRecord] = field(default_factory=list)
    attacker_stats: dict[str, Any] = field(default_factory=dict)
    defense_describe: dict[str, Any] = field(default_factory=dict)
    started_at: str = ""
    ended_at: str = ""
    # model_failure_policy bookkeeping — all default to "nothing unusual happened" so every
    # existing CampaignResult(...) construction (tests included) keeps working unchanged.
    abort_reason: str | None = None
    needs_demo_fallback: bool = False
    is_demo_fallback: bool = False
    fallback_of: str | None = None
    cost: dict[str, Any] = field(default_factory=dict)  # see cost.compute_cost_accounting

    def metrics(self) -> dict[str, Any]:
        return compute_campaign_metrics(self.rounds)

    @property
    def evidence_status(self) -> str:
        return evidence_status_for_campaign(self)

    @property
    def eligible_as_research_evidence(self) -> bool:
        return eligible_as_research_evidence(self.evidence_status)

    def to_dict(self) -> dict[str, Any]:
        return {
            "campaign_id": self.campaign_id, "scenario_id": self.scenario_id, "scenario_version": self.scenario_version,
            "environment": self.environment, "defense_id": self.defense_id, "attack_mode": self.attack_mode,
            "target_mode": self.target_mode, "seed": self.seed, "attack_budget": self.attack_budget,
            "status": self.status, "started_at": self.started_at, "ended_at": self.ended_at,
            "defense": self.defense_describe, "attacker_stats": self.attacker_stats,
            "abort_reason": self.abort_reason, "needs_demo_fallback": self.needs_demo_fallback,
            "is_demo_fallback": self.is_demo_fallback, "fallback_of": self.fallback_of,
            "evidence_status": self.evidence_status, "eligible_as_research_evidence": self.eligible_as_research_evidence,
            "cost": self.cost,
            "metrics": self.metrics(), "rounds": [r.to_dict() for r in self.rounds],
        }


def _is_simulated(campaign: CampaignResult) -> bool:
    return campaign.target_mode == "simulated" or campaign.attack_mode != "adaptive_ollama"


@dataclass
class ExperimentReport:
    experiment_id: str
    manifest: dict[str, Any]
    campaigns: list[CampaignResult] = field(default_factory=list)

    @property
    def primary_campaigns(self) -> list[CampaignResult]:
        """Every campaign EXCEPT a demo-fallback spawned by model_failure_policy =
        'restart_as_separate_demo_campaign'. This is what every comparison, aggregation and
        matched-budget check should use — a fallback campaign used a different attacker than the
        one requested for that condition, so pooling it in would silently misrepresent the
        comparison. It is never dropped from the report itself; see fallback_campaigns()."""
        return [c for c in self.campaigns if not c.is_demo_fallback]

    @property
    def fallback_campaigns(self) -> list[CampaignResult]:
        return [c for c in self.campaigns if c.is_demo_fallback]

    def provenance_summary(self) -> dict[str, Any]:
        simulated = sum(1 for c in self.campaigns if c.target_mode == "simulated")
        real_target = sum(1 for c in self.campaigns if c.target_mode == "real_model")
        real_attacker = sum(1 for c in self.campaigns if c.attack_mode == "adaptive_ollama")

        components: dict[tuple[str, str], dict[str, Any]] = {}
        for c in self.campaigns:
            target_prov = next((r.target_provenance for r in c.rounds if r.target_provenance != "n/a"), c.target_mode)
            for role, name, prov in (
                ("Target agent", target_prov, target_prov),
                ("Attacker", c.attack_mode, str(c.attacker_stats.get("provenance", "unspecified"))),
                ("Defense", c.defense_id, str(c.defense_describe.get("provenance", "unspecified"))),
            ):
                components[(role, name)] = {
                    "role": role, "name": name, "provenance": prov,
                    "is_demonstration": prov in DEMO_PROVENANCE or prov.startswith("simulated"),
                }
        any_demo = any(v["is_demonstration"] for v in components.values())
        if not any_demo:
            component_mix = "real"
        elif simulated and not real_target and not real_attacker:
            component_mix = "simulated"
        else:
            component_mix = "mixed"
        return {
            "component_mix": component_mix,
            "simulated_target_campaigns": simulated,
            "real_target_campaigns": real_target,
            "real_attacker_campaigns": real_attacker,
            "components": list(components.values()),
            "demonstration_warning": DEMO_WARNING if any_demo else None,
        }

    def matched_budget_report(self) -> list[dict[str, Any]]:
        out = []
        by_group: dict[tuple[str, str], dict[str, dict[str, Any]]] = {}
        for c in self.primary_campaigns:
            key = (c.scenario_id, c.attack_mode)
            by_group.setdefault(key, {})[c.defense_id] = c.metrics()
        for (scenario_id, attack_mode), by_defense in by_group.items():
            ok, detail = matched_budget_ok(by_defense)
            out.append({"scenario_id": scenario_id, "attack_mode": attack_mode, "matched": ok, "detail": detail})
        return out

    def to_dict(self) -> dict[str, Any]:
        return {
            "experiment_id": self.experiment_id,
            "schema_version": SCHEMA_VERSION,
            "platform_version": PLATFORM_VERSION,
            "manifest": self.manifest,
            "provenance": self.provenance_summary(),
            "matched_budget": self.matched_budget_report(),
            "campaigns": [c.to_dict() for c in self.campaigns],  # every campaign, fallbacks included — nothing is ever deleted
            "fallback_campaigns": [c.campaign_id for c in self.fallback_campaigns],
        }

    def comparison_table(self) -> list[dict[str, Any]]:
        """One row per (scenario, attack_mode, defense) — what the dashboard's
        Comparison view and run_demo.py's CLI table both render from. Demo-fallback campaigns are
        deliberately excluded (see primary_campaigns); they never silently join this comparison."""
        rows = []
        for c in self.primary_campaigns:
            m = c.metrics()
            rows.append({
                "scenario_id": c.scenario_id, "environment": c.environment, "attack_mode": c.attack_mode,
                "defense_id": c.defense_id, "defense_label": c.defense_describe.get("kind", c.defense_id),
                "campaign_average_asr": m["campaign_average_asr"], "final_window_asr": m["final_window_asr"],
                "attempts_to_first_success": m["attempts_to_first_success"],
                "legitimate_task_completion_rate": m["legitimate_task_completion_rate"],
                "safe_utility_rate": m["safe_utility_rate"], "benign_block_rate": m["benign_block_rate"],
                "unauthorized_action_attempted_rate": m["unauthorized_action_attempted_rate"],
                "unauthorized_action_blocked_rate": m["unauthorized_action_blocked_rate"],
                "unauthorized_action_executed_rate": m["unauthorized_action_executed_rate"],
                "unauthorized_action_rate": m["unauthorized_action_rate"],  # backward-compat alias for executed_rate
                "mean_defense_latency_ms": m["mean_defense_latency_ms"],
                "evidence_status": c.evidence_status, "eligible_as_research_evidence": c.eligible_as_research_evidence,
                "total_estimated_cost": c.cost.get("total_estimated_cost"), "currency": c.cost.get("currency"),
                "pricing_source": c.cost.get("pricing_source"),
            })
        return rows


# ---------------------------------------------------------------------------------------
# Rebuilding results from their JSON form (run store, exported reports)
# ---------------------------------------------------------------------------------------
# Everything a CampaignResult knows is in its to_dict() output, so a campaign saved to the run
# store by one process (e.g. a headless Kaggle session) can be rebuilt by another (a laptop
# dashboard) and produce byte-identical metrics. Derived fields in the dict (metrics,
# evidence_status, eligible_as_research_evidence) are deliberately NOT read back: they are
# recomputed from the rounds, so a stored label can never upgrade what the rounds actually show.
def _round_from_dict(d: dict[str, Any]) -> RoundRecord:
    d = dict(d)
    d["tool_calls"] = [ToolCallRecord(**tc) for tc in d.get("tool_calls", [])]
    d["oracle"] = OracleResult(**d["oracle"])
    return RoundRecord(**d)


def campaign_from_dict(d: dict[str, Any]) -> CampaignResult:
    return CampaignResult(
        campaign_id=d["campaign_id"], scenario_id=d["scenario_id"], scenario_version=d["scenario_version"],
        environment=d["environment"], defense_id=d["defense_id"], attack_mode=d["attack_mode"],
        target_mode=d["target_mode"], seed=d["seed"], attack_budget=d["attack_budget"], status=d["status"],
        rounds=[_round_from_dict(r) for r in d.get("rounds", [])],
        attacker_stats=d.get("attacker_stats", {}), defense_describe=d.get("defense", {}),
        started_at=d.get("started_at", ""), ended_at=d.get("ended_at", ""),
        abort_reason=d.get("abort_reason"), needs_demo_fallback=d.get("needs_demo_fallback", False),
        is_demo_fallback=d.get("is_demo_fallback", False), fallback_of=d.get("fallback_of"),
        cost=d.get("cost", {}),
    )


def report_from_dict(d: dict[str, Any]) -> ExperimentReport:
    """Inverse of ExperimentReport.to_dict() (for exported JSON reports)."""
    return ExperimentReport(experiment_id=d["experiment_id"], manifest=d.get("manifest", {}),
                            campaigns=[campaign_from_dict(c) for c in d.get("campaigns", [])])
