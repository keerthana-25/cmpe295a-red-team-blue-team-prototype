"""Size an experiment matrix to the compute the team actually has.

The team's compute is free-tier Kaggle and Colab GPU sessions (decided in WB1). A matrix that does
not fit in that is not a plan, so the attack budget and number of seeds are chosen from a MEASURED
seconds-per-round figure (the pilot run in notebooks/wb2_baselines.ipynb), not guessed.

Rounds in one campaign = attack budget (attackable scenarios only) + that scenario's benign
variants (every scenario, every campaign: the benign control phase always runs). That is exactly
what harness.run_campaign executes, and a test pins the two together.
"""
from __future__ import annotations

import math
from dataclasses import dataclass
from typing import Any


@dataclass(frozen=True)
class MatrixPlan:
    campaigns: int
    attack_rounds: int
    benign_rounds: int
    seconds_per_round: float
    parallel_sessions: int

    @property
    def rounds(self) -> int:
        return self.attack_rounds + self.benign_rounds

    @property
    def gpu_hours(self) -> float:
        return self.rounds * self.seconds_per_round / 3600.0

    @property
    def wall_clock_hours(self) -> float:
        return self.gpu_hours / max(1, self.parallel_sessions)

    def to_dict(self) -> dict[str, Any]:
        return {"campaigns": self.campaigns, "attack_rounds": self.attack_rounds, "benign_rounds": self.benign_rounds,
                "rounds": self.rounds, "seconds_per_round": self.seconds_per_round,
                "gpu_hours": round(self.gpu_hours, 2), "parallel_sessions": self.parallel_sessions,
                "wall_clock_hours": round(self.wall_clock_hours, 2)}


def plan_matrix(suite, *, scenario_ids, defenses: int, attack_modes: int, seeds: int, budget: int,
                seconds_per_round: float, parallel_sessions: int = 1) -> MatrixPlan:
    scenarios = [suite.get(s) for s in scenario_ids] if scenario_ids else list(suite.scenarios)
    per_seed_attack = sum(budget for sc in scenarios if sc.is_attackable)
    per_seed_benign = sum(len(sc.benign_variants) for sc in scenarios)
    mult = defenses * attack_modes * seeds
    return MatrixPlan(campaigns=len(scenarios) * mult, attack_rounds=per_seed_attack * mult,
                      benign_rounds=per_seed_benign * mult, seconds_per_round=seconds_per_round,
                      parallel_sessions=parallel_sessions)


def fit_to_hours(suite, *, scenario_ids, defenses: int, attack_modes: int, gpu_hours_available: float,
                 seconds_per_round: float, min_seeds: int = 3, min_budget: int = 10,
                 budgets=(30, 25, 20, 15, 10), seed_options=(5, 4, 3)) -> list[dict[str, Any]]:
    """Every (budget, seeds) option that fits, best first: more seeds before a bigger budget,
    because between-seed variance is what the confidence intervals need, and the final-window ASR
    needs at least final_window_minimum attack rounds, which any budget >= 10 already gives."""
    options = []
    for seeds in seed_options:
        if seeds < min_seeds:
            continue
        for budget in budgets:
            if budget < min_budget:
                continue
            p = plan_matrix(suite, scenario_ids=scenario_ids, defenses=defenses, attack_modes=attack_modes,
                            seeds=seeds, budget=budget, seconds_per_round=seconds_per_round)
            if p.gpu_hours <= gpu_hours_available:
                options.append({"seeds": seeds, "budget": budget, **p.to_dict(),
                                "headroom_gpu_hours": round(gpu_hours_available - p.gpu_hours, 2)})
    return options


def sessions_needed(gpu_hours: float, session_hours: float = 9.0, safety: float = 0.8) -> int:
    """Kaggle sessions stop after ~9-12 h; plan on 80% of a 9 h session being usable work."""
    return max(1, math.ceil(gpu_hours / (session_hours * safety)))
