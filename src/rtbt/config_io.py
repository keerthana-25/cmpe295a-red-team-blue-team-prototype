"""One place that turns an ExperimentConfig into plain JSON and back.

The CLI (run_demo.py --db / --resume) and the dashboard (run_web.py) both persist a run's
configuration in the SQLite run store so an interrupted run can be resumed later, possibly on a
different machine (for example: started on a Kaggle GPU session, resumed in the next session).
Before this module, only the dashboard could do that, through its own private payload parser.
Keeping the conversion in one module means both entry points write and read exactly the same
shape, and a run started from one can be inspected or resumed from the other.
"""
from __future__ import annotations

from dataclasses import asdict, fields
from typing import Any

from .attackers.local_model import ModelConfig
from .harness import ExperimentConfig
from .target_agents.real_model import RealTargetConfig

DEFAULT_DEFENSES = ("baseline", "defensive_prompt", "classifier", "tool_validator")
DEFAULT_ATTACK_MODES = ("static", "adaptive_demo")


def _known_kwargs(cls, raw: dict[str, Any]) -> dict[str, Any]:
    """Ignore keys a dataclass does not declare, so a config written by a newer version (with an
    extra optional field) still loads in an older checkout instead of crashing."""
    names = {f.name for f in fields(cls)}
    return {k: v for k, v in raw.items() if k in names}


def config_to_dict(config: ExperimentConfig) -> dict[str, Any]:
    return {
        "defenses": list(config.defenses),
        "attack_modes": list(config.attack_modes),
        "attack_budget": config.attack_budget,
        "seeds": list(config.seeds),
        "target_mode": config.target_mode,
        "scenario_ids": list(config.scenario_ids) if config.scenario_ids else None,
        "model_config": asdict(config.model_config) if config.model_config else None,
        "real_target_config": asdict(config.real_target_config) if config.real_target_config else None,
        "classifier_spec": config.classifier_spec,
        "final_window_fraction": config.final_window_fraction,
        "final_window_minimum": config.final_window_minimum,
        "network_allowlist": list(config.network_allowlist) if config.network_allowlist else None,
        "model_failure_policy": config.model_failure_policy,
    }


def config_from_dict(raw: dict[str, Any], *, default_budget: int = 20) -> ExperimentConfig:
    model_config = ModelConfig(**_known_kwargs(ModelConfig, raw["model_config"])) if raw.get("model_config") else None
    real_config = (RealTargetConfig(**_known_kwargs(RealTargetConfig, raw["real_target_config"]))
                   if raw.get("real_target_config") else None)
    return ExperimentConfig(
        # Defaults apply only when a key is absent. An explicit empty list is kept as given so
        # ExperimentConfig.validate() rejects it with a readable error instead of it silently
        # becoming "all four defenses".
        defenses=tuple(raw["defenses"] if raw.get("defenses") is not None else DEFAULT_DEFENSES),
        attack_modes=tuple(raw["attack_modes"] if raw.get("attack_modes") is not None else DEFAULT_ATTACK_MODES),
        attack_budget=int(raw.get("attack_budget", default_budget)),
        seeds=tuple(int(s) for s in raw.get("seeds", [1, 2, 3])),
        target_mode=raw.get("target_mode", "simulated"),
        scenario_ids=tuple(raw["scenario_ids"]) if raw.get("scenario_ids") else None,
        model_config=model_config,
        real_target_config=real_config,
        classifier_spec=raw.get("classifier_spec"),
        final_window_fraction=raw.get("final_window_fraction", 0.2),
        final_window_minimum=raw.get("final_window_minimum", 3),
        network_allowlist=tuple(raw["network_allowlist"]) if raw.get("network_allowlist") else None,
        model_failure_policy=raw.get("model_failure_policy", "mark_invalid"),
    )
