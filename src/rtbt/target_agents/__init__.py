from __future__ import annotations

from ..schemas import ConfigurationError
from .base import TargetAgent, TargetResponse
from .ollama_chat import OllamaChatTargetAgent
from .real_model import RealModelTargetAgent, RealTargetConfig
from .simulated import SimulatedTargetAgent, SimulatedTargetAgentConfig


def make_target(mode: str, *, scenario=None, sim_config: SimulatedTargetAgentConfig | None = None,
                 real_config: RealTargetConfig | None = None,
                 allowlist: tuple[str, ...] | None = None) -> TargetAgent:
    if mode == "simulated":
        if scenario is None:
            raise ConfigurationError("simulated target requires a scenario")
        return SimulatedTargetAgent(scenario=scenario, config=sim_config or SimulatedTargetAgentConfig())
    if mode == "real_model":
        if real_config is None:
            raise ConfigurationError("real_model target requires a real_config")
        if real_config.api == "chat":
            return OllamaChatTargetAgent(config=real_config, allowlist=allowlist)
        if real_config.api != "generate":
            raise ConfigurationError(f"Unknown real_target_config.api '{real_config.api}'. Use generate or chat.")
        return RealModelTargetAgent(config=real_config, allowlist=allowlist)
    raise ConfigurationError(f"Unknown target mode '{mode}'. Use simulated or real_model.")


__all__ = ["TargetAgent", "TargetResponse", "SimulatedTargetAgent", "SimulatedTargetAgentConfig",
           "RealModelTargetAgent", "OllamaChatTargetAgent", "RealTargetConfig", "make_target"]
