"""Seeded demo scenarios and deterministic replay support."""

from sentinel_ai.demo.generator import build_scenario_event, generate_dataset, generate_employees
from sentinel_ai.demo.scenarios import SIMULATION_SCENARIOS

__all__ = ["SIMULATION_SCENARIOS", "build_scenario_event", "generate_dataset", "generate_employees"]

