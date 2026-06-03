"""Load LLM- or paper-inspired pattern scenarios from JSON.

The JSON file is the boundary between the LLM/paper-abstraction layer and the
simulator. In this prototype the file is written manually, but it has the shape
we would expect from an LLM-generated test-case description.
"""

from __future__ import annotations

from pathlib import Path
from typing import Any, Dict, List
import json

Scenario = Dict[str, Any]


REQUIRED_FIELDS = {"name", "pattern_type", "secret_space", "expected_leakage"}


def load_scenarios(path: str | Path) -> List[Scenario]:
    """Read and lightly validate a scenario JSON file."""
    path = Path(path)
    with path.open("r", encoding="utf-8") as f:
        scenarios = json.load(f)

    if not isinstance(scenarios, list):
        raise ValueError("Scenario file must contain a list of scenarios")

    for index, scenario in enumerate(scenarios):
        if not isinstance(scenario, dict):
            raise ValueError(f"Scenario {index} must be a JSON object")
        missing = REQUIRED_FIELDS - set(scenario)
        if missing:
            raise ValueError(f"Scenario {index} is missing required fields: {sorted(missing)}")
        name = scenario["name"]
        if not isinstance(name, str) or not name.strip():
            raise ValueError(f"Scenario {index} has an invalid name")
        pattern_type = scenario["pattern_type"]
        if not isinstance(pattern_type, str) or not pattern_type.strip():
            raise ValueError(f"Scenario {name} has an invalid pattern_type")
        secret_space = scenario["secret_space"]
        if not isinstance(secret_space, int) or secret_space <= 0:
            raise ValueError(f"Scenario {name} has invalid secret_space; expected a positive integer")
        expected_leakage = scenario["expected_leakage"]
        if expected_leakage not in {"high", "medium", "low"}:
            raise ValueError(f"Scenario {name} has invalid expected_leakage; expected high, medium, or low")
        if not isinstance(scenario.get("parameters", {}), dict):
            raise ValueError(f"Scenario {name} has a non-object parameters field")

    return scenarios
