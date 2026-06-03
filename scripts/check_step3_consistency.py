"""Check consistency between raw/reviewed LLM pattern files and executable scenarios.

This script is intentionally lightweight and uses only the Python standard library.
It does not replace full JSON Schema validation, but it catches the project-specific
consistency errors that matter for this prototype.
"""

from __future__ import annotations

import json
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]

RAW_PATH = ROOT / "llm_outputs" / "raw_llm_patterns.json"
REVIEWED_PATH = ROOT / "llm_outputs" / "reviewed_patterns.json"
ATTACK_SCENARIOS_PATH = ROOT / "scenarios" / "llm_extracted_patterns.json"
DEFENSE_SCENARIOS_PATH = ROOT / "scenarios" / "defense_scenarios.json"

REQUIRED_CANDIDATE_FIELDS = {
    "candidate_id",
    "classification",
    "attack_method_layer",
    "supported_pattern_type",
    "simulator_support",
    "expected_leakage",
    "recommended_destination",
}

ALLOWED_CLASSIFICATIONS = {
    "vulnerable_victim_pattern",
    "mitigation_candidate",
    "attack_observation_method_only",
    "unsupported_or_out_of_scope",
}

ALLOWED_DESTINATIONS = {
    "llm_extracted_patterns.json",
    "defense_scenarios.json",
    "paper_sources_only",
    "reject",
}


def load_json(path: Path):
    with path.open("r", encoding="utf-8") as f:
        return json.load(f)


def assert_true(condition: bool, message: str) -> None:
    if not condition:
        raise AssertionError(message)


def main() -> None:
    raw = load_json(RAW_PATH)
    reviewed = load_json(REVIEWED_PATH)
    attack_scenarios = load_json(ATTACK_SCENARIOS_PATH)
    defense_scenarios = load_json(DEFENSE_SCENARIOS_PATH)

    assert_true(isinstance(raw, dict), "raw_llm_patterns.json must be a JSON object")
    assert_true(isinstance(raw.get("candidates"), list), "raw candidates must be a list")

    seen_candidate_ids = set()
    for cand in raw["candidates"]:
        missing = REQUIRED_CANDIDATE_FIELDS - cand.keys()
        assert_true(not missing, f"candidate {cand.get('candidate_id')} missing fields: {missing}")
        candidate_id = cand["candidate_id"]
        assert_true(candidate_id not in seen_candidate_ids, f"duplicate candidate_id: {candidate_id}")
        seen_candidate_ids.add(candidate_id)
        assert_true(cand["classification"] in ALLOWED_CLASSIFICATIONS, f"invalid classification for {candidate_id}")
        assert_true(cand["recommended_destination"] in ALLOWED_DESTINATIONS, f"invalid destination for {candidate_id}")

    attack_names = {scenario["name"] for scenario in attack_scenarios}
    defense_names = {scenario["name"] for scenario in defense_scenarios}

    # Ensure attack scenario file contains only vulnerable victim patterns.
    for scenario in attack_scenarios:
        assert_true(
            scenario.get("scenario_role") == "vulnerable_victim_pattern",
            f"attack scenario {scenario['name']} must have scenario_role=vulnerable_victim_pattern",
        )
        assert_true(
            scenario["pattern_type"] not in {
                "constant_time_scan",
                "random_padding",
                "balanced_branch",
                "fixed_loop_count",
                "multi_table_constant_time",
                "partitioned_cache",
            },
            f"mitigation pattern_type found in attack scenario file: {scenario['name']}",
        )

    # Reviewed vulnerable patterns must point to real attack scenarios.
    for item in reviewed.get("accepted_vulnerable_patterns", []):
        final_name = item["final_scenario_name"]
        assert_true(final_name in attack_names, f"reviewed vulnerable pattern not found in attack scenarios: {final_name}")
        assert_true(item["candidate_id"] in seen_candidate_ids, f"unknown candidate_id in reviewed vulnerable patterns: {item['candidate_id']}")

    # Reviewed mitigations must point to real defense scenarios.
    for item in reviewed.get("accepted_mitigations", []):
        assert_true(item["candidate_id"] in seen_candidate_ids, f"unknown candidate_id in reviewed mitigations: {item['candidate_id']}")
        for final_name in item.get("final_scenario_names", []):
            assert_true(final_name in defense_names, f"reviewed mitigation not found in defense scenarios: {final_name}")

    # Record-only and rejected candidates should not be executable scenarios.
    record_or_reject_ids = {
        item["candidate_id"] for item in reviewed.get("paper_sources_only", [])
    } | {
        item["candidate_id"] for item in reviewed.get("rejected_candidates", [])
    }
    for candidate_id in record_or_reject_ids:
        assert_true(candidate_id in seen_candidate_ids, f"unknown record/reject candidate_id: {candidate_id}")

    print("Step 3 consistency check passed.")
    print(f"  raw candidates: {len(seen_candidate_ids)}")
    print(f"  executable vulnerable scenarios: {len(attack_names)}")
    print(f"  defense scenarios: {len(defense_names)}")


if __name__ == "__main__":
    main()
