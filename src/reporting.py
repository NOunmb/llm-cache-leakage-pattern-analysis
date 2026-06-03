"""Generate human-readable validation reports from experiment artifacts."""

from __future__ import annotations

import csv
import json
from pathlib import Path
from typing import Iterable


def _read_csv(path: str | Path) -> list[dict[str, str]]:
    with Path(path).open("r", newline="", encoding="utf-8") as f:
        return list(csv.DictReader(f))


def _load_json(path: str | Path):
    with Path(path).open("r", encoding="utf-8") as f:
        return json.load(f)


def _fmt_float(value: str | float) -> str:
    return f"{float(value):.4f}"


def _scenario_lookup(scenarios: Iterable[dict]) -> dict[str, dict]:
    return {scenario["name"]: scenario for scenario in scenarios}


def _candidate_lookup(reviewed_patterns: dict) -> dict[str, str]:
    """Map final scenario names to raw LLM candidate IDs when available."""
    mapping: dict[str, str] = {}
    for item in reviewed_patterns.get("accepted_vulnerable_patterns", []):
        mapping[item.get("final_scenario_name", "")] = item.get("candidate_id", "")
    for item in reviewed_patterns.get("accepted_mitigations", []):
        for scenario_name in item.get("final_scenario_names", []):
            mapping[scenario_name] = item.get("candidate_id", "")
    return mapping


def _leakage_label(row: dict[str, str]) -> str:
    acc = float(row["accuracy"])
    baseline = float(row["random_baseline"])
    if acc <= baseline + 0.05:
        return "near baseline"
    if acc < 0.65:
        return "partial / medium leakage"
    return "high leakage"


def generate_validation_report(
    output_md: str | Path,
    pattern_results_csv: str | Path,
    defense_results_csv: str | Path,
    partial_summary_csv: str | Path,
    scenarios_json: str | Path,
    defense_json: str | Path,
    reviewed_patterns_json: str | Path,
) -> None:
    """Generate a Markdown report linking LLM review, scenarios, and measurements."""
    output_md = Path(output_md)
    output_md.parent.mkdir(parents=True, exist_ok=True)

    pattern_rows = _read_csv(pattern_results_csv)
    defense_rows = _read_csv(defense_results_csv)
    partial_rows = _read_csv(partial_summary_csv)
    scenarios = _scenario_lookup(_load_json(scenarios_json))
    defense_scenarios = _scenario_lookup(_load_json(defense_json))
    reviewed = _load_json(reviewed_patterns_json)
    candidate_by_scenario = _candidate_lookup(reviewed)

    lines: list[str] = []
    lines.append("# Pattern Validation Report")
    lines.append("")
    lines.append("This report is generated from the reviewed scenario JSON files and simulator results. It links the LLM-assisted candidate/review workflow to the executable Prime+Probe-style validation backend.")
    lines.append("")
    lines.append("## Scope")
    lines.append("")
    lines.append("- The simulator fixes the attacker observation model as **Prime+Probe-style**.")
    lines.append("- The executable attack-side scenarios are **victim program leakage patterns**, not full real-hardware attacks.")
    lines.append("- LLM-style raw candidates are **not executed directly**; only reviewed and simulator-compatible scenarios under `scenarios/` are executed.")
    lines.append("- Timing uses normalized simulator units rather than hardware-calibrated cycle counts.")
    lines.append("")

    lines.append("## Vulnerable Pattern Validation")
    lines.append("")
    lines.append("| Scenario | Raw candidate | Pattern type | Expected | Accuracy | Baseline | Leakage label | Notes |")
    lines.append("|---|---|---|---|---:|---:|---|---|")
    for row in pattern_rows:
        name = row["pattern"]
        scenario = scenarios.get(name, {})
        candidate_id = candidate_by_scenario.get(name, "manual/reviewed")
        notes = scenario.get("source_inspiration", "").replace("|", "/")
        if len(notes) > 120:
            notes = notes[:117] + "..."
        lines.append(
            f"| `{name}` | `{candidate_id}` | `{row['pattern_type']}` | {row['expected_leakage']} | "
            f"{_fmt_float(row['accuracy'])} | {_fmt_float(row['random_baseline'])} | {_leakage_label(row)} | {notes} |"
        )
    lines.append("")

    lines.append("## Defense / Mitigation Validation")
    lines.append("")
    lines.append("| Defense group | Scenario | Case type | Pattern type | Accuracy | Baseline | Interpretation |")
    lines.append("|---|---|---|---|---:|---:|---|")
    for row in defense_rows:
        scenario = defense_scenarios.get(row["pattern"], {})
        if row.get("case_type") == "no_defense":
            interp = "control baseline"
        elif _leakage_label(row) == "near baseline":
            interp = "effective in this simplified model"
        elif _leakage_label(row) == "partial / medium leakage":
            interp = "reduces but does not eliminate leakage"
        else:
            interp = "still high leakage"
        lines.append(
            f"| {row.get('defense_group', '')} | `{row['pattern']}` | {row.get('case_type', '')} | `{row['pattern_type']}` | "
            f"{_fmt_float(row['accuracy'])} | {_fmt_float(row['random_baseline'])} | {interp} |"
        )
    lines.append("")

    lines.append("## Partial Leakage Analysis")
    lines.append("")
    lines.append("Accuracy alone can hide partial leakage. The following patterns leak a coarser secret group even when exact-secret recovery is limited.")
    lines.append("")
    lines.append("| Pattern | Exact accuracy | Exact baseline | Group rule | Group accuracy | Group baseline | Confusion matrix |")
    lines.append("|---|---:|---:|---|---:|---:|---|")
    for row in partial_rows:
        lines.append(
            f"| `{row['pattern']}` | {_fmt_float(row['exact_accuracy'])} | {_fmt_float(row['exact_random_baseline'])} | "
            f"{row['group_rule']} | {_fmt_float(row['group_accuracy'])} | {_fmt_float(row['group_random_baseline'])} | `{row['confusion_matrix_csv']}` |"
        )
    lines.append("")

    lines.append("## Takeaways")
    lines.append("")
    lines.append("1. Strong secret-dependent memory footprints, such as single-table and multi-table lookup, are easy to classify in the simplified Prime+Probe-style model.")
    lines.append("2. Branch and set-aliasing cases show **partial leakage**: the evaluator may not always recover the exact secret, but it can recover a secret-dependent group such as branch direction or cache-set group.")
    lines.append("3. Program-level constant-footprint defenses and partitioning-style isolation reduce accuracy close to the random baseline in this model.")
    lines.append("4. Random padding reduces leakage but does not remove the underlying secret-dependent signal.")
    lines.append("")

    lines.append("## Limitations")
    lines.append("")
    lines.append("- This is not a real hardware Prime+Probe implementation.")
    lines.append("- The cache model is simplified: fixed sets/ways, LRU replacement, normalized hit/miss latency, and additive Gaussian noise.")
    lines.append("- The system does not automatically read PDFs or directly execute raw LLM outputs.")
    lines.append("- Results indicate leakage potential in a controlled model, not real-world exploit success.")
    lines.append("")

    output_md.write_text("\n".join(lines), encoding="utf-8")
