"""Experiments for the config-driven prototype."""

from __future__ import annotations

import csv
from pathlib import Path
from typing import Dict, List, Sequence

from .cache_model import CacheConfig
from .leakage_evaluator import NearestMeanLeakageEvaluator
from .scenario_loader import load_scenarios
from .trace_generator import generate_dataset, validate_monitored_sets
from .victim_patterns import build_victim_builder_from_scenario


def _write_rows(output_csv: str | Path, rows: List[Dict[str, object]]) -> None:
    """Write a list of result dictionaries to a CSV file."""
    output_csv = Path(output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    if not rows:
        raise ValueError("No rows to write")

    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.DictWriter(f, fieldnames=list(rows[0].keys()))
        writer.writeheader()
        writer.writerows(rows)


def _get_monitored_sets(scenario: dict, config: CacheConfig) -> list[int] | None:
    """Return optional attacker-monitored sets from a scenario.

    If omitted, the attacker monitors every cache set. If present, the set list
    is checked for type, range, duplicates, and emptiness against the current
    cache configuration.
    """
    monitored_sets = scenario.get("monitored_sets")
    if monitored_sets is None:
        return None
    if not isinstance(monitored_sets, list):
        raise ValueError(f"Scenario {scenario['name']} has invalid monitored_sets; expected a list of integers")
    try:
        return validate_monitored_sets(config, monitored_sets)
    except ValueError as exc:
        raise ValueError(f"Scenario {scenario['name']} has invalid monitored_sets: {exc}") from exc


def _run_one_scenario(
    scenario: dict,
    config: CacheConfig,
    n_trials: int,
    seed: int,
    probe_order: str,
) -> dict:
    """Run one scenario and return an evaluation row."""
    scenario_secret_space = int(scenario["secret_space"])
    builder = build_victim_builder_from_scenario(scenario)
    monitored_sets = _get_monitored_sets(scenario, config)

    X, y = generate_dataset(
        victim_builder=builder,
        config=config,
        n_trials=n_trials,
        secret_space=scenario_secret_space,
        seed=seed,
        probe_order=probe_order,
        monitored_sets=monitored_sets,
    )
    evaluator = NearestMeanLeakageEvaluator(secret_space=scenario_secret_space, seed=seed)
    result = evaluator.evaluate(X, y)

    monitored_sets_label = "all" if monitored_sets is None else ",".join(str(x) for x in monitored_sets)
    return {
        "pattern": scenario["name"],
        "pattern_type": scenario["pattern_type"],
        "expected_leakage": scenario["expected_leakage"],
        "probe_order": probe_order,
        "noise_std": config.noise_std,
        "monitored_sets": monitored_sets_label,
        "accuracy": round(result.accuracy, 4),
        "random_baseline": round(result.random_baseline, 4),
        "threshold": round(result.threshold, 4),
        "leakage_detected": result.leakage_detected,
        "defense_group": scenario.get("defense_group", ""),
        "case_type": scenario.get("case_type", ""),
        "source_inspiration": scenario.get("source_inspiration", ""),
    }


def run_pattern_comparison(
    output_csv: str | Path,
    scenario_json: str | Path,
    n_trials: int = 1000,
    seed: int = 7,
    probe_order: str = "reverse",
    noise_std: float = 1.5,
) -> List[Dict[str, object]]:
    """Compare leakage across victim patterns loaded from JSON scenarios."""
    config = CacheConfig(
        num_sets=8,
        ways=2,
        line_size=64,
        hit_latency=10.0,
        miss_latency=30.0,
        noise_std=noise_std,
    )

    scenarios = load_scenarios(scenario_json)
    rows = [_run_one_scenario(s, config, n_trials, seed, probe_order) for s in scenarios]
    _write_rows(output_csv, rows)
    return rows


def run_noise_sweep(
    output_csv: str | Path,
    scenario_json: str | Path,
    noise_values: Sequence[float] = (0, 1, 2, 4, 6, 8, 10),
    n_trials: int = 1000,
    seed: int = 7,
    probe_order: str = "reverse",
) -> List[Dict[str, object]]:
    """Run each scenario under several timing-noise levels.

    This tests how robust the inferred leakage is when the hit/miss timing
    signal is mixed with increasing random noise.
    """
    scenarios = load_scenarios(scenario_json)
    rows: List[Dict[str, object]] = []

    for noise_std in noise_values:
        config = CacheConfig(
            num_sets=8,
            ways=2,
            line_size=64,
            hit_latency=10.0,
            miss_latency=30.0,
            noise_std=float(noise_std),
        )
        for scenario in scenarios:
            rows.append(_run_one_scenario(scenario, config, n_trials, seed, probe_order))

    _write_rows(output_csv, rows)
    return rows


def run_defense_comparison(
    output_csv: str | Path,
    defense_json: str | Path,
    n_trials: int = 1000,
    seed: int = 7,
    probe_order: str = "reverse",
    noise_std: float = 1.5,
) -> List[Dict[str, object]]:
    """Compare leakage under several simplified mitigation strategies.

    The defense JSON can specify scenario-specific attacker monitored sets. This
    is used for the partitioned-cache scenario, where the attacker monitors only
    sets 0-3 while the victim intentionally maps secret-dependent accesses to
    sets 4-7.
    """
    config = CacheConfig(
        num_sets=8,
        ways=2,
        line_size=64,
        hit_latency=10.0,
        miss_latency=30.0,
        noise_std=noise_std,
    )
    scenarios = load_scenarios(defense_json)
    rows = [_run_one_scenario(s, config, n_trials, seed, probe_order) for s in scenarios]
    _write_rows(output_csv, rows)
    return rows

def run_defense_noise_sweep(
    output_csv: str | Path,
    defense_json: str | Path,
    defense_group: str = "table_lookup",
    noise_values: Sequence[float] = (0, 1, 2, 4, 6, 8, 10),
    n_trials: int = 1000,
    seed: int = 7,
    probe_order: str = "reverse",
) -> List[Dict[str, object]]:
    """Run one defense group under several timing-noise levels.

    This is a focused robustness test. Instead of plotting every mitigation for
    every victim pattern, it compares the no-defense and mitigation variants of
    one representative defense group, such as table_lookup, as timing noise
    increases.
    """
    all_scenarios = load_scenarios(defense_json)
    scenarios = [s for s in all_scenarios if s.get("defense_group") == defense_group]
    if not scenarios:
        raise ValueError(f"No defense scenarios found for defense_group={defense_group!r}")

    rows: List[Dict[str, object]] = []
    for noise_std in noise_values:
        config = CacheConfig(
            num_sets=8,
            ways=2,
            line_size=64,
            hit_latency=10.0,
            miss_latency=30.0,
            noise_std=float(noise_std),
        )
        for scenario in scenarios:
            rows.append(_run_one_scenario(scenario, config, n_trials, seed, probe_order))

    _write_rows(output_csv, rows)
    return rows



def _make_confusion_matrix(y_true: list[int], y_pred: list[int], secret_space: int) -> list[list[int]]:
    """Return a true-secret by predicted-secret confusion matrix."""
    matrix = [[0 for _ in range(secret_space)] for _ in range(secret_space)]
    for true, pred in zip(y_true, y_pred):
        matrix[true][pred] += 1
    return matrix


def _write_matrix_csv(output_csv: str | Path, matrix: list[list[int]]) -> None:
    """Write a confusion matrix as CSV with true secret rows and predicted secret columns."""
    output_csv = Path(output_csv)
    output_csv.parent.mkdir(parents=True, exist_ok=True)
    secret_space = len(matrix)
    with output_csv.open("w", newline="", encoding="utf-8") as f:
        writer = csv.writer(f)
        writer.writerow(["true_secret\\predicted_secret"] + [str(i) for i in range(secret_space)])
        for i, row in enumerate(matrix):
            writer.writerow([str(i)] + row)


def _group_accuracy(y_true: list[int], y_pred: list[int], group_fn) -> float:
    """Compute accuracy after mapping exact secrets into coarser leakage groups."""
    if not y_true:
        raise ValueError("Cannot compute group accuracy on empty labels")
    correct = sum(int(group_fn(t) == group_fn(p)) for t, p in zip(y_true, y_pred))
    return correct / len(y_true)


def run_partial_leakage_analysis(
    output_dir: str | Path,
    scenario_json: str | Path,
    patterns: Sequence[str] = ("set_aliasing_table_lookup", "secret_dependent_branch_footprint"),
    n_trials: int = 1000,
    seed: int = 7,
    probe_order: str = "reverse",
    noise_std: float = 1.5,
) -> list[dict[str, object]]:
    """Generate confusion matrices and partial-leakage summaries.

    Accuracy alone can hide partial leakage. For example, set aliasing may not
    reveal the exact secret, but it can reveal which cache-set group the secret
    belongs to. This function keeps the nearest-mean evaluator unchanged, then
    analyzes the test-set predictions with confusion matrices and group-level
    accuracy metrics.
    """
    output_dir = Path(output_dir)
    output_dir.mkdir(parents=True, exist_ok=True)

    config = CacheConfig(
        num_sets=8,
        ways=2,
        line_size=64,
        hit_latency=10.0,
        miss_latency=30.0,
        noise_std=noise_std,
    )
    scenarios = {s["name"]: s for s in load_scenarios(scenario_json)}
    summary_rows: list[dict[str, object]] = []

    for pattern_name in patterns:
        if pattern_name not in scenarios:
            raise ValueError(f"Pattern {pattern_name!r} not found in {scenario_json}")
        scenario = scenarios[pattern_name]
        secret_space = int(scenario["secret_space"])
        builder = build_victim_builder_from_scenario(scenario)
        monitored_sets = _get_monitored_sets(scenario, config)

        X, y = generate_dataset(
            victim_builder=builder,
            config=config,
            n_trials=n_trials,
            secret_space=secret_space,
            seed=seed,
            probe_order=probe_order,
            monitored_sets=monitored_sets,
        )
        evaluator = NearestMeanLeakageEvaluator(secret_space=secret_space, seed=seed)
        details = evaluator.evaluate_with_predictions(X, y)
        matrix = _make_confusion_matrix(details.y_true, details.y_pred, secret_space)
        matrix_csv = output_dir / f"confusion_matrix_{pattern_name}.csv"
        _write_matrix_csv(matrix_csv, matrix)

        params = scenario.get("parameters", {})
        if scenario["pattern_type"] == "set_aliasing_lookup":
            alias_sets = int(params.get("alias_sets", 4))
            group_fn = lambda secret, alias_sets=alias_sets: secret % alias_sets
            group_label = f"cache_set_group = secret mod {alias_sets}"
            group_baseline = 1.0 / alias_sets
            interpretation = (
                "Exact-secret recovery is limited because multiple secrets map to the same observed cache-set group. "
                "High group accuracy indicates partial leakage: the attacker can infer the group even when exact secret recovery is ambiguous."
            )
        elif scenario["pattern_type"] == "secret_dependent_branch":
            branch_mod = int(params.get("branch_mod", 2))
            group_fn = lambda secret, branch_mod=branch_mod: secret % branch_mod
            group_label = f"branch_group = secret mod {branch_mod}"
            group_baseline = 1.0 / branch_mod
            interpretation = (
                "The branch footprint leaks branch direction rather than the full secret. "
                "High group accuracy indicates partial leakage of the secret-dependent control-flow class."
            )
        else:
            group_fn = lambda secret: secret
            group_label = "exact_secret"
            group_baseline = 1.0 / secret_space
            interpretation = "No coarser group rule was configured for this pattern."

        group_acc = _group_accuracy(details.y_true, details.y_pred, group_fn)
        summary_rows.append(
            {
                "pattern": pattern_name,
                "pattern_type": scenario["pattern_type"],
                "secret_space": secret_space,
                "noise_std": noise_std,
                "probe_order": probe_order,
                "exact_accuracy": round(details.result.accuracy, 4),
                "exact_random_baseline": round(details.result.random_baseline, 4),
                "group_rule": group_label,
                "group_accuracy": round(group_acc, 4),
                "group_random_baseline": round(group_baseline, 4),
                "confusion_matrix_csv": str(matrix_csv.relative_to(output_dir.parent)),
                "interpretation": interpretation,
            }
        )

    summary_csv = output_dir / "partial_leakage_summary.csv"
    _write_rows(summary_csv, summary_rows)
    return summary_rows
