"""Run the config-driven cache leakage experiments."""

from pathlib import Path

from src.experiments import (
    run_defense_comparison,
    run_defense_noise_sweep,
    run_noise_sweep,
    run_partial_leakage_analysis,
    run_pattern_comparison,
)
from src.plotting import (
    plot_confusion_matrix,
    plot_defense_comparison,
    plot_defense_noise_sweep,
    plot_noise_sweep,
    plot_pattern_results,
)
from src.reporting import generate_validation_report


def main() -> None:
    root = Path(__file__).resolve().parent
    scenarios_json = root / "scenarios" / "llm_extracted_patterns.json"
    defense_json = root / "scenarios" / "defense_scenarios.json"

    pattern_results_csv = root / "results" / "pattern_results.csv"
    pattern_plot_png = root / "plots" / "pattern_leakage_comparison.png"
    noise_results_csv = root / "results" / "noise_sweep.csv"
    noise_plot_png = root / "plots" / "noise_sweep.png"
    defense_results_csv = root / "results" / "defense_results.csv"
    defense_plot_png = root / "plots" / "defense_comparison.png"
    defense_noise_results_csv = root / "results" / "defense_noise_sweep.csv"
    defense_noise_plot_png = root / "plots" / "defense_noise_sweep.png"
    partial_results_dir = root / "results"
    partial_summary_csv = root / "results" / "partial_leakage_summary.csv"
    set_aliasing_confusion_csv = root / "results" / "confusion_matrix_set_aliasing_table_lookup.csv"
    branch_confusion_csv = root / "results" / "confusion_matrix_secret_dependent_branch_footprint.csv"
    set_aliasing_confusion_png = root / "plots" / "confusion_matrix_set_aliasing_table_lookup.png"
    branch_confusion_png = root / "plots" / "confusion_matrix_secret_dependent_branch_footprint.png"
    validation_report_md = root / "results" / "pattern_validation_report.md"
    reviewed_patterns_json = root / "llm_outputs" / "reviewed_patterns.json"

    pattern_rows = run_pattern_comparison(
        output_csv=pattern_results_csv,
        scenario_json=scenarios_json,
        n_trials=1000,
        seed=7,
        probe_order="reverse",
        noise_std=1.5,
    )
    plot_pattern_results(pattern_results_csv, pattern_plot_png)

    noise_rows = run_noise_sweep(
        output_csv=noise_results_csv,
        scenario_json=scenarios_json,
        noise_values=(0, 1, 2, 4, 6, 8, 10),
        n_trials=1000,
        seed=7,
        probe_order="reverse",
    )
    plot_noise_sweep(noise_results_csv, noise_plot_png)

    defense_rows = run_defense_comparison(
        output_csv=defense_results_csv,
        defense_json=defense_json,
        n_trials=1000,
        seed=7,
        probe_order="reverse",
        noise_std=1.5,
    )
    plot_defense_comparison(defense_results_csv, defense_plot_png)

    defense_noise_rows = run_defense_noise_sweep(
        output_csv=defense_noise_results_csv,
        defense_json=defense_json,
        defense_group="table_lookup",
        noise_values=(0, 1, 2, 4, 6, 8, 10),
        n_trials=1000,
        seed=7,
        probe_order="reverse",
    )
    plot_defense_noise_sweep(defense_noise_results_csv, defense_noise_plot_png)

    partial_rows = run_partial_leakage_analysis(
        output_dir=partial_results_dir,
        scenario_json=scenarios_json,
        patterns=("set_aliasing_table_lookup", "secret_dependent_branch_footprint"),
        n_trials=1000,
        seed=7,
        probe_order="reverse",
        noise_std=1.5,
    )
    plot_confusion_matrix(
        set_aliasing_confusion_csv,
        set_aliasing_confusion_png,
        "Partial Leakage: Set-Aliasing Table Lookup",
    )
    plot_confusion_matrix(
        branch_confusion_csv,
        branch_confusion_png,
        "Partial Leakage: Secret-Dependent Branch Footprint",
    )

    generate_validation_report(
        output_md=validation_report_md,
        pattern_results_csv=pattern_results_csv,
        defense_results_csv=defense_results_csv,
        partial_summary_csv=partial_summary_csv,
        scenarios_json=scenarios_json,
        defense_json=defense_json,
        reviewed_patterns_json=reviewed_patterns_json,
    )

    print("Config-driven pattern leakage comparison:")
    print(f"Scenario file: {scenarios_json}")
    print("Probe order: reverse")
    for row in pattern_rows:
        print(
            f"- {row['pattern']} ({row['pattern_type']}): "
            f"noise_std={row['noise_std']}, accuracy={row['accuracy']}, baseline={row['random_baseline']}, "
            f"expected={row['expected_leakage']}, leakage_detected={row['leakage_detected']}"
        )

    print("\nNoise sweep summary:")
    print("noise_std values: 0, 1, 2, 4, 6, 8, 10")
    for row in noise_rows:
        if float(row["noise_std"]) in (0.0, 4.0, 10.0):
            print(
                f"- noise={row['noise_std']:>4}: {row['pattern']} "
                f"accuracy={row['accuracy']}, leakage_detected={row['leakage_detected']}"
            )

    print("\nDefense comparison:")
    print(f"Defense scenario file: {defense_json}")
    for row in defense_rows:
        group = row.get("defense_group") or "general"
        case_type = row.get("case_type") or "scenario"
        print(
            f"- [{group} / {case_type}] {row['pattern']} ({row['pattern_type']}): "
            f"monitored_sets={row['monitored_sets']}, accuracy={row['accuracy']}, "
            f"baseline={row['random_baseline']}, expected={row['expected_leakage']}, "
            f"leakage_detected={row['leakage_detected']}"
        )

    print("\nDefense noise sweep summary: table_lookup group")
    print("noise_std values: 0, 1, 2, 4, 6, 8, 10")
    for row in defense_noise_rows:
        if float(row["noise_std"]) in (0.0, 4.0, 10.0):
            print(
                f"- noise={row['noise_std']:>4}: {row['pattern']} "
                f"accuracy={row['accuracy']}, leakage_detected={row['leakage_detected']}"
            )

    print("\nPartial leakage analysis:")
    for row in partial_rows:
        print(
            f"- {row['pattern']}: exact_accuracy={row['exact_accuracy']}, "
            f"group_accuracy={row['group_accuracy']} ({row['group_rule']})"
        )

    print(f"\nSaved pattern results to: {pattern_results_csv}")
    print(f"Saved pattern plot to:    {pattern_plot_png}")
    print(f"Saved noise results to:   {noise_results_csv}")
    print(f"Saved noise plot to:      {noise_plot_png}")
    print(f"Saved defense results to: {defense_results_csv}")
    print(f"Saved defense plot to:    {defense_plot_png}")
    print(f"Saved defense-noise results to: {defense_noise_results_csv}")
    print(f"Saved defense-noise plot to:    {defense_noise_plot_png}")
    print(f"Saved partial leakage summary to: {partial_summary_csv}")
    print(f"Saved set-aliasing confusion plot to: {set_aliasing_confusion_png}")
    print(f"Saved branch confusion plot to:       {branch_confusion_png}")
    print(f"Saved validation report to:           {validation_report_md}")


if __name__ == "__main__":
    main()
