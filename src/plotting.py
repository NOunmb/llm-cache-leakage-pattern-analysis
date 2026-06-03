"""Plot helpers."""

from __future__ import annotations

import csv
from collections import defaultdict
from pathlib import Path

import matplotlib.pyplot as plt


def _read_csv(input_csv: str | Path) -> list[dict[str, str]]:
    input_csv = Path(input_csv)
    rows = []
    with input_csv.open("r", newline="", encoding="utf-8") as f:
        reader = csv.DictReader(f)
        for row in reader:
            rows.append(row)
    return rows


def _unique_float_values(rows: list[dict[str, str]], key: str) -> list[float]:
    """Return sorted unique float values from a CSV column."""
    return sorted({round(float(row[key]), 10) for row in rows})


def _draw_reference_lines(rows: list[dict[str, str]], include_threshold: bool = True) -> None:
    """Draw all distinct random baselines/thresholds found in result rows.

    Some experiments compare scenarios with different secret spaces. For example,
    the set-aliasing scenario uses ``secret_space=8`` and has baseline 0.125,
    while most scenarios use ``secret_space=4`` and have baseline 0.25. Drawing
    only the first row's baseline would be misleading.
    """
    baselines = _unique_float_values(rows, "random_baseline")
    for baseline in baselines:
        plt.axhline(baseline, linestyle="--", linewidth=1, label=f"random baseline={baseline:.3f}")

    if include_threshold and rows and "threshold" in rows[0]:
        thresholds = _unique_float_values(rows, "threshold")
        for threshold in thresholds:
            plt.axhline(threshold, linestyle=":", linewidth=1, label=f"threshold={threshold:.3f}")


def plot_pattern_results(input_csv: str | Path, output_png: str | Path) -> None:
    output_png = Path(output_png)
    output_png.parent.mkdir(parents=True, exist_ok=True)

    rows = _read_csv(input_csv)
    patterns = [row["pattern"] for row in rows]
    accuracies = [float(row["accuracy"]) for row in rows]

    plt.figure(figsize=(10, 5.5))
    plt.bar(patterns, accuracies)
    _draw_reference_lines(rows, include_threshold=False)
    plt.ylim(0, 1.05)
    plt.ylabel("Secret prediction accuracy")
    plt.xlabel("Victim pattern")
    plt.title("Vulnerable Victim Pattern Leakage Comparison")
    plt.xticks(rotation=25, ha="right")
    plt.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(output_png, dpi=180)
    plt.close()


def plot_noise_sweep(input_csv: str | Path, output_png: str | Path) -> None:
    output_png = Path(output_png)
    output_png.parent.mkdir(parents=True, exist_ok=True)

    rows = _read_csv(input_csv)
    grouped: dict[str, list[tuple[float, float]]] = defaultdict(list)

    for row in rows:
        grouped[row["pattern"]].append((float(row["noise_std"]), float(row["accuracy"])))

    plt.figure(figsize=(10, 5.5))
    for pattern, points in grouped.items():
        points = sorted(points, key=lambda item: item[0])
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        plt.plot(xs, ys, marker="o", label=pattern)

    _draw_reference_lines(rows, include_threshold=True)

    plt.ylim(0, 1.05)
    plt.xlabel("Timing noise standard deviation")
    plt.ylabel("Secret prediction accuracy")
    plt.title("Noise Sensitivity of Vulnerable Leakage Patterns")
    plt.legend(fontsize=7)
    plt.tight_layout()
    plt.savefig(output_png, dpi=180)
    plt.close()


def plot_defense_comparison(input_csv: str | Path, output_png: str | Path) -> None:
    output_png = Path(output_png)
    output_png.parent.mkdir(parents=True, exist_ok=True)

    rows = _read_csv(input_csv)
    labels = [row["pattern"] for row in rows]
    accuracies = [float(row["accuracy"]) for row in rows]

    plt.figure(figsize=(12, 5.5))
    plt.bar(labels, accuracies)
    _draw_reference_lines(rows, include_threshold=True)
    plt.ylim(0, 1.05)
    plt.ylabel("Secret prediction accuracy")
    plt.xlabel("Defense / mitigation scenario")
    plt.title("Defense Comparison Across Representative Victim Patterns")
    plt.xticks(rotation=25, ha="right", fontsize=8)
    plt.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(output_png, dpi=180)
    plt.close()


def plot_defense_noise_sweep(input_csv: str | Path, output_png: str | Path) -> None:
    """Plot defense robustness under timing noise for one defense group."""
    output_png = Path(output_png)
    output_png.parent.mkdir(parents=True, exist_ok=True)

    rows = _read_csv(input_csv)
    grouped: dict[str, list[tuple[float, float]]] = defaultdict(list)

    for row in rows:
        grouped[row["pattern"]].append((float(row["noise_std"]), float(row["accuracy"])))

    plt.figure(figsize=(9, 5))
    for pattern, points in grouped.items():
        points = sorted(points, key=lambda item: item[0])
        xs = [p[0] for p in points]
        ys = [p[1] for p in points]
        plt.plot(xs, ys, marker="o", label=pattern)

    _draw_reference_lines(rows, include_threshold=True)

    plt.ylim(0, 1.05)
    plt.xlabel("Timing noise standard deviation")
    plt.ylabel("Secret prediction accuracy")
    plt.title("Defense Robustness Under Timing Noise: Table Lookup")
    plt.legend(fontsize=8)
    plt.tight_layout()
    plt.savefig(output_png, dpi=180)
    plt.close()


def _read_confusion_matrix(input_csv: str | Path) -> tuple[list[str], list[list[int]]]:
    """Read a confusion matrix CSV produced by run_partial_leakage_analysis."""
    rows = _read_csv(input_csv)
    if not rows:
        raise ValueError(f"No rows found in confusion matrix {input_csv}")
    first_key = "true_secret\\predicted_secret"
    labels = [key for key in rows[0].keys() if key != first_key]
    matrix: list[list[int]] = []
    for row in rows:
        matrix.append([int(row[label]) for label in labels])
    return labels, matrix


def plot_confusion_matrix(input_csv: str | Path, output_png: str | Path, title: str) -> None:
    """Plot a confusion matrix for partial-leakage interpretation."""
    output_png = Path(output_png)
    output_png.parent.mkdir(parents=True, exist_ok=True)

    labels, matrix = _read_confusion_matrix(input_csv)
    fig, ax = plt.subplots(figsize=(6.5, 5.5))
    im = ax.imshow(matrix)
    ax.set_xticks(range(len(labels)))
    ax.set_yticks(range(len(labels)))
    ax.set_xticklabels(labels)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Predicted secret")
    ax.set_ylabel("True secret")
    ax.set_title(title)

    for i, row in enumerate(matrix):
        for j, value in enumerate(row):
            ax.text(j, i, str(value), ha="center", va="center")

    fig.colorbar(im, ax=ax, fraction=0.046, pad=0.04)
    fig.tight_layout()
    fig.savefig(output_png, dpi=180)
    plt.close(fig)
