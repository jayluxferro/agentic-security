#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.lines import Line2D

METRIC_LABELS = {
    "risk_reduction_min": "Risk reduction floor",
    "blocked_by_policy_min": "Blocked-action floor",
    "violations_with_policy_max": "Residual ceiling",
    "utility_with_policy_min": "Utility floor",
}

SCENARIO_COLORS = {
    "default": "#1f77b4",
    "stress": "#d62728",
}

TESTED_MIN_POLICY_BLOCK_RATE = 0.45


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description=(
            "Render first-failure policy-block-rate thresholds from the OBLITERATUS watchlist artifact."
        )
    )
    parser.add_argument("input", help="OBLITERATUS watchlist JSON artifact")
    parser.add_argument("--output", required=True, help="Output PDF/PNG path")
    return parser.parse_args()


def load_artifact(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def _row_by_metric(entry: dict) -> dict[str, dict]:
    return {row["metric"]: row for row in entry["metric_priority"]}


def main() -> None:
    args = parse_args()
    artifact = load_artifact(args.input)
    watchlist = artifact["scenario_metric_watchlist"]
    metric_order = [
        "risk_reduction_min",
        "blocked_by_policy_min",
        "violations_with_policy_max",
        "utility_with_policy_min",
    ]

    fig, axes = plt.subplots(1, 2, figsize=(8.2, 4.3), sharey=True)
    if not isinstance(axes, (list, tuple)):
        axes = list(axes)

    y_positions = list(range(len(metric_order)))

    for ax, entry in zip(axes, watchlist):
        scenario = entry["scenario"]
        color = SCENARIO_COLORS[scenario]
        baseline_rate = float(entry["baseline_policy_block_rate"])
        metric_rows = _row_by_metric(entry)

        for y, metric in zip(y_positions, metric_order):
            row = metric_rows[metric]
            first_fail_rate = row["first_failure_policy_block_rate"]

            ax.hlines(
                y,
                TESTED_MIN_POLICY_BLOCK_RATE,
                baseline_rate,
                color="#d9d9d9",
                linewidth=2.5,
                zorder=1,
            )
            ax.scatter(
                baseline_rate,
                y,
                marker="|",
                s=280,
                linewidths=2.2,
                color="#444444",
                zorder=3,
            )

            if first_fail_rate is not None:
                first_fail_rate = float(first_fail_rate)
                ax.hlines(
                    y,
                    first_fail_rate,
                    baseline_rate,
                    color=color,
                    linewidth=6,
                    alpha=0.9,
                    zorder=2,
                )
                ax.scatter(
                    first_fail_rate,
                    y,
                    marker="o",
                    s=48,
                    color=color,
                    edgecolors="white",
                    linewidths=0.8,
                    zorder=4,
                )
                ax.text(
                    first_fail_rate - 0.002,
                    y - 0.20,
                    f"{first_fail_rate:.2f}",
                    ha="right",
                    va="center",
                    fontsize=8,
                    color=color,
                )
            else:
                ax.text(
                    TESTED_MIN_POLICY_BLOCK_RATE + 0.003,
                    y - 0.20,
                    "holds through tested band",
                    ha="left",
                    va="center",
                    fontsize=7.5,
                    color="#2a9d8f",
                )

        ax.set_title(f"{scenario.capitalize()} scenario", fontsize=11)
        ax.set_xlim(TESTED_MIN_POLICY_BLOCK_RATE - 0.005, 0.735)
        ax.set_xticks([0.45, 0.50, 0.55, 0.60, 0.65, 0.70])
        ax.grid(axis="x", linestyle=":", alpha=0.35)
        ax.spines["top"].set_visible(False)
        ax.spines["right"].set_visible(False)
        ax.spines["left"].set_visible(False)
        ax.set_axisbelow(True)
        ax.text(
            baseline_rate,
            len(metric_order) - 0.35,
            f"baseline {baseline_rate:.2f}",
            ha="center",
            va="bottom",
            fontsize=8,
            color="#444444",
        )

    axes[0].set_yticks(y_positions, [METRIC_LABELS[key] for key in metric_order])
    axes[0].invert_yaxis()
    for ax in axes:
        ax.set_xlabel("Policy block rate")

    legend = [
        Line2D(
            [0],
            [0],
            color="#444444",
            marker="|",
            linestyle="None",
            markersize=12,
            markeredgewidth=2,
            label="Scenario baseline",
        ),
        Line2D(
            [0],
            [0],
            color="#1f77b4",
            marker="o",
            linestyle="-",
            linewidth=4,
            markersize=6,
            label="First metric failure",
        ),
        Line2D(
            [0],
            [0],
            color="#2a9d8f",
            linestyle="None",
            marker="",
            label="No tested failure for utility",
        ),
    ]
    fig.legend(
        handles=legend,
        loc="lower center",
        ncol=3,
        frameon=False,
        bbox_to_anchor=(0.5, -0.02),
    )
    fig.suptitle(
        "First-failure policy-block-rate thresholds from the OBLITERATUS watchlist",
        fontsize=12,
        y=0.98,
    )
    fig.tight_layout(rect=(0, 0.05, 1, 0.95))

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output)
    print(output)


if __name__ == "__main__":
    main()
