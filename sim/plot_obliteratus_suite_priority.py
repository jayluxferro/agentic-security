#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt
from matplotlib.patches import Patch

COLOR_MAP = {
    "reconstructed": "#4c78a8",
    "benchmark-derived": "#f58518",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render the current OBLITERATUS suite-priority coverage figure from the follow-up priority artifact."
    )
    parser.add_argument("input", help="OBLITERATUS follow-up priority JSON artifact")
    parser.add_argument("--output", required=True, help="Output PDF/PNG path")
    return parser.parse_args()


def load_artifact(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def main() -> None:
    args = parse_args()
    artifact = load_artifact(args.input)
    rows = artifact["suite_priority_watchlist"]

    suites = [row["suite"] for row in rows]
    reconstructed = [row["reconstructed_case_count"] for row in rows]
    benchmark = [row["benchmark_derived_case_count"] for row in rows]
    total = [row["grounded_case_count"] for row in rows]
    first_tactics = [", ".join(row["first_guard_tactics"]) for row in rows]

    fig_height = max(3.6, 1.15 * len(rows) + 0.8)
    fig, ax = plt.subplots(figsize=(8.2, fig_height))

    y_positions = list(range(len(rows)))
    ax.barh(
        y_positions,
        reconstructed,
        color=COLOR_MAP["reconstructed"],
        label="Reconstructed traces",
        height=0.64,
    )
    ax.barh(
        y_positions,
        benchmark,
        left=reconstructed,
        color=COLOR_MAP["benchmark-derived"],
        label="Benchmark-derived traces",
        height=0.64,
    )

    for idx, row in enumerate(rows):
        if reconstructed[idx]:
            ax.text(
                reconstructed[idx] / 2,
                idx,
                str(reconstructed[idx]),
                ha="center",
                va="center",
                color="white",
                fontsize=9,
                fontweight="bold",
            )
        if benchmark[idx]:
            ax.text(
                reconstructed[idx] + benchmark[idx] / 2,
                idx,
                str(benchmark[idx]),
                ha="center",
                va="center",
                color="white",
                fontsize=9,
                fontweight="bold",
            )
        ax.text(
            total[idx] + 0.12,
            idx,
            f"total {total[idx]} | live traces 0",
            ha="left",
            va="center",
            fontsize=8,
            color="#444444",
        )
        ax.text(
            0.02,
            idx + 0.34,
            f"first guard: {first_tactics[idx]}",
            ha="left",
            va="center",
            fontsize=7.5,
            color="#555555",
        )

    ax.set_yticks(y_positions, suites)
    ax.invert_yaxis()
    ax.set_xlabel("Grounded cases in the current replay bundle")
    ax.set_title(
        "Current OBLITERATUS suite-priority coverage by trace origin",
        fontsize=12,
    )
    ax.grid(axis="x", linestyle=":", alpha=0.35)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.set_axisbelow(True)
    ax.set_xlim(0, max(total) + 1.6)

    legend = [
        Patch(facecolor=COLOR_MAP["reconstructed"], label="Reconstructed traces"),
        Patch(
            facecolor=COLOR_MAP["benchmark-derived"], label="Benchmark-derived traces"
        ),
    ]
    ax.legend(handles=legend, loc="lower right", frameon=False)
    fig.tight_layout()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output)
    print(output)


if __name__ == "__main__":
    main()
