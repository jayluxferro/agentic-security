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
    "allow": "#2a9d8f",
    "transform": "#e9c46a",
    "deny": "#e76f51",
}

DISPLAY_MAP = {
    "allow": "Allow",
    "transform": "Transform",
    "deny": "Deny",
}


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Render a tactic-stratified policy decision chart from a challenge replay JSON artifact."
    )
    parser.add_argument("input", help="Challenge replay JSON artifact")
    parser.add_argument("--output", required=True, help="Output PDF/PNG path")
    return parser.parse_args()


def load_artifact(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def prettify_tactic(name: str) -> str:
    return name.replace(" and ", " & ").title()


def main() -> None:
    args = parse_args()
    artifact = load_artifact(args.input)
    tactic_breakdown = artifact["summary"]["tactic_breakdown"]
    tactics = list(tactic_breakdown.keys())
    labels = [prettify_tactic(tactic) for tactic in tactics]

    allow_counts = [tactic_breakdown[tactic]["allow"] for tactic in tactics]
    transform_counts = [tactic_breakdown[tactic]["transform"] for tactic in tactics]
    deny_counts = [tactic_breakdown[tactic]["deny"] for tactic in tactics]
    totals = [tactic_breakdown[tactic]["total"] for tactic in tactics]

    fig_height = max(3.6, 0.48 * len(tactics) + 1.5)
    fig, ax = plt.subplots(figsize=(7.2, fig_height))

    y_positions = list(range(len(tactics)))
    left = [0] * len(tactics)

    for key, counts in [
        ("allow", allow_counts),
        ("transform", transform_counts),
        ("deny", deny_counts),
    ]:
        ax.barh(
            y_positions,
            counts,
            left=left,
            color=COLOR_MAP[key],
            height=0.68,
            label=DISPLAY_MAP[key],
        )
        for idx, count in enumerate(counts):
            if count:
                x_pos = left[idx] + (count / 2)
                ax.text(
                    x_pos,
                    idx,
                    str(count),
                    ha="center",
                    va="center",
                    fontsize=8,
                    fontweight="bold",
                )
        left = [current + count for current, count in zip(left, counts)]

    for idx, total in enumerate(totals):
        ax.text(
            total + 0.08,
            idx,
            f"n={total}",
            va="center",
            ha="left",
            fontsize=8,
            color="#444444",
        )

    ax.set_yticks(y_positions, labels)
    ax.invert_yaxis()
    ax.set_xlabel("Replay steps")
    ax.set_title(
        "Tactic-stratified guard decisions from the bounded challenge replay artifact",
        fontsize=11,
    )
    ax.grid(axis="x", linestyle=":", alpha=0.35)
    ax.spines["top"].set_visible(False)
    ax.spines["right"].set_visible(False)
    ax.spines["left"].set_visible(False)
    ax.set_axisbelow(True)
    ax.set_xlim(0, max(totals) + 0.9)

    legend = [
        Patch(facecolor=COLOR_MAP[key], label=DISPLAY_MAP[key])
        for key in ["allow", "transform", "deny"]
    ]
    ax.legend(handles=legend, loc="lower right", frameon=False)
    fig.tight_layout()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output)
    print(output)


if __name__ == "__main__":
    main()
