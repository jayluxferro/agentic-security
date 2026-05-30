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
        description="Render a per-case policy decision matrix from a challenge replay JSON artifact."
    )
    parser.add_argument("input", help="Challenge replay JSON artifact")
    parser.add_argument("--output", required=True, help="Output PDF/PNG path")
    return parser.parse_args()


def load_artifact(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as handle:
        return json.load(handle)


def shorten(label: str, limit: int = 42) -> str:
    if len(label) <= limit:
        return label
    return label[: limit - 1].rstrip() + "…"


def main() -> None:
    args = parse_args()
    artifact = load_artifact(args.input)
    cases = artifact["cases"]

    fig, axes = plt.subplots(
        nrows=len(cases),
        ncols=1,
        figsize=(7.4, 1.9 * len(cases) + 0.3),
        sharex=True,
    )
    if len(cases) == 1:
        axes = [axes]

    max_stage = max(len(case["steps"]) for case in cases)

    for axis, case in zip(axes, cases):
        steps = case["steps"]
        decisions = [step["policy_decision"] for step in steps]
        colors = [COLOR_MAP[decision] for decision in decisions]
        x_positions = list(range(1, len(steps) + 1))

        axis.barh(
            [0] * len(steps),
            [1.0] * len(steps),
            left=[x - 0.5 for x in x_positions],
            color=colors,
            height=0.68,
        )
        axis.set_xlim(0.5, max_stage + 0.5)
        axis.set_ylim(-0.75, 0.75)
        axis.set_yticks([])
        axis.set_ylabel(
            shorten(case["source_suite_family"]),
            rotation=0,
            ha="right",
            va="center",
            labelpad=36,
            fontsize=9,
        )
        axis.grid(axis="x", linestyle=":", alpha=0.35)
        axis.spines["top"].set_visible(False)
        axis.spines["right"].set_visible(False)
        axis.spines["left"].set_visible(False)

        for x_pos, step, decision in zip(x_positions, steps, decisions):
            axis.text(
                x_pos,
                0.18,
                DISPLAY_MAP[decision],
                ha="center",
                va="center",
                fontsize=9,
                color="black",
                fontweight="bold",
            )
            axis.text(
                x_pos,
                -0.23,
                shorten(step["action"], 36),
                ha="center",
                va="center",
                fontsize=7,
            )

        deny_count = decisions.count("deny")
        transform_count = decisions.count("transform")
        retained = case["outcome"]["utility_retained"].capitalize()
        axis.set_title(
            f"{shorten(case['task_class'], 62)} | deny={deny_count}, transform={transform_count}, utility={retained}",
            fontsize=9,
            loc="left",
        )

    axes[-1].set_xticks(list(range(1, max_stage + 1)))
    axes[-1].set_xlabel("Replay step")
    fig.suptitle(
        "Bounded challenge replay matrix across cited cyber benchmark families",
        fontsize=11,
        y=0.995,
    )
    legend = [
        Patch(facecolor=COLOR_MAP[key], label=DISPLAY_MAP[key])
        for key in ["allow", "transform", "deny"]
    ]
    fig.legend(
        handles=legend,
        loc="upper center",
        ncol=3,
        frameon=False,
        bbox_to_anchor=(0.52, 0.965),
    )
    fig.tight_layout(rect=(0, 0, 1, 0.93))

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output)
    print(output)


if __name__ == "__main__":
    main()
