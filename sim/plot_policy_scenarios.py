#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path

import matplotlib

matplotlib.use("Agg")
import matplotlib.pyplot as plt


def load_payload(path: str) -> dict:
    with open(path, "r", encoding="utf-8") as f:
        return json.load(f)


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Plot stacked blocked-vs-residual unsafe actions across scenario replay JSON files."
    )
    parser.add_argument(
        "inputs", nargs="+", help="Scenario JSON files produced by run_policy_eval.py"
    )
    parser.add_argument(
        "--labels",
        nargs="*",
        help="Optional labels; defaults to embedded scenario name or filename stem",
    )
    parser.add_argument("--output", required=True, help="Output PDF/PNG path")
    return parser.parse_args()


def _extract_metric(payload: dict, metric_name: str) -> tuple[float, float]:
    if "summary" in payload:
        metric_summary = payload["summary"][metric_name]
        return float(metric_summary["mean"]), float(metric_summary.get("ci95", 0.0))
    metric_value = float(payload["metrics"][metric_name])
    return metric_value, 0.0


def main() -> None:
    args = parse_args()
    payloads = [load_payload(path) for path in args.inputs]

    labels: list[str] = []
    if args.labels:
        if len(args.labels) != len(payloads):
            raise SystemExit("--labels count must match number of inputs")
        labels = list(args.labels)
    else:
        for path, payload in zip(args.inputs, payloads):
            labels.append(payload.get("scenario") or Path(path).stem)

    blocked = []
    residual = []
    reductions = []
    reduction_ci = []
    utilities = []
    utility_ci = []
    baselines = []
    for payload in payloads:
        baseline, _ = _extract_metric(payload, "violations_without_policy")
        blocked_count, _ = _extract_metric(payload, "blocked_by_policy")
        residual_count, _ = _extract_metric(payload, "violations_with_policy")
        reduction, reduction_ci95 = _extract_metric(payload, "risk_reduction")
        utility, utility_ci95 = _extract_metric(payload, "utility_with_policy")

        blocked.append(blocked_count)
        residual.append(residual_count)
        reductions.append(reduction * 100.0)
        reduction_ci.append(reduction_ci95 * 100.0)
        utilities.append(utility * 100.0)
        utility_ci.append(utility_ci95 * 100.0)
        baselines.append(baseline)

    fig, ax = plt.subplots(figsize=(7.4, 3.8))
    y_positions = list(range(len(labels)))

    ax.barh(y_positions, blocked, color="#2a9d8f", label="Blocked by policy")
    ax.barh(
        y_positions,
        residual,
        left=blocked,
        color="#e76f51",
        label="Residual unsafe actions",
    )

    ax.set_yticks(y_positions)
    ax.set_yticklabels(labels)
    ax.set_xlabel("Unsafe actions in replay scenario")
    ax.set_title("Policy replay matrix across default and stress scenarios")
    ax.legend(loc="lower right", frameon=False)
    ax.grid(axis="x", linestyle=":", alpha=0.4)

    max_baseline = max(baselines) if baselines else 1.0
    for (
        y,
        baseline,
        blocked_count,
        residual_count,
        reduction,
        reduction_ci95,
        utility,
        utility_ci95,
    ) in zip(
        y_positions,
        baselines,
        blocked,
        residual,
        reductions,
        reduction_ci,
        utilities,
        utility_ci,
    ):
        metric_label = f"RR {reduction:.1f}%"
        if reduction_ci95:
            metric_label += f" ± {reduction_ci95:.1f}"
        metric_label += f" | utility {utility:.1f}%"
        if utility_ci95:
            metric_label += f" ± {utility_ci95:.1f}"
        ax.text(
            baseline + max_baseline * 0.02,
            y,
            metric_label,
            va="center",
            fontsize=9,
        )
        ax.text(
            blocked_count / 2 if blocked_count else 0.5,
            y,
            f"{blocked_count:.1f}" if blocked_count % 1 else str(int(blocked_count)),
            ha="center",
            va="center",
            color="white",
            fontsize=9,
        )
        ax.text(
            blocked_count + residual_count / 2
            if residual_count
            else blocked_count + 0.5,
            y,
            f"{residual_count:.1f}" if residual_count % 1 else str(int(residual_count)),
            ha="center",
            va="center",
            color="white",
            fontsize=9,
        )

    xmax = max((b + r for b, r in zip(blocked, residual)), default=1.0)
    ax.set_xlim(0, xmax * 1.42)
    fig.tight_layout()

    output = Path(args.output)
    output.parent.mkdir(parents=True, exist_ok=True)
    fig.savefig(output)
    print(output)


if __name__ == "__main__":
    main()
