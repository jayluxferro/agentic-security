#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Generate figures for agentic-security paper from live SAP metrics.

Outputs:
  figures/per-model-metrics.pdf    -- guard recall, utility per model
  figures/category-guard.pdf       -- per-category guard recall
  figures/confusion-heatmap.pdf    -- overall confusion matrix
"""

from __future__ import annotations

import json
import sys
from pathlib import Path

import matplotlib
matplotlib.use("Agg")
import matplotlib.pyplot as plt
import numpy as np

EXPERIMENTS = Path(__file__).resolve().parent
RESULTS = EXPERIMENTS / "results"
METRICS_PATH = RESULTS / "metrics.json"
FIGURES = EXPERIMENTS.parent / "figures"
FIGURES.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 10,
    "axes.titlesize": 11,
    "axes.labelsize": 10,
    "figure.dpi": 150,
})


def plot_per_model(metrics: dict) -> Path:
    """Horizontal bar chart: guard recall and utility per model with Wilson CIs."""
    models = sorted(metrics["per_model"].items(), key=lambda x: x[1]["guard_recall"]["value"], reverse=True)
    labels = [m[0] for m in models]
    recall_vals = [m[1]["guard_recall"]["value"] for m in models]
    recall_lo = [m[1]["guard_recall"]["value"] - m[1]["guard_recall"]["ci95_lower"] for m in models]
    recall_hi = [m[1]["guard_recall"]["ci95_upper"] - m[1]["guard_recall"]["value"] for m in models]
    utility_vals = [m[1]["utility_retained"]["value"] for m in models]

    fig, ax1 = plt.subplots(figsize=(8, 4.5))

    y = np.arange(len(labels))
    height = 0.35

    bars1 = ax1.barh(y - height / 2, recall_vals, height,
                      xerr=[recall_lo, recall_hi], capsize=3,
                      color="#2b8cbe", alpha=0.85, label="Guard Recall (Dangerous Actions Caught)")
    ax1.set_xlabel("Guard Recall")
    ax1.set_xlim(0, 1.05)

    ax2 = ax1.twiny()
    bars2 = ax2.barh(y + height / 2, utility_vals, height,
                      color="#7bccc4", alpha=0.85, label="Utility Retained (Safe Actions Allowed)")
    ax2.set_xlabel("Utility Retained")
    ax2.set_xlim(0, 1.05)

    ax1.set_yticks(y)
    ax1.set_yticklabels(labels)

    # Annotate with violation rate
    for i, m in enumerate(models):
        vr = m[1]["violation_rate"]["value"]
        ax1.text(0.02, i + height / 2 + 0.1, f"viol={vr:.0%}", fontsize=7, va="bottom", color="#444")

    lines1, labels1 = ax1.get_legend_handles_labels()
    lines2, labels2 = ax2.get_legend_handles_labels()
    ax1.legend(lines1 + lines2, labels1 + labels2, loc="lower right", fontsize=8)

    ax1.set_title("Per-Model Guard Performance with 95% Wilson CIs")
    fig.tight_layout()
    out = FIGURES / "per-model-metrics.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def plot_category_guard(metrics: dict) -> Path:
    """Per-category guard recall bar chart."""
    cats = sorted(metrics["per_category"].items(), key=lambda x: x[1]["dangerous_actions"], reverse=True)
    labels = [c[0].replace("_", " ").title() for c in cats]
    dangerous = [c[1]["dangerous_actions"] for c in cats]
    total = [c[1]["total_actions"] for c in cats]
    deny = [c[1]["guard_deny"] for c in cats]

    fig, ax = plt.subplots(figsize=(8, 4.5))
    x = np.arange(len(labels))
    width = 0.6

    ax.bar(x, total, width, color="#eee", edgecolor="#ccc", label="Total Actions")
    ax.bar(x, dangerous, width, color="#e34a33", alpha=0.7, label="Dangerous (Judge)")
    ax.bar(x, deny, width, color="#2b8cbe", alpha=0.7, label="Blocked by Guard")

    ax.set_xticks(x)
    ax.set_xticklabels(labels, rotation=45, ha="right")
    ax.set_ylabel("Action Count")
    ax.legend(loc="upper right", fontsize=8)
    ax.set_title("Per-Category Action Classification")

    # Add violation rate annotations
    for i, c in enumerate(cats):
        vr = c[1]["violation_rate"]["value"]
        ax.text(i, total[i] + 1, f"{vr:.0%}", ha="center", fontsize=7, color="#e34a33")

    fig.tight_layout()
    out = FIGURES / "category-guard.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def plot_confusion(metrics: dict) -> Path:
    """Confusion matrix as a 2x2 annotated heatmap."""
    o = metrics["overall"]
    tp = o["total_caught"]
    fn = o["total_missed"]
    fp = o["total_false_positives"]
    tn = o["total_safe_actions"] - fp
    matrix = np.array([[tn, fp], [fn, tp]])

    fig, ax = plt.subplots(figsize=(5, 4.5))
    im = ax.imshow(matrix, cmap="YlOrRd", vmin=0, vmax=max(tn + tp, 1))

    ax.set_xticks([0, 1])
    ax.set_xticklabels(["Allowed", "Blocked"])
    ax.set_yticks([0, 1])
    ax.set_yticklabels(["Safe", "Dangerous"])

    # Annotate
    labels_map = [[f"TN\n{tn}", f"FP\n{fp}"], [f"FN\n{fn}", f"TP\n{tp}"]]
    for i in range(2):
        for j in range(2):
            max_val = matrix.max() if hasattr(matrix, 'max') else max(matrix.flatten())
            color = "white" if matrix[i, j] > max_val * 0.4 else "black"
            ax.text(j, i, labels_map[i][j], ha="center", va="center", fontsize=13, color=color, fontweight="bold")

    ax.set_title("Policy Guard Confusion Matrix")
    fig.colorbar(im, ax=ax, label="Count")
    fig.tight_layout()
    out = FIGURES / "confusion-heatmap.pdf"
    fig.savefig(out, bbox_inches="tight")
    plt.close(fig)
    return out


def main() -> None:
    if not METRICS_PATH.exists():
        print(f"Metrics not found: {METRICS_PATH}")
        print("Run aggregate_metrics.py first.")
        sys.exit(1)

    metrics = json.loads(METRICS_PATH.read_text(encoding="utf-8"))

    out1 = plot_per_model(metrics)
    print(f"  {out1}")

    out2 = plot_category_guard(metrics)
    print(f"  {out2}")

    out3 = plot_confusion(metrics)
    print(f"  {out3}")

    print("\nDone. 3 figures generated.")


if __name__ == "__main__":
    main()
