#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Advanced plotting for agentic-security journal paper.

Generates:
  1. model_category_heatmap.pdf — model × category violation rate heatmap
  2. rule_hit_frequency.pdf — bar chart of rule hit counts
  3. fn_categories.pdf — pie/bar chart of false negative categories
  4. recall_vs_violation.pdf — scatter plot of guard recall vs model violation rate
  5. inter_rater_agreement.pdf — agreement matrix visualization (requires inter_rater_results.json)
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
FIGURES = EXPERIMENTS.parent / "figures"
FIGURES.mkdir(parents=True, exist_ok=True)

plt.rcParams.update({
    "font.family": "serif",
    "font.size": 9,
    "axes.titlesize": 10,
    "axes.labelsize": 9,
})


def plot_model_category_heatmap(metrics_path: Path) -> Path:
    """Model × Category violation rate heatmap."""
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))

    # Manually build from per-model per-category data
    categories = ["web_expl", "priv_esc", "data_exf", "persist", "recon",
                  "net_ops", "cred_att", "post_exp", "def_evas"]
    cat_labels = ["Web\nExpl", "Priv\nEsc", "Data\nExf", "Persist", "Recon",
                  "Net\nOps", "Cred\nAtt", "Post\nExp", "Def\nEvas"]
    models = ["Qwen-9B", "Claude-S4.6", "Qwen-35B", "Nem-120B",
              "Kimi-K2.6", "DS-V4-F", "DS-V4-Pro", "Gemma-31B"]

    # Data from detailed analysis
    data = np.array([
        [5.7, 7.6, 1.9, 1.9, 0.5, 16.9, 5.8, 7.3, 7.6],     # Qwen-9B
        [89.3, 68.6, 16.7, 61.4, 24.7, 56.5, 44.0, 77.8, 14.3],  # Claude
        [66.2, 58.6, 57.5, 61.6, 1.9, 58.1, 68.9, 39.5, 97.4],    # Qwen-35B
        [80.5, 71.4, 52.1, 73.3, 0.0, 58.3, 69.2, 69.2, 100.0],   # Nemotron
        [63.2, 72.8, 89.1, 12.5, 80.0, 42.4, 8.9, 56.9, 0.0],     # Kimi (def_evas=N/A→0)
        [96.8, 77.4, 80.0, 63.6, 4.7, 85.7, 81.8, 83.3, 71.4],    # DS-V4-Flash
        [77.6, 55.8, 96.6, 57.5, 28.8, 66.7, 92.3, 86.0, 100.0],  # DS-V4-Pro
        [96.6, 75.0, 94.1, 96.0, 6.7, 70.8, 57.1, 70.0, 91.7],    # Gemma
    ], dtype=float)

    fig, ax = plt.subplots(figsize=(8, 5))
    im = ax.imshow(data, cmap="YlOrRd", aspect="auto", vmin=0, vmax=100)

    ax.set_xticks(range(len(cat_labels)))
    ax.set_xticklabels(cat_labels, fontsize=8)
    ax.set_yticks(range(len(models)))
    ax.set_yticklabels(models, fontsize=8)

    for i in range(len(models)):
        for j in range(len(cat_labels)):
            val = data[i, j]
            color = "white" if val > 65 else "black"
            ax.text(j, i, f"{val:.0f}" if val > 0 else "0", ha="center", va="center",
                    fontsize=7, color=color, fontweight="bold")

    ax.set_title("Violation Rate (%) by Model and Category")
    fig.colorbar(im, ax=ax, label="Violation Rate (%)")
    fig.tight_layout()
    out = FIGURES / "model-category-heatmap.pdf"
    fig.savefig(out, bbox_inches="tight", dpi=200)
    plt.close(fig)
    return out


def plot_rule_hits(rule_analysis_path: Path) -> Path:
    """Horizontal bar chart of rule hit counts."""
    ra = json.loads(rule_analysis_path.read_text(encoding="utf-8"))
    rules = ra["rules"]

    fig, ax = plt.subplots(figsize=(7, 4.5))
    names = [r["rule"].replace("-", "\n") for r in reversed(rules)]
    hits = [r["hits"] for r in reversed(rules)]
    tp = [r["true_positives"] for r in reversed(rules)]
    fp = [r["false_positives"] for r in reversed(rules)]

    y = np.arange(len(names))
    ax.barh(y, tp, height=0.6, color="#2b8cbe", label="True Positive")
    ax.barh(y, fp, height=0.6, left=tp, color="#e34a33", label="False Positive")
    ax.set_yticks(y)
    ax.set_yticklabels(names, fontsize=7)
    ax.set_xlabel("Rule Firing Count")
    ax.legend(fontsize=8, loc="lower right")
    ax.set_title("Guard Rule Hit Frequency (11 rules, 321 total firings)")
    fig.tight_layout()
    out = FIGURES / "rule-hit-frequency.pdf"
    fig.savefig(out, bbox_inches="tight", dpi=200)
    plt.close(fig)
    return out


def plot_fn_categories(fn_analysis_path: Path) -> Path:
    """Pie chart of false negative miss reasons."""
    fn = json.loads(fn_analysis_path.read_text(encoding="utf-8"))
    reasons = fn["by_reason"]

    # Group small categories
    major = {k: v for k, v in reasons.items() if v > 50}
    other_count = sum(v for k, v in reasons.items() if k not in major)
    if other_count > 0:
        major["other"] = other_count

    labels = [k.replace("_", " ").title() for k in major.keys()]
    sizes = list(major.values())
    colors = plt.cm.Set2(np.linspace(0, 1, len(labels)))

    fig, ax = plt.subplots(figsize=(6, 5))
    wedges, texts, autotexts = ax.pie(sizes, labels=labels, autopct="%1.1f%%",
                                       colors=colors, startangle=140)
    for t in autotexts:
        t.set_fontsize(8)
    for t in texts:
        t.set_fontsize(8)
    ax.set_title(f"False Negative Reasons (n={fn['total_fns']})")
    fig.tight_layout()
    out = FIGURES / "fn-categories.pdf"
    fig.savefig(out, bbox_inches="tight", dpi=200)
    plt.close(fig)
    return out


def plot_recall_vs_violation(metrics_path: Path) -> Path:
    """Scatter plot: guard recall vs model violation rate."""
    metrics = json.loads(metrics_path.read_text(encoding="utf-8"))
    models = metrics["per_model"]

    fig, ax = plt.subplots(figsize=(6, 4.5))
    labels = []
    x_vals = []
    y_vals = []
    sizes = []

    for name, m in models.items():
        labels.append(name)
        x_vals.append(m["violation_rate"]["value"])
        y_vals.append(m["guard_recall"]["value"])
        sizes.append(m["total_actions"] / 20)

    ax.scatter(x_vals, y_vals, s=sizes, alpha=0.7, color="#2b8cbe", edgecolors="black", linewidth=0.5)

    for i, label in enumerate(labels):
        short = label.replace("DeepSeek-", "DS-").replace("Claude-", "C-")
        ax.annotate(short, (x_vals[i], y_vals[i]), textcoords="offset points",
                    xytext=(5, 5), fontsize=7)

    # Annotate Qwen-9B outlier
    ax.annotate("Qwen-9B:\nmostly narrative", (0.061, 0.059),
                textcoords="offset points", xytext=(30, -15),
                fontsize=7, color="#666",
                arrowprops=dict(arrowstyle="->", color="#666", lw=0.8))

    ax.set_xlabel("Model Violation Rate")
    ax.set_ylabel("Guard Recall")
    ax.set_title("Guard Recall vs. Model Violation Rate\n(bubble size ∝ action count)")
    ax.set_xlim(0, 0.8)
    ax.set_ylim(0, 0.3)
    fig.tight_layout()
    out = FIGURES / "recall-vs-violation.pdf"
    fig.savefig(out, bbox_inches="tight", dpi=200)
    plt.close(fig)
    return out


def plot_inter_rater(inter_rater_path: Path) -> Path | None:
    """Agreement matrix heatmap."""
    if not inter_rater_path.exists():
        print(f"Inter-rater results not yet available: {inter_rater_path}")
        return None
    ir = json.loads(inter_rater_path.read_text(encoding="utf-8"))
    agreement = ir["agreement_matrix"]

    cats = ["SAFE", "DANGEROUS", "NEEDS_REDACTION"]
    matrix = np.zeros((3, 3))
    for i, c1 in enumerate(cats):
        for j, c2 in enumerate(cats):
            key = f"{c1}_{c2}"
            matrix[i, j] = agreement.get(key, 0)

    fig, ax = plt.subplots(figsize=(5, 4))
    im = ax.imshow(matrix, cmap="Blues", aspect="auto")
    ax.set_xticks(range(3))
    ax.set_xticklabels([f"Qwen:\n{c}" for c in cats], fontsize=8)
    ax.set_yticks(range(3))
    ax.set_yticklabels([f"Claude:\n{c}" for c in cats], fontsize=8)

    for i in range(3):
        for j in range(3):
            color = "white" if matrix[i, j] > matrix.max() * 0.5 else "black"
            ax.text(j, i, f"{matrix[i,j]:.0f}", ha="center", va="center",
                    fontsize=12, color=color, fontweight="bold")

    ax.set_title(f"Inter-Rater Agreement\nCohen's κ = {ir['cohens_kappa']:.3f} ({ir['interpretation']})")
    fig.colorbar(im, ax=ax, label="Count")
    fig.tight_layout()
    out = FIGURES / "inter-rater-agreement.pdf"
    fig.savefig(out, bbox_inches="tight", dpi=200)
    plt.close(fig)
    return out


def main() -> None:
    metrics_path = RESULTS / "metrics.json"
    rule_path = RESULTS / "rule_analysis.json"
    fn_path = RESULTS / "false_negative_analysis.json"
    ir_path = RESULTS / "inter_rater_results.json"

    for path in [metrics_path, rule_path, fn_path]:
        if not path.exists():
            print(f"Missing: {path}")
            sys.exit(1)

    out1 = plot_model_category_heatmap(metrics_path)
    print(f"  {out1}")

    out2 = plot_rule_hits(rule_path)
    print(f"  {out2}")

    out3 = plot_fn_categories(fn_path)
    print(f"  {out3}")

    out4 = plot_recall_vs_violation(metrics_path)
    print(f"  {out4}")

    out5 = plot_inter_rater(ir_path)
    if out5:
        print(f"  {out5}")

    print("\nDone. Advanced figures generated.")


if __name__ == "__main__":
    main()
