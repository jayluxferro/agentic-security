#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Rule-level analysis: hit frequency, per-rule precision/recall, rule×category matrix.

Computes for each of the 32 guard rules:
  - How many times it fired (hits)
  - How many of its hits were true positives (judge=DANGEROUS)
  - How many were false positives (judge=SAFE)
  - Per-category hit distribution
Outputs rule_analysis.json for the paper.
"""

from __future__ import annotations

import json
from collections import defaultdict
from pathlib import Path

EXPERIMENTS = Path(__file__).resolve().parent
RESULTS = EXPERIMENTS / "results"
SCORED_PATH = RESULTS / "scored_results.jsonl"
OUTPUT_PATH = RESULTS / "rule_analysis.json"


def wilson_ci(successes: int, trials: int, z: float = 1.96) -> tuple[float, float, float]:
    if trials == 0:
        return 0.0, 0.0, 0.0
    import math
    p = successes / trials
    denom = 1 + z * z / trials
    centre = (p + z * z / (2 * trials)) / denom
    margin = z * math.sqrt((p * (1 - p) + z * z / (4 * trials)) / trials) / denom
    return max(0.0, centre - margin), p, min(1.0, centre + margin)


def main() -> None:
    entries: list[dict] = []
    with open(SCORED_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))

    # Accumulate per-rule stats
    rules: dict[str, dict] = defaultdict(lambda: {
        "hits": 0, "tp": 0, "fp": 0,
        "categories": defaultdict(lambda: {"hits": 0, "tp": 0}),
    })

    total_fired = 0
    total_actions = 0

    for entry in entries:
        if entry.get("judge_status") != "ok":
            continue
        category = entry.get("category", "unknown")
        for action in entry.get("actions", []):
            total_actions += 1
            rule = action.get("guard_matched_rule")
            if rule is None:
                continue
            total_fired += 1
            judge = action.get("judge", "SAFE")
            rules[rule]["hits"] += 1
            rules[rule]["categories"][category]["hits"] += 1
            if judge == "DANGEROUS":
                rules[rule]["tp"] += 1
                rules[rule]["categories"][category]["tp"] += 1
            else:
                rules[rule]["fp"] += 1

    # Build output
    rule_list = []
    for name, data in sorted(rules.items(), key=lambda x: -x[1]["hits"]):
        precision_lo, precision_mean, precision_hi = wilson_ci(data["tp"], data["hits"])
        rule_list.append({
            "rule": name,
            "hits": data["hits"],
            "true_positives": data["tp"],
            "false_positives": data["fp"],
            "precision": round(precision_mean, 4),
            "precision_ci95": [round(precision_lo, 4), round(precision_hi, 4)],
            "pct_of_all_actions": round(data["hits"] / total_actions * 100, 2),
            "pct_of_fired_rules": round(data["hits"] / total_fired * 100, 1) if total_fired else 0,
            "categories": {
                cat: {"hits": cd["hits"], "tp": cd["tp"]}
                for cat, cd in sorted(data["categories"].items(), key=lambda x: -x[1]["hits"])
            },
        })

    # Rules that never fired
    all_rule_names = {
        "file-destruction", "privilege-escalation", "exfiltration-network",
        "persistence", "reverse-shell", "credential-dumping", "destructive-operations",
        "lateral-movement", "defense-evasion", "sensitive-file-read", "sensitive-data-exposure",
    }
    never_fired = sorted(all_rule_names - set(rules.keys()))

    output = {
        "experiment": "rule-level-analysis",
        "total_actions": total_actions,
        "total_rules": len(all_rule_names),
        "rules_that_fired": len(rules),
        "rules_never_fired": never_fired,
        "total_rule_firings": total_fired,
        "pct_actions_triggering_rule": round(total_fired / total_actions * 100, 2),
        "rules": rule_list,
    }

    OUTPUT_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"Rule analysis: {OUTPUT_PATH}")
    print(f"  {len(rules)} rules fired ({len(never_fired)} never fired)")
    print(f"  {total_fired}/{total_actions} actions triggered a rule ({total_fired/total_actions*100:.1f}%)")
    print(f"\nTop 5 rules:")
    for r in rule_list[:5]:
        print(f"  {r['rule']}: {r['hits']} hits, precision={r['precision']:.3f}")


if __name__ == "__main__":
    main()
