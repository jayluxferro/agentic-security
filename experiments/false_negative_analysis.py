#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""False negative analysis: categorize the 1,441 dangerous actions the guard missed.

Groups FNs by:
  1. Action type (curl, SSH, PHP, Python, bash, etc.)
  2. Why the guard missed it (no matching rule, abstract description, parameterized command)
  3. Per-category distribution
Outputs false_negative_analysis.json.
"""

from __future__ import annotations

import json
import re
from collections import Counter, defaultdict
from pathlib import Path

EXPERIMENTS = Path(__file__).resolve().parent
RESULTS = EXPERIMENTS / "results"
SCORED_PATH = RESULTS / "scored_results.jsonl"
OUTPUT_PATH = RESULTS / "false_negative_analysis.json"


def classify_action_type(action_text: str) -> str:
    """Classify an action into a high-level type."""
    text = action_text.lower()
    if "curl" in text:
        return "curl/http"
    if re.search(r"\bssh\b", text):
        return "ssh"
    if re.search(r"\bwget\b", text):
        return "wget"
    if re.search(r"\bnc\b|ncat|netcat", text):
        return "netcat"
    if re.search(r"\bpython", text):
        return "python"
    if re.search(r"\bphp\b", text):
        return "php"
    if re.search(r"\bnmap\b", text):
        return "nmap"
    if re.search(r"\bsqlmap\b", text):
        return "sqlmap"
    if re.search(r"\bhydra\b|hashcat|john\b", text):
        return "credential_tool"
    if re.search(r"\bdocker\b", text):
        return "docker"
    if re.search(r"\bsudo\b|chmod|chown", text):
        return "privilege_ops"
    if re.search(r"\bcrontab|systemctl|at\b", text):
        return "scheduling"
    if re.search(r"\bcat\b|ls\b|find\b|grep\b|head\b|tail\b", text):
        return "file_ops"
    if re.search(r"\becho\b", text):
        return "echo/write"
    if re.search(r"\bgit\b", text):
        return "git"
    if re.search(r"\bscp\b|rsync|sftp", text):
        return "file_transfer"
    if re.search(r"\btar\b|gzip|bzip|zip\b", text):
        return "compression"
    if ">" in text or "|" in text:
        return "shell_pipeline"
    return "other"


def classify_miss_reason(action_text: str, category: str) -> str:
    """Why did the guard miss this dangerous action?"""
    text = action_text.lower()
    # Check if it's an abstract description (no command)
    if not re.search(r"\b(curl|wget|ssh|nmap|python|php|bash|nc|ncat|sudo|docker|cat|ls|find|grep|echo|sqlmap|hydra|hashcat|crontab|systemctl|git|scp|rsync)\b", text):
        if len(text.split()) < 5:
            return "too_short"
        return "abstract_description"
    # Check if it's a curl/web-based attack (no rule covers these well)
    if re.search(r"\bcurl\b", text):
        if re.search(r"\bcurl\b.*(-d|--data)", text):
            return "curl_data_exfil"  # Should match exfiltration rule but doesn't
        return "curl_web_attack"  # curl used for web exploitation
    if re.search(r"\bwget\b", text):
        return "wget_web_attack"
    # Check if it's SSH-based lateral movement
    if re.search(r"\bssh\b", text) and not re.search(r"\bsshpass\b|psexec\b", text):
        return "ssh_lateral"  # Standard SSH, not caught by lateral-movement rule
    # Check parameterized command
    if re.search(r"(localhost|127\.0\.0\.1|\.\.\/)", text) and re.search(r"\bcurl\b|wget\b", text):
        return "local_exploitation"  # Local exploitation, not external exfiltration
    # Check Python/PHP scripts
    if re.search(r"\bpython\b|php\b", text):
        return "script_language"
    # Catch-all
    if re.search(r"\b(cat|find|grep)\b", text) and re.search(r"(/etc/|\.env|\.ssh|/root/)", text):
        return "sensitive_read_not_caught"
    return "other_command"


def main() -> None:
    entries: list[dict] = []
    with open(SCORED_PATH, encoding="utf-8") as f:
        for line in f:
            if line.strip():
                entries.append(json.loads(line))

    # Collect all FNs
    fns: list[dict] = []
    for entry in entries:
        if entry.get("judge_status") != "ok":
            continue
        category = entry.get("category", "unknown")
        model = entry.get("model_label", "unknown")
        for action in entry.get("actions", []):
            if action.get("judge") == "DANGEROUS" and action.get("guard_decision") == "allow":
                fns.append({
                    "action": action["action"],
                    "category": category,
                    "model": model,
                    "action_type": classify_action_type(action["action"]),
                    "miss_reason": classify_miss_reason(action["action"], category),
                })

    # Aggregate
    type_counts = Counter(f["action_type"] for f in fns)
    reason_counts = Counter(f["miss_reason"] for f in fns)
    cat_counts = Counter(f["category"] for f in fns)
    model_counts = Counter(f["model"] for f in fns)

    # Per-category per-reason cross-tab
    cat_reason = defaultdict(lambda: Counter())
    for f in fns:
        cat_reason[f["category"]][f["miss_reason"]] += 1

    # Sample FNs for each major category
    samples: dict[str, list[str]] = {}
    for cat in sorted(cat_counts.keys()):
        cat_fns = [f for f in fns if f["category"] == cat]
        samples[cat] = [f["action"][:200] for f in cat_fns[:5]]

    output = {
        "experiment": "false-negative-analysis",
        "total_fns": len(fns),
        "total_dangerous": sum(1 for e in entries if e.get("judge_status") == "ok"
                               for a in e.get("actions", []) if a.get("judge") == "DANGEROUS"),
        "fn_rate": round(len(fns) / max(1, sum(
            1 for e in entries if e.get("judge_status") == "ok"
            for a in e.get("actions", []) if a.get("judge") == "DANGEROUS"
        )), 4),
        "by_type": dict(type_counts.most_common(20)),
        "by_reason": dict(reason_counts.most_common()),
        "by_category": dict(cat_counts.most_common()),
        "by_model": dict(model_counts.most_common()),
        "category_x_reason": {cat: dict(reasons) for cat, reasons in cat_reason.items()},
        "samples": samples,
    }

    OUTPUT_PATH.write_text(json.dumps(output, indent=2), encoding="utf-8")
    print(f"False negative analysis: {OUTPUT_PATH}")
    print(f"  Total FNs: {len(fns)}")
    print(f"\nTop action types:")
    for typ, count in type_counts.most_common(10):
        print(f"  {typ}: {count} ({count/len(fns)*100:.1f}%)")
    print(f"\nTop miss reasons:")
    for reason, count in reason_counts.most_common(10):
        print(f"  {reason}: {count} ({count/len(fns)*100:.1f}%)")


if __name__ == "__main__":
    main()
