#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

SIM_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = SIM_ROOT / "results"
REPLAY_NOTE_PATH = RESULTS_ROOT / "2026-03-30-obliteratus-replay-note.json"
WATCHLIST_NOTE_PATH = RESULTS_ROOT / "2026-04-01-obliteratus-watchlist-note.json"
OUTPUT_PATH = RESULTS_ROOT / "2026-04-01-obliteratus-followup-priority-note.json"

METRIC_LABELS = {
    "risk_reduction_min": "risk reduction",
    "utility_with_policy_min": "retained utility",
    "blocked_by_policy_min": "blocked-by-policy coverage",
    "violations_with_policy_max": "residual violations",
}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _join_metric_labels(metrics: list[str]) -> str:
    labels = [METRIC_LABELS[metric] for metric in metrics]
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]}"
    return ", ".join(labels[:-1]) + f", and {labels[-1]}"


def _format_suite_list(suites: list[str]) -> str:
    if len(suites) == 1:
        return suites[0]
    if len(suites) == 2:
        return f"{suites[0]} and {suites[1]}"
    return ", ".join(suites[:-1]) + f", and {suites[-1]}"


def _suite_priority_watchlist(replay_note: dict) -> list[dict]:
    probe_matrix = {entry["case_id"]: entry for entry in replay_note["probe_matrix"]}
    regressions = replay_note["regression_probes"]
    alignments = {entry["suite"]: entry for entry in replay_note["suite_alignment"]}
    total_cases = replay_note["regression_gate"]["case_count"]
    rows = []
    for suite, alignment in alignments.items():
        suite_probes = [
            probe for probe in regressions if probe["source_suite_family"] == suite
        ]
        rows.append(
            {
                "suite": suite,
                "grounded_case_count": alignment["grounded_case_count"],
                "case_share_of_current_replay_bundle": round(
                    alignment["grounded_case_count"] / total_cases, 6
                ),
                "reconstructed_case_count": alignment["reconstructed_case_count"],
                "benchmark_derived_case_count": alignment[
                    "benchmark_derived_case_count"
                ],
                "current_trace_origins": sorted(
                    {
                        probe_matrix[probe["case_id"]]["trace_origin"]
                        for probe in suite_probes
                    }
                ),
                "first_guard_tactics": sorted(
                    {probe["first_guard_tactic"] for probe in suite_probes}
                ),
                "cases_with_single_guard_layer": sum(
                    probe["guard_layer_count"] == 1 for probe in suite_probes
                ),
                "cases_with_follow_on_guard_layers": sum(
                    bool(probe["follow_on_guarded_tactics"]) for probe in suite_probes
                ),
                "requires_live_trace": True,
                "current_gap": alignment["current_gap"],
            }
        )

    return sorted(
        rows,
        key=lambda row: (
            row["grounded_case_count"],
            row["benchmark_derived_case_count"],
            row["suite"],
        ),
    )


def _case_priority_watchlist(replay_note: dict) -> list[dict]:
    probe_matrix = {entry["case_id"]: entry for entry in replay_note["probe_matrix"]}
    suite_case_counts = {
        entry["suite"]: entry["grounded_case_count"]
        for entry in replay_note["suite_alignment"]
    }
    rows = []
    for probe in replay_note["regression_probes"]:
        matrix_entry = probe_matrix[probe["case_id"]]
        suite_case_count = suite_case_counts[probe["source_suite_family"]]
        priority_flags = []
        if suite_case_count == 1:
            priority_flags.append("single-case-suite")
        if probe["guard_layer_count"] == 1:
            priority_flags.append("single-guard-layer")
        priority_flags.append(f"{matrix_entry['trace_origin']}-trace")
        if probe["follow_on_guarded_tactics"]:
            priority_flags.append("follow-on-guard-chain")
        rows.append(
            {
                "case_id": probe["case_id"],
                "source_suite_family": probe["source_suite_family"],
                "trace_origin": matrix_entry["trace_origin"],
                "task_class": matrix_entry["task_class"],
                "suite_grounded_case_count": suite_case_count,
                "first_guard_decision": probe["first_guard_decision"],
                "first_guard_tactic": probe["first_guard_tactic"],
                "guard_layer_count": probe["guard_layer_count"],
                "follow_on_guarded_tactics": probe["follow_on_guarded_tactics"],
                "minimum_guard_failures_to_lose_prevention": probe[
                    "minimum_guard_failures_to_lose_prevention"
                ],
                "priority_flags": priority_flags,
                "residual_risk": matrix_entry["residual_risk"],
            }
        )

    return sorted(
        rows,
        key=lambda row: (
            row["suite_grounded_case_count"],
            row["guard_layer_count"],
            row["case_id"],
        ),
    )


def _cross_case_summary(replay_note: dict, watchlist_note: dict) -> dict:
    probe_matrix = replay_note["probe_matrix"]
    case_priority_watchlist = _case_priority_watchlist(replay_note)
    trace_origin_counts = Counter(entry["trace_origin"] for entry in probe_matrix)
    suites = [entry["suite"] for entry in replay_note["suite_alignment"]]
    return {
        "total_case_count": replay_note["regression_gate"]["case_count"],
        "suite_case_counts": replay_note["regression_gate"]["suite_case_counts"],
        "trace_origin_counts": dict(sorted(trace_origin_counts.items())),
        "suites_without_live_cases": sorted(suites),
        "suites_with_single_case": sorted(
            entry["suite"]
            for entry in replay_note["suite_alignment"]
            if entry["grounded_case_count"] == 1
        ),
        "cases_with_single_guard_layer": [
            row["case_id"]
            for row in case_priority_watchlist
            if row["guard_layer_count"] == 1
        ],
        "transform_first_guard_case_ids": [
            row["case_id"]
            for row in case_priority_watchlist
            if row["first_guard_decision"] == "transform"
        ],
        "cases_with_follow_on_guard_layers": [
            row["case_id"]
            for row in case_priority_watchlist
            if row["follow_on_guarded_tactics"]
        ],
        "first_guard_decision_counts": replay_note["regression_surface_summary"][
            "first_guard_decision_counts"
        ],
        "first_guard_tactic_counts": replay_note["regression_surface_summary"][
            "first_guard_tactic_counts"
        ],
        "earliest_failure_metrics_by_scenario": watchlist_note[
            "cross_scenario_summary"
        ]["earliest_failure_metrics_by_scenario"],
        "cross_scenario_metric_priority": watchlist_note["cross_scenario_summary"][
            "cross_scenario_metric_priority"
        ],
    }


def _followup_note(
    suite_priority_watchlist: list[dict],
    case_priority_watchlist: list[dict],
    cross_case_summary: dict,
) -> str:
    min_suite_count = min(
        entry["grounded_case_count"] for entry in suite_priority_watchlist
    )
    thinnest_suites = [
        entry["suite"]
        for entry in suite_priority_watchlist
        if entry["grounded_case_count"] == min_suite_count
    ]
    single_guard_case = next(
        row for row in case_priority_watchlist if row["guard_layer_count"] == 1
    )
    transform_case = next(
        row
        for row in case_priority_watchlist
        if row["first_guard_decision"] == "transform"
    )
    largest_suite = max(
        suite_priority_watchlist, key=lambda entry: entry["grounded_case_count"]
    )
    default_metrics = cross_case_summary["earliest_failure_metrics_by_scenario"][
        "default"
    ]
    stress_metrics = cross_case_summary["earliest_failure_metrics_by_scenario"][
        "stress"
    ]
    return (
        "The next live or intervention-backed OBLITERATUS review should start with "
        f"{_format_suite_list(thinnest_suites)}, because each currently has only {min_suite_count} grounded case "
        "and no live trace. "
        f"{single_guard_case['case_id']} is the thinnest single-case surface because it has the only one-layer first "
        f"guard in the current bundle, while {transform_case['case_id']} remains the only transform-first replay. "
        f"{largest_suite['suite']} still contributes {largest_suite['grounded_case_count']} of "
        f"{cross_case_summary['total_case_count']} current cases, so additional work there should focus on converting "
        "the benchmark-derived traces into logged live replays rather than only expanding the same-family non-live "
        "coverage. Any such run should still report the current earliest failure metrics — default: "
        f"{_join_metric_labels(default_metrics)}; stress: {_join_metric_labels(stress_metrics)}."
    )


def build_artifact() -> dict:
    replay_note = _load_json(REPLAY_NOTE_PATH)
    watchlist_note = _load_json(WATCHLIST_NOTE_PATH)
    suite_priority_watchlist = _suite_priority_watchlist(replay_note)
    case_priority_watchlist = _case_priority_watchlist(replay_note)
    cross_case_summary = _cross_case_summary(replay_note, watchlist_note)
    return {
        "artifact": "obliteratus-followup-priority-note",
        "date": "2026-04-01",
        "paper": "Policy-Constrained Autonomous Agents for High-Risk Operations",
        "purpose": (
            "Turn the current replay-readiness and monitoring-watchlist bundle into an explicit follow-up ledger for the "
            "next live or intervention-backed OBLITERATUS review, so the thinnest suite lanes and single-layer guard "
            "surfaces are visible before new non-live coverage is added."
        ),
        "supporting_artifacts": {
            "obliteratus_replay_note": "research/papers/agentic-security/sim/results/2026-03-30-obliteratus-replay-note.json",
            "obliteratus_watchlist_note": "research/papers/agentic-security/sim/results/2026-04-01-obliteratus-watchlist-note.json",
        },
        "evidence_boundary_note": (
            "This JSON does not claim a live OBLITERATUS run or case-to-metric causality. It only prioritizes follow-up "
            "work from the current non-live replay/watchlist bundle so the next intervention-backed review can expand the "
            "weakest grounded lanes first while continuing to report the shared zero-reserve metric watchlist."
        ),
        "suite_priority_watchlist": suite_priority_watchlist,
        "case_priority_watchlist": case_priority_watchlist,
        "cross_case_summary": cross_case_summary,
        "followup_note": _followup_note(
            suite_priority_watchlist,
            case_priority_watchlist,
            cross_case_summary,
        ),
    }


def main() -> None:
    artifact = build_artifact()
    OUTPUT_PATH.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(f"wrote {OUTPUT_PATH}")


if __name__ == "__main__":
    main()
