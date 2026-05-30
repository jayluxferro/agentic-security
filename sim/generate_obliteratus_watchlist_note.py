#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

SIM_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = SIM_ROOT / "results"
REPLAY_NOTE_PATH = RESULTS_ROOT / "2026-03-30-obliteratus-replay-note.json"
ACCEPTANCE_MARGIN_NOTE_PATH = (
    RESULTS_ROOT / "2026-04-01-obliteratus-acceptance-margin-note.json"
)
OUTPUT_PATH = RESULTS_ROOT / "2026-04-01-obliteratus-watchlist-note.json"
METRIC_LABELS = {
    "risk_reduction_min": "risk reduction",
    "utility_with_policy_min": "retained utility",
    "blocked_by_policy_min": "blocked-by-policy coverage",
    "violations_with_policy_max": "residual violations",
}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _first_failure_row(candidate_ledgers: list[dict], metric: str) -> dict | None:
    for candidate in candidate_ledgers[1:]:
        if candidate["minimum_margin_by_metric"][metric] < 0:
            return candidate
    return None


def _metric_priority_rows(scenario_entry: dict) -> list[dict]:
    candidate_ledgers = scenario_entry["candidate_margin_ledgers"]
    baseline_rate = scenario_entry["baseline_policy_block_rate"]
    baseline_zero_reserve = set(candidate_ledgers[0]["zero_reserve_metrics"])
    rows = []
    for metric in candidate_ledgers[0]["minimum_margin_by_metric"]:
        failing_candidates = [
            candidate
            for candidate in candidate_ledgers[1:]
            if candidate["minimum_margin_by_metric"][metric] < 0
        ]
        first_failure = _first_failure_row(candidate_ledgers, metric)
        worst_margin = min(
            candidate["minimum_margin_by_metric"][metric]
            for candidate in candidate_ledgers
        )
        worst_candidate = next(
            candidate
            for candidate in candidate_ledgers
            if candidate["minimum_margin_by_metric"][metric] == worst_margin
        )
        rows.append(
            {
                "metric": metric,
                "baseline_zero_reserve": metric in baseline_zero_reserve,
                "first_failure_policy_block_rate": (
                    first_failure["policy_block_rate"] if first_failure else None
                ),
                "first_failure_delta_from_baseline": (
                    first_failure["policy_block_delta_from_baseline"]
                    if first_failure
                    else None
                ),
                "first_failure_count": (
                    first_failure["metric_failure_counts"][metric]
                    if first_failure
                    else 0
                ),
                "failing_candidate_count": len(failing_candidates),
                "worst_margin": worst_margin,
                "worst_margin_policy_block_rate": worst_candidate["policy_block_rate"],
                "worst_margin_delta_from_baseline": round(
                    baseline_rate - worst_candidate["policy_block_rate"], 6
                ),
            }
        )

    return sorted(
        rows,
        key=lambda row: (
            row["first_failure_delta_from_baseline"] is None,
            row["first_failure_delta_from_baseline"]
            if row["first_failure_delta_from_baseline"] is not None
            else float("inf"),
            row["worst_margin"],
            -row["failing_candidate_count"],
            row["metric"],
        ),
    )


def _scenario_metric_watchlist(acceptance_note: dict) -> list[dict]:
    watchlist = []
    for scenario_entry in acceptance_note["scenario_margin_ledgers"]:
        metric_priority = _metric_priority_rows(scenario_entry)
        failing_deltas = [
            row["first_failure_delta_from_baseline"]
            for row in metric_priority
            if row["first_failure_delta_from_baseline"] is not None
        ]
        earliest_delta = min(failing_deltas) if failing_deltas else None
        watchlist.append(
            {
                "scenario": scenario_entry["scenario"],
                "baseline_policy_block_rate": scenario_entry[
                    "baseline_policy_block_rate"
                ],
                "baseline_zero_reserve_metrics": scenario_entry[
                    "candidate_margin_ledgers"
                ][0]["zero_reserve_metrics"],
                "earliest_failure_delta_from_baseline": earliest_delta,
                "earliest_failure_metrics": [
                    row["metric"]
                    for row in metric_priority
                    if row["first_failure_delta_from_baseline"] == earliest_delta
                ],
                "metric_priority": metric_priority,
            }
        )
    return watchlist


def _replay_case_watchlist(replay_note: dict) -> list[dict]:
    probe_matrix = {entry["case_id"]: entry for entry in replay_note["probe_matrix"]}
    return [
        {
            "case_id": probe["case_id"],
            "source_suite_family": probe["source_suite_family"],
            "trace_origin": probe_matrix[probe["case_id"]]["trace_origin"],
            "task_class": probe_matrix[probe["case_id"]]["task_class"],
            "first_guard_decision": probe["first_guard_decision"],
            "first_guard_tactic": probe["first_guard_tactic"],
            "guard_layer_count": probe["guard_layer_count"],
            "follow_on_guarded_tactics": probe["follow_on_guarded_tactics"],
            "minimum_guard_failures_to_lose_prevention": probe[
                "minimum_guard_failures_to_lose_prevention"
            ],
            "residual_risk": probe_matrix[probe["case_id"]]["residual_risk"],
        }
        for probe in replay_note["regression_probes"]
    ]


def _cross_scenario_metric_priority(
    scenario_metric_watchlist: list[dict],
) -> list[dict]:
    by_scenario = {
        entry["scenario"]: {row["metric"]: row for row in entry["metric_priority"]}
        for entry in scenario_metric_watchlist
    }
    metrics = list(next(iter(by_scenario.values())).keys())
    rows = []
    for metric in metrics:
        per_scenario = {
            scenario: metric_rows[metric]
            for scenario, metric_rows in by_scenario.items()
        }
        scenarios_with_failure = [
            scenario
            for scenario, row in per_scenario.items()
            if row["failing_candidate_count"] > 0
        ]
        failure_deltas = [
            row["first_failure_delta_from_baseline"]
            for row in per_scenario.values()
            if row["first_failure_delta_from_baseline"] is not None
        ]
        earliest_delta = min(failure_deltas) if failure_deltas else None
        scenario_of_worst_margin, worst_row = min(
            per_scenario.items(),
            key=lambda item: (
                item[1]["worst_margin"],
                item[1]["worst_margin_delta_from_baseline"],
                item[0],
            ),
        )
        rows.append(
            {
                "metric": metric,
                "scenarios_with_failure": scenarios_with_failure,
                "earliest_failure_delta_from_baseline": earliest_delta,
                "combined_failing_candidate_count": sum(
                    row["failing_candidate_count"] for row in per_scenario.values()
                ),
                "worst_margin": worst_row["worst_margin"],
                "scenario_of_worst_margin": scenario_of_worst_margin,
                "policy_block_rate_of_worst_margin": worst_row[
                    "worst_margin_policy_block_rate"
                ],
            }
        )

    return sorted(
        rows,
        key=lambda row: (
            row["earliest_failure_delta_from_baseline"] is None,
            row["earliest_failure_delta_from_baseline"]
            if row["earliest_failure_delta_from_baseline"] is not None
            else float("inf"),
            row["worst_margin"],
            -row["combined_failing_candidate_count"],
            row["metric"],
        ),
    )


def _join_metric_labels(metrics: list[str]) -> str:
    labels = [METRIC_LABELS[metric] for metric in metrics]
    if len(labels) == 1:
        return labels[0]
    if len(labels) == 2:
        return f"{labels[0]} and {labels[1]}"
    return ", ".join(labels[:-1]) + f", and {labels[-1]}"


def _acceptance_note(
    replay_case_watchlist: list[dict], scenario_metric_watchlist: list[dict]
) -> str:
    default_entry = next(
        entry for entry in scenario_metric_watchlist if entry["scenario"] == "default"
    )
    stress_entry = next(
        entry for entry in scenario_metric_watchlist if entry["scenario"] == "stress"
    )
    return (
        "All four monitored metrics already sit at zero reserve in both scenarios, so future live or "
        "intervention-backed runs should always report the six replay watchlist cases alongside the scenario "
        "watchlist metrics. The earliest synthetic failures arrive at the first tested five-point policy-block "
        f"drop: default loses {_join_metric_labels(default_entry['earliest_failure_metrics'])} headroom first, "
        f"while stress loses {_join_metric_labels(stress_entry['earliest_failure_metrics'])} headroom at the same step."
    )


def build_artifact() -> dict:
    replay_note = _load_json(REPLAY_NOTE_PATH)
    acceptance_note = _load_json(ACCEPTANCE_MARGIN_NOTE_PATH)
    scenario_metric_watchlist = _scenario_metric_watchlist(acceptance_note)
    replay_case_watchlist = _replay_case_watchlist(replay_note)

    return {
        "artifact": "obliteratus-watchlist-note",
        "date": "2026-04-01",
        "paper": "Policy-Constrained Autonomous Agents for High-Risk Operations",
        "purpose": (
            "Combine the current acceptance-envelope metric pressure with the replay-backed first-guard regression "
            "surface, so future live or intervention-backed reviews can report the most fragile scenario metrics and "
            "the exact bounded cyber traces that must stay non-regressive."
        ),
        "supporting_artifacts": {
            "obliteratus_replay_note": "research/papers/agentic-security/sim/results/2026-03-30-obliteratus-replay-note.json",
            "obliteratus_acceptance_margin_note": "research/papers/agentic-security/sim/results/2026-04-01-obliteratus-acceptance-margin-note.json",
        },
        "evidence_boundary_note": (
            "This JSON does not claim a live OBLITERATUS run or causal links between specific replay tactics and "
            "scenario-metric deficits. It packages the current monitoring watchlist that future live or refusal-direction "
            "runs should report together before claiming non-regression."
        ),
        "scenario_metric_watchlist": scenario_metric_watchlist,
        "replay_case_watchlist": replay_case_watchlist,
        "cross_scenario_summary": {
            "baseline_zero_reserve_metrics_by_scenario": {
                entry["scenario"]: entry["baseline_zero_reserve_metrics"]
                for entry in scenario_metric_watchlist
            },
            "earliest_failure_metrics_by_scenario": {
                entry["scenario"]: entry["earliest_failure_metrics"]
                for entry in scenario_metric_watchlist
            },
            "cross_scenario_metric_priority": _cross_scenario_metric_priority(
                scenario_metric_watchlist
            ),
            "replay_first_guard_tactic_counts": replay_note[
                "regression_surface_summary"
            ]["first_guard_tactic_counts"],
            "watchlist_case_count": len(replay_case_watchlist),
            "cases_with_follow_on_guard_layers": replay_note[
                "regression_surface_summary"
            ]["cases_with_follow_on_guard_layers"],
        },
        "acceptance_note": _acceptance_note(
            replay_case_watchlist, scenario_metric_watchlist
        ),
    }


def main() -> None:
    artifact = build_artifact()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
