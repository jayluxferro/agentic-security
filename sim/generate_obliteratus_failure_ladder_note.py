#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

SIM_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = SIM_ROOT / "results"
ACCEPTANCE_MARGIN_NOTE_PATH = (
    RESULTS_ROOT / "2026-04-01-obliteratus-acceptance-margin-note.json"
)
WATCHLIST_NOTE_PATH = RESULTS_ROOT / "2026-04-01-obliteratus-watchlist-note.json"
OUTPUT_PATH = RESULTS_ROOT / "2026-04-01-obliteratus-failure-ladder-note.json"

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


def _watchlist_map(watchlist_note: dict) -> dict[str, dict]:
    return {
        entry["scenario"]: entry
        for entry in watchlist_note["scenario_metric_watchlist"]
    }


def _worst_metric_margin(minimum_margin_by_metric: dict[str, float]) -> dict:
    metric, margin = min(
        minimum_margin_by_metric.items(),
        key=lambda item: (item[1], item[0]),
    )
    return {
        "metric": metric,
        "metric_label": METRIC_LABELS[metric],
        "margin": margin,
    }


def _ladder_rows(scenario_ledger: dict) -> list[dict]:
    rows = []
    for candidate in scenario_ledger["candidate_margin_ledgers"]:
        rows.append(
            {
                "policy_block_rate": candidate["policy_block_rate"],
                "policy_block_delta_from_baseline": candidate[
                    "policy_block_delta_from_baseline"
                ],
                "metrics_below_floor": candidate["metrics_below_floor"],
                "zero_reserve_metrics": candidate["zero_reserve_metrics"],
                "metric_failure_counts": candidate["metric_failure_counts"],
                "total_failure_count": sum(candidate["metric_failure_counts"].values()),
                "worst_metric_margin": _worst_metric_margin(
                    candidate["minimum_margin_by_metric"]
                ),
            }
        )
    return rows


def _first_failure_step(rows: list[dict]) -> dict:
    for row in rows:
        if row["total_failure_count"] > 0:
            return {
                "policy_block_rate": row["policy_block_rate"],
                "policy_block_delta_from_baseline": row[
                    "policy_block_delta_from_baseline"
                ],
                "metrics_below_floor": row["metrics_below_floor"],
            }
    raise ValueError("Expected at least one failure step in the ladder")


def _metrics_never_below_floor(rows: list[dict], metric_names: list[str]) -> list[str]:
    return [
        metric
        for metric in metric_names
        if all(metric not in row["metrics_below_floor"] for row in rows)
    ]


def _max_failure_burden_step(rows: list[dict]) -> dict:
    worst = max(
        rows,
        key=lambda row: (
            row["total_failure_count"],
            row["policy_block_delta_from_baseline"],
        ),
    )
    return {
        "policy_block_rate": worst["policy_block_rate"],
        "policy_block_delta_from_baseline": worst["policy_block_delta_from_baseline"],
        "total_failure_count": worst["total_failure_count"],
        "worst_metric_margin": worst["worst_metric_margin"],
    }


def _scenario_failure_ladder(scenario_ledger: dict, watchlist_entry: dict) -> dict:
    rows = _ladder_rows(scenario_ledger)
    metric_names = list(scenario_ledger["acceptance_floor_reference"].keys())
    return {
        "scenario": scenario_ledger["scenario"],
        "baseline_policy_block_rate": scenario_ledger["baseline_policy_block_rate"],
        "baseline_zero_reserve_metrics": watchlist_entry[
            "baseline_zero_reserve_metrics"
        ],
        "earliest_failure_metrics": watchlist_entry["earliest_failure_metrics"],
        "failure_ladder": rows,
        "first_failure_step": _first_failure_step(rows),
        "metrics_never_below_floor": _metrics_never_below_floor(rows, metric_names),
        "max_failure_burden_step": _max_failure_burden_step(rows),
    }


def _cross_scenario_summary(scenario_ladders: list[dict]) -> dict:
    first_failure_deltas = {
        ladder["scenario"]: ladder["first_failure_step"][
            "policy_block_delta_from_baseline"
        ]
        for ladder in scenario_ladders
    }
    first_failure_metrics = {
        ladder["scenario"]: ladder["first_failure_step"]["metrics_below_floor"]
        for ladder in scenario_ladders
    }
    first_failure_rates = {
        ladder["scenario"]: ladder["first_failure_step"]["policy_block_rate"]
        for ladder in scenario_ladders
    }
    never_fail_sets = [
        set(ladder["metrics_never_below_floor"]) for ladder in scenario_ladders
    ]
    shared_never_fail = sorted(set.intersection(*never_fail_sets))
    shared_first_failure_metrics = sorted(
        set.intersection(
            *[
                set(ladder["first_failure_step"]["metrics_below_floor"])
                for ladder in scenario_ladders
            ]
        )
    )
    return {
        "first_failure_deltas_by_scenario": first_failure_deltas,
        "first_failure_policy_block_rates_by_scenario": first_failure_rates,
        "first_failure_metrics_by_scenario": first_failure_metrics,
        "same_first_failure_delta_across_scenarios": len(
            set(first_failure_deltas.values())
        )
        == 1,
        "shared_never_fail_metrics": shared_never_fail,
        "shared_first_failure_metrics": shared_first_failure_metrics,
    }


def _failure_ladder_note(scenario_ladders: list[dict], cross_summary: dict) -> str:
    ladders = {ladder["scenario"]: ladder for ladder in scenario_ladders}
    default = ladders["default"]
    stress = ladders["stress"]
    shared_never_fail_metrics = cross_summary["shared_never_fail_metrics"]
    shared_never_fail_clause = ""
    if shared_never_fail_metrics:
        shared_never_fail_clause = f" {_join_metric_labels(shared_never_fail_metrics).capitalize()} stays at or above floor across the current ladder in both scenarios."
    return (
        "The current OBLITERATUS failure ladder shows that both default and stress scenarios lose at least one acceptance-floor metric after a "
        f"{default['first_failure_step']['policy_block_delta_from_baseline']:.2f} policy-block-rate drop from baseline. "
        f"Default first fails on {_join_metric_labels(default['first_failure_step']['metrics_below_floor'])} at "
        f"{default['first_failure_step']['policy_block_rate']:.2f}, while stress first fails on "
        f"{_join_metric_labels(stress['first_failure_step']['metrics_below_floor'])} at "
        f"{stress['first_failure_step']['policy_block_rate']:.2f}.{shared_never_fail_clause}"
    )


def build_artifact() -> dict:
    acceptance_margin_note = _load_json(ACCEPTANCE_MARGIN_NOTE_PATH)
    watchlist_note = _load_json(WATCHLIST_NOTE_PATH)
    watchlist_map = _watchlist_map(watchlist_note)

    scenario_ladders = [
        _scenario_failure_ladder(
            scenario_ledger, watchlist_map[scenario_ledger["scenario"]]
        )
        for scenario_ledger in acceptance_margin_note["scenario_margin_ledgers"]
    ]
    cross_summary = _cross_scenario_summary(scenario_ladders)

    return {
        "artifact": "obliteratus-failure-ladder-note",
        "date": "2026-04-01",
        "paper": "Policy-Constrained Autonomous Agents for High-Risk Operations",
        "purpose": (
            "Condense the current acceptance-margin ledgers into a policy-block-rate failure ladder so future "
            "OBLITERATUS reviews can report the first failing metrics and the widening deficit set without re-reading "
            "the full per-seed margin tables."
        ),
        "supporting_artifacts": {
            "obliteratus_acceptance_margin_note": "research/papers/agentic-security/sim/results/2026-04-01-obliteratus-acceptance-margin-note.json",
            "obliteratus_watchlist_note": "research/papers/agentic-security/sim/results/2026-04-01-obliteratus-watchlist-note.json",
        },
        "evidence_boundary_note": (
            "This JSON does not claim a live OBLITERATUS run or new refusal-direction evidence. It only compresses the "
            "current synthetic acceptance-margin and watchlist bundle into a scenario-by-scenario failure ladder so future "
            "reviews can report when the current envelope first breaks and how the failure set expands."
        ),
        "scenario_failure_ladders": scenario_ladders,
        "cross_scenario_summary": cross_summary,
        "failure_ladder_note": _failure_ladder_note(scenario_ladders, cross_summary),
    }


def main() -> None:
    artifact = build_artifact()
    OUTPUT_PATH.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
