#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

SIM_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = SIM_ROOT / "results"
README_PATH = SIM_ROOT / "README_OBLITERATUS.md"
REPLAY_NOTE_PATH = RESULTS_ROOT / "2026-03-30-obliteratus-replay-note.json"
INTERVENTION_NOTE_PATH = RESULTS_ROOT / "2026-03-30-obliteratus-intervention-note.json"
EROSION_NOTE_PATH = RESULTS_ROOT / "2026-03-31-obliteratus-erosion-note.json"
ACCEPTANCE_MARGIN_NOTE_PATH = (
    RESULTS_ROOT / "2026-04-01-obliteratus-acceptance-margin-note.json"
)
WATCHLIST_NOTE_PATH = RESULTS_ROOT / "2026-04-01-obliteratus-watchlist-note.json"
FOLLOWUP_PRIORITY_NOTE_PATH = (
    RESULTS_ROOT / "2026-04-01-obliteratus-followup-priority-note.json"
)
OUTPUT_PATH = RESULTS_ROOT / "2026-04-01-obliteratus-review-packet.json"

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


def _extract_minimum_reporting_fields(readme_path: Path) -> list[str]:
    lines = readme_path.read_text(encoding="utf-8").splitlines()
    in_section = False
    fields: list[str] = []
    for raw_line in lines:
        line = raw_line.strip()
        if line == "## Minimum reporting fields":
            in_section = True
            continue
        if in_section and line.startswith("## "):
            break
        if in_section and line.startswith("- "):
            fields.append(line[2:])
    if not fields:
        raise ValueError(
            "Could not find minimum reporting fields in README_OBLITERATUS.md"
        )
    return fields


def _required_report_sections(minimum_reporting_fields: list[str]) -> list[dict]:
    return [
        {
            "section": "run_identity_and_scope",
            "required_fields": minimum_reporting_fields[:3],
            "bundle_anchor_keys": [
                "scenario_stability_gates",
                "suite_priority_watchlist",
            ],
            "why_required": (
                "A future live or intervention-backed review has to identify the exact model, method, seed set, "
                "and suite coverage before any comparison against the current bounded replay bundle is meaningful."
            ),
        },
        {
            "section": "policy_and_utility_metrics",
            "required_fields": minimum_reporting_fields[3:5],
            "bundle_anchor_keys": [
                "scenario_stability_gates",
                "policy_erosion_summary",
                "acceptance_margin_summary",
                "scenario_metric_watchlist",
            ],
            "why_required": (
                "The current envelope is defined by scenario-specific stability floors plus the earliest-failure and "
                "worst-deficit summaries, so any new run must report the same policy and utility metrics with pre/post "
                "comparability."
            ),
        },
        {
            "section": "failure_cases_and_regressions",
            "required_fields": minimum_reporting_fields[5:],
            "bundle_anchor_keys": [
                "replay_regression_gate",
                "replay_case_watchlist",
                "suite_priority_watchlist",
                "case_priority_watchlist",
            ],
            "why_required": (
                "The current bundle is grounded by six replay-backed guarded traces, so future OBLITERATUS reviews must "
                "show which cases regressed, which guard layers held, and which thin suite lanes were exercised."
            ),
        },
    ]


def _priority_metric_labels(cross_scenario_metric_priority: list[dict]) -> list[dict]:
    rows = []
    for entry in cross_scenario_metric_priority:
        rows.append(
            {
                **entry,
                "metric_label": METRIC_LABELS[entry["metric"]],
            }
        )
    return rows


def _thinnest_suites(suite_priority_watchlist: list[dict]) -> list[str]:
    min_count = min(entry["grounded_case_count"] for entry in suite_priority_watchlist)
    return [
        entry["suite"]
        for entry in suite_priority_watchlist
        if entry["grounded_case_count"] == min_count
    ]


def _smallest_drop_summary(erosion_note: dict) -> dict:
    smallest_drop = erosion_note["cross_scenario_summary"][
        "smallest_policy_block_drop_triggering_any_failure"
    ]
    return {
        "default": smallest_drop["default"],
        "stress": smallest_drop["stress"],
        "same_across_scenarios": smallest_drop["default"] == smallest_drop["stress"],
    }


def _review_readiness_summary(
    replay_note: dict,
    erosion_note: dict,
    watchlist_note: dict,
    followup_note: dict,
) -> dict:
    cross_scenario_summary = watchlist_note["cross_scenario_summary"]
    return {
        "current_bundle_has_live_obliteratus_run": False,
        "regression_case_count": replay_note["regression_gate"]["case_count"],
        "suite_case_counts": replay_note["regression_gate"]["suite_case_counts"],
        "suites_without_live_cases": followup_note["cross_case_summary"][
            "suites_without_live_cases"
        ],
        "thinnest_suites": _thinnest_suites(followup_note["suite_priority_watchlist"]),
        "smallest_policy_block_drop_triggering_any_failure": _smallest_drop_summary(
            erosion_note
        ),
        "baseline_zero_reserve_metrics_by_scenario": cross_scenario_summary[
            "baseline_zero_reserve_metrics_by_scenario"
        ],
        "earliest_failure_metrics_by_scenario": cross_scenario_summary[
            "earliest_failure_metrics_by_scenario"
        ],
        "priority_metric_labels": _priority_metric_labels(
            cross_scenario_summary["cross_scenario_metric_priority"]
        ),
        "single_guard_case_ids": followup_note["cross_case_summary"][
            "cases_with_single_guard_layer"
        ],
        "transform_first_guard_case_ids": followup_note["cross_case_summary"][
            "transform_first_guard_case_ids"
        ],
    }


def _review_packet(
    replay_note: dict,
    intervention_note: dict,
    erosion_note: dict,
    acceptance_margin_note: dict,
    watchlist_note: dict,
    followup_note: dict,
) -> dict:
    return {
        "replay_regression_gate": replay_note["regression_gate"],
        "scenario_stability_gates": intervention_note["scenario_stability_gates"],
        "policy_erosion_summary": erosion_note["cross_scenario_summary"],
        "acceptance_margin_summary": acceptance_margin_note["cross_scenario_summary"],
        "scenario_metric_watchlist": watchlist_note["scenario_metric_watchlist"],
        "replay_case_watchlist": watchlist_note["replay_case_watchlist"],
        "suite_priority_watchlist": followup_note["suite_priority_watchlist"],
        "case_priority_watchlist": followup_note["case_priority_watchlist"],
    }


def _review_packet_note(
    replay_note: dict,
    erosion_note: dict,
    watchlist_note: dict,
    followup_note: dict,
) -> str:
    regression_case_count = replay_note["regression_gate"]["case_count"]
    thinnest_suites = _thinnest_suites(followup_note["suite_priority_watchlist"])
    smallest_drop = _smallest_drop_summary(erosion_note)
    earliest_failure_metrics = watchlist_note["cross_scenario_summary"][
        "earliest_failure_metrics_by_scenario"
    ]
    return (
        "The current OBLITERATUS review packet remains non-live: "
        f"{regression_case_count} replay-backed guarded cases span the current bundle, every suite still lacks a live trace, "
        f"and the first acceptance-envelope break arrives after a {smallest_drop['default']:.2f} policy-block-rate drop in both default and stress scenarios. "
        f"The next intervention-backed review should start with {_format_suite_list(thinnest_suites)} while continuing to report "
        f"default-side earliest failures in {_join_metric_labels(earliest_failure_metrics['default'])} and stress-side earliest "
        f"failures in {_join_metric_labels(earliest_failure_metrics['stress'])}."
    )


def build_artifact() -> dict:
    replay_note = _load_json(REPLAY_NOTE_PATH)
    intervention_note = _load_json(INTERVENTION_NOTE_PATH)
    erosion_note = _load_json(EROSION_NOTE_PATH)
    acceptance_margin_note = _load_json(ACCEPTANCE_MARGIN_NOTE_PATH)
    watchlist_note = _load_json(WATCHLIST_NOTE_PATH)
    followup_note = _load_json(FOLLOWUP_PRIORITY_NOTE_PATH)
    minimum_reporting_fields = _extract_minimum_reporting_fields(README_PATH)

    return {
        "artifact": "obliteratus-review-packet",
        "date": "2026-04-01",
        "paper": "Policy-Constrained Autonomous Agents for High-Risk Operations",
        "purpose": (
            "Collapse the current replay, intervention, erosion, acceptance-margin, watchlist, and follow-up-priority "
            "notes into one explicit review contract for the next live or intervention-backed OBLITERATUS assessment."
        ),
        "supporting_artifacts": {
            "obliteratus_integration_notes": "research/papers/agentic-security/sim/README_OBLITERATUS.md",
            "obliteratus_replay_note": "research/papers/agentic-security/sim/results/2026-03-30-obliteratus-replay-note.json",
            "obliteratus_intervention_note": "research/papers/agentic-security/sim/results/2026-03-30-obliteratus-intervention-note.json",
            "obliteratus_erosion_note": "research/papers/agentic-security/sim/results/2026-03-31-obliteratus-erosion-note.json",
            "obliteratus_acceptance_margin_note": "research/papers/agentic-security/sim/results/2026-04-01-obliteratus-acceptance-margin-note.json",
            "obliteratus_watchlist_note": "research/papers/agentic-security/sim/results/2026-04-01-obliteratus-watchlist-note.json",
            "obliteratus_followup_priority_note": "research/papers/agentic-security/sim/results/2026-04-01-obliteratus-followup-priority-note.json",
        },
        "evidence_boundary_note": (
            "This JSON does not claim a live OBLITERATUS run or any new refusal-direction result. It packages the current "
            "non-live replay, stability-floor, erosion, watchlist, and follow-up artifacts into a single review contract so "
            "future runs can report the same required fields and regressions against a synchronized baseline."
        ),
        "minimum_reporting_fields": minimum_reporting_fields,
        "required_report_sections": _required_report_sections(minimum_reporting_fields),
        "review_readiness_summary": _review_readiness_summary(
            replay_note,
            erosion_note,
            watchlist_note,
            followup_note,
        ),
        "review_packet": _review_packet(
            replay_note,
            intervention_note,
            erosion_note,
            acceptance_margin_note,
            watchlist_note,
            followup_note,
        ),
        "review_packet_note": _review_packet_note(
            replay_note,
            erosion_note,
            watchlist_note,
            followup_note,
        ),
    }


def main() -> None:
    artifact = build_artifact()
    OUTPUT_PATH.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
