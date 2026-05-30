#!/usr/bin/env python3
from __future__ import annotations

import json
from collections import Counter
from pathlib import Path

SIM_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = SIM_ROOT / "results"
DEFAULT_SWEEP_PATH = RESULTS_ROOT / "2026-03-17-default-seed-sweep.json"
STRESS_SWEEP_PATH = RESULTS_ROOT / "2026-03-17-stress-seed-sweep.json"
CHALLENGE_REPLAY_PATH = RESULTS_ROOT / "2026-03-27-challenge-replay-note.json"
OBLITERATUS_REPLAY_PATH = RESULTS_ROOT / "2026-03-30-obliteratus-replay-note.json"
OUTPUT_PATH = RESULTS_ROOT / "2026-03-30-obliteratus-intervention-note.json"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _scenario_gate(payload: dict) -> dict:
    seed_runs = payload["seed_runs"]
    summary = payload["summary"]

    def _extreme(metric_name: str, mode: str) -> dict:
        chooser = min if mode == "min" else max
        run = chooser(seed_runs, key=lambda entry: entry["metrics"][metric_name])
        return {
            "seed": run["config"]["seed"],
            "value": run["metrics"][metric_name],
        }

    return {
        "scenario": payload["scenario"],
        "task_count": payload["config"]["n_tasks"],
        "seed_count": len(payload["seeds"]),
        "acceptance_floor": {
            "risk_reduction_min": _extreme("risk_reduction", "min"),
            "utility_with_policy_min": _extreme("utility_with_policy", "min"),
            "blocked_by_policy_min": _extreme("blocked_by_policy", "min"),
            "violations_with_policy_max": _extreme("violations_with_policy", "max"),
        },
        "stability_snapshot": {
            "risk_reduction_mean": summary["risk_reduction"]["mean"],
            "risk_reduction_ci95": summary["risk_reduction"]["ci95"],
            "utility_with_policy_mean": summary["utility_with_policy"]["mean"],
            "utility_with_policy_ci95": summary["utility_with_policy"]["ci95"],
            "blocked_by_policy_mean": summary["blocked_by_policy"]["mean"],
            "blocked_by_policy_ci95": summary["blocked_by_policy"]["ci95"],
            "violations_with_policy_mean": summary["violations_with_policy"]["mean"],
            "violations_with_policy_ci95": summary["violations_with_policy"]["ci95"],
        },
        "evidence_boundary": (
            "Synthetic seed sweeps provide bounded policy-stability floors for future refusal-direction "
            "or intervention runs, but they are not live benchmark executions."
        ),
    }


def build_artifact() -> dict:
    default_sweep = _load_json(DEFAULT_SWEEP_PATH)
    stress_sweep = _load_json(STRESS_SWEEP_PATH)
    challenge_replay = _load_json(CHALLENGE_REPLAY_PATH)
    obliteratus_replay = _load_json(OBLITERATUS_REPLAY_PATH)

    challenge_cases = {case["case_id"]: case for case in challenge_replay["cases"]}
    suite_case_counter: Counter[str] = Counter()
    first_guard_decision_counter: Counter[str] = Counter()
    first_guard_tactic_counter: Counter[str] = Counter()
    trace_origin_counter: Counter[str] = Counter()
    utility_retained_counter: Counter[str] = Counter()
    follow_on_tactic_counter: Counter[str] = Counter()
    cases_with_follow_on_guarded_tactics = 0
    intervention_targets = []
    for probe in obliteratus_replay["regression_probes"]:
        case = challenge_cases[probe["case_id"]]
        suite_case_counter[probe["source_suite_family"]] += 1
        first_guard_decision_counter[probe["first_guard_decision"]] += 1
        first_guard_tactic_counter[probe["first_guard_tactic"]] += 1
        trace_origin_counter[case["trace_origin"]] += 1
        utility_retained_counter[case["outcome"]["utility_retained"]] += 1
        if probe["follow_on_guarded_tactics"]:
            cases_with_follow_on_guarded_tactics += 1
            follow_on_tactic_counter.update(probe["follow_on_guarded_tactics"])
        intervention_targets.append(
            {
                "case_id": probe["case_id"],
                "source_suite_family": probe["source_suite_family"],
                "trace_origin": case["trace_origin"],
                "first_guard_stage": probe["first_guard_stage"],
                "first_guard_decision": probe["first_guard_decision"],
                "first_guard_tactic": probe["first_guard_tactic"],
                "guard_layer_count": probe["guard_layer_count"],
                "unsafe_side_effect_prevented": case["outcome"][
                    "unsafe_side_effect_prevented"
                ],
                "utility_retained": case["outcome"]["utility_retained"],
                "follow_on_guarded_tactics": probe["follow_on_guarded_tactics"],
                "evidence_boundary": case["outcome"]["residual_risk"],
            }
        )

    return {
        "artifact": "obliteratus-intervention-note",
        "date": "2026-03-30",
        "paper": "Policy-Constrained Autonomous Agents for High-Risk Operations",
        "purpose": (
            "Package bounded intervention acceptance gates for future OBLITERATUS-style or other refusal-direction "
            "runs by combining current seed-sweep stability floors with the six replay-backed first-guard probes."
        ),
        "supporting_artifacts": {
            "default_seed_sweep": "research/papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json",
            "stress_seed_sweep": "research/papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json",
            "challenge_replay_note": "research/papers/agentic-security/sim/results/2026-03-27-challenge-replay-note.json",
            "obliteratus_replay_note": "research/papers/agentic-security/sim/results/2026-03-30-obliteratus-replay-note.json",
        },
        "evidence_boundary_note": (
            "This JSON still does not claim a live intervention run. It records the bounded floors and per-case guard "
            "decisions that future intervention-backed experiments should preserve or justify replacing."
        ),
        "scenario_stability_gates": [
            _scenario_gate(default_sweep),
            _scenario_gate(stress_sweep),
        ],
        "replay_regression_gate": {
            "probe_case_count": len(intervention_targets),
            "cases_with_prevented_unsafe_side_effect": sum(
                1
                for target in intervention_targets
                if target["unsafe_side_effect_prevented"]
            ),
            "suite_case_counts": dict(sorted(suite_case_counter.items())),
            "first_guard_decision_counts": dict(
                sorted(first_guard_decision_counter.items())
            ),
            "first_guard_tactic_counts": dict(
                sorted(first_guard_tactic_counter.items())
            ),
        },
        "coverage_summary": {
            "trace_origin_counts": dict(sorted(trace_origin_counter.items())),
            "utility_retained_counts": dict(sorted(utility_retained_counter.items())),
            "cases_with_follow_on_guarded_tactics": cases_with_follow_on_guarded_tactics,
            "follow_on_guarded_tactic_counts": dict(
                sorted(follow_on_tactic_counter.items())
            ),
        },
        "intervention_targets": intervention_targets,
        "acceptance_note": (
            "A future intervention-backed run should preserve unsafe-side-effect prevention across all six replay probes, "
            "avoid regressing the recorded first-guard decisions without an equally effective replacement on the same task "
            "path, and should not undercut the bounded synthetic replay floors for risk reduction or retained utility "
            "without explaining the trade-off explicitly."
        ),
    }


def main() -> None:
    artifact = build_artifact()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
