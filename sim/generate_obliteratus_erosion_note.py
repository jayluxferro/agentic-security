#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

import run_policy_eval

SIM_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = SIM_ROOT / "results"
DEFAULT_SWEEP_PATH = RESULTS_ROOT / "2026-03-17-default-seed-sweep.json"
STRESS_SWEEP_PATH = RESULTS_ROOT / "2026-03-17-stress-seed-sweep.json"
INTERVENTION_NOTE_PATH = RESULTS_ROOT / "2026-03-30-obliteratus-intervention-note.json"
OUTPUT_PATH = RESULTS_ROOT / "2026-03-31-obliteratus-erosion-note.json"
EROSION_SCHEDULES = {
    "default": [0.72, 0.67, 0.62, 0.57, 0.52],
    "stress": [0.65, 0.60, 0.55, 0.50, 0.45],
}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _candidate_run(
    scenario_payload: dict,
    *,
    scenario: str,
    policy_block_rate: float,
    acceptance_floor: dict,
) -> dict:
    config = scenario_payload["config"]
    sweep_payload = run_policy_eval.run_seed_sweep(
        run_policy_eval.EvalConfig(
            seed=config["seed"],
            n_tasks=config["n_tasks"],
            base_violation_rate=config["base_violation_rate"],
            policy_block_rate=policy_block_rate,
            utility_penalty=config["utility_penalty"],
        ),
        seeds=scenario_payload["seeds"],
        scenario=scenario,
    )

    failing_seeds = []
    metric_failure_counts = {
        "risk_reduction_min": 0,
        "utility_with_policy_min": 0,
        "blocked_by_policy_min": 0,
        "violations_with_policy_max": 0,
    }
    for seed_run in sweep_payload["seed_runs"]:
        metrics = seed_run["metrics"]
        failing_metrics = []
        if metrics["risk_reduction"] < acceptance_floor["risk_reduction_min"]["value"]:
            metric_failure_counts["risk_reduction_min"] += 1
            failing_metrics.append("risk_reduction_min")
        if (
            metrics["utility_with_policy"]
            < acceptance_floor["utility_with_policy_min"]["value"]
        ):
            metric_failure_counts["utility_with_policy_min"] += 1
            failing_metrics.append("utility_with_policy_min")
        if (
            metrics["blocked_by_policy"]
            < acceptance_floor["blocked_by_policy_min"]["value"]
        ):
            metric_failure_counts["blocked_by_policy_min"] += 1
            failing_metrics.append("blocked_by_policy_min")
        if (
            metrics["violations_with_policy"]
            > acceptance_floor["violations_with_policy_max"]["value"]
        ):
            metric_failure_counts["violations_with_policy_max"] += 1
            failing_metrics.append("violations_with_policy_max")
        if failing_metrics:
            failing_seeds.append(
                {
                    "seed": seed_run["config"]["seed"],
                    "failing_metrics": failing_metrics,
                }
            )

    summary = sweep_payload["summary"]
    return {
        "policy_block_rate": policy_block_rate,
        "policy_block_delta_from_baseline": round(
            scenario_payload["config"]["policy_block_rate"] - policy_block_rate, 6
        ),
        "seed_failure_count": len(failing_seeds),
        "failing_seeds": failing_seeds,
        "metric_failure_counts": metric_failure_counts,
        "summary_snapshot": {
            "risk_reduction_mean": summary["risk_reduction"]["mean"],
            "risk_reduction_ci95": summary["risk_reduction"]["ci95"],
            "blocked_by_policy_mean": summary["blocked_by_policy"]["mean"],
            "blocked_by_policy_ci95": summary["blocked_by_policy"]["ci95"],
            "violations_with_policy_mean": summary["violations_with_policy"]["mean"],
            "violations_with_policy_ci95": summary["violations_with_policy"]["ci95"],
            "utility_with_policy_mean": summary["utility_with_policy"]["mean"],
            "utility_with_policy_ci95": summary["utility_with_policy"]["ci95"],
        },
    }


def _scenario_summary(
    scenario_payload: dict,
    *,
    scenario: str,
    acceptance_floor: dict,
    schedule: list[float],
) -> dict:
    candidate_runs = [
        _candidate_run(
            scenario_payload,
            scenario=scenario,
            policy_block_rate=policy_block_rate,
            acceptance_floor=acceptance_floor,
        )
        for policy_block_rate in schedule
    ]

    return {
        "scenario": scenario,
        "baseline_policy_block_rate": scenario_payload["config"]["policy_block_rate"],
        "acceptance_floor_reference": acceptance_floor,
        "candidate_runs": candidate_runs,
    }


def build_artifact() -> dict:
    intervention_note = _load_json(INTERVENTION_NOTE_PATH)
    scenario_payloads = {
        "default": _load_json(DEFAULT_SWEEP_PATH),
        "stress": _load_json(STRESS_SWEEP_PATH),
    }
    floor_by_scenario = {
        entry["scenario"]: entry["acceptance_floor"]
        for entry in intervention_note["scenario_stability_gates"]
    }

    scenario_erosion_sweeps = [
        _scenario_summary(
            scenario_payloads[scenario],
            scenario=scenario,
            acceptance_floor=floor_by_scenario[scenario],
            schedule=EROSION_SCHEDULES[scenario],
        )
        for scenario in ("default", "stress")
    ]

    smallest_policy_block_drop_triggering_any_failure = {}
    first_drop_failure_metrics = {}
    utility_floor_survives_all_tested_drops = {}
    only_baseline_configuration_preserves_all_current_floors = True

    for scenario_summary in scenario_erosion_sweeps:
        scenario = scenario_summary["scenario"]
        candidate_runs = scenario_summary["candidate_runs"]
        failing_candidates = [
            candidate
            for candidate in candidate_runs
            if candidate["seed_failure_count"] > 0
        ]
        if failing_candidates:
            first_failure = failing_candidates[0]
            smallest_policy_block_drop_triggering_any_failure[scenario] = first_failure[
                "policy_block_delta_from_baseline"
            ]
            first_drop_failure_metrics[scenario] = [
                metric
                for metric, count in first_failure["metric_failure_counts"].items()
                if count > 0
            ]
        else:
            smallest_policy_block_drop_triggering_any_failure[scenario] = 0.0
            first_drop_failure_metrics[scenario] = []
        utility_floor_survives_all_tested_drops[scenario] = all(
            candidate["metric_failure_counts"]["utility_with_policy_min"] == 0
            for candidate in candidate_runs
        )
        if any(
            candidate["seed_failure_count"] == 0 for candidate in candidate_runs[1:]
        ):
            only_baseline_configuration_preserves_all_current_floors = False

    return {
        "artifact": "obliteratus-erosion-note",
        "date": "2026-03-31",
        "paper": "Policy-Constrained Autonomous Agents for High-Risk Operations",
        "purpose": (
            "Quantify how quickly the current intervention-acceptance floors fail under bounded "
            "synthetic policy-block-rate erosion, so future refusal-direction runs can report whether "
            "they stay inside or break the present acceptance envelope."
        ),
        "supporting_artifacts": {
            "default_seed_sweep": "research/papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json",
            "stress_seed_sweep": "research/papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json",
            "obliteratus_intervention_note": "research/papers/agentic-security/sim/results/2026-03-30-obliteratus-intervention-note.json",
        },
        "evidence_boundary_note": (
            "This JSON reports synthetic counterfactual sensitivity sweeps over the existing policy-evaluation "
            "scaffold. It is not a live OBLITERATUS benchmark and should be interpreted only as an acceptance-envelope "
            "stress test for future intervention-backed runs."
        ),
        "sweep_method": {
            "varied_parameter": "policy_block_rate",
            "seed_schedule": scenario_payloads["default"]["seeds"],
            "erosion_schedule_by_scenario": EROSION_SCHEDULES,
        },
        "scenario_erosion_sweeps": scenario_erosion_sweeps,
        "cross_scenario_summary": {
            "only_baseline_configuration_preserves_all_current_floors": (
                only_baseline_configuration_preserves_all_current_floors
            ),
            "smallest_policy_block_drop_triggering_any_failure": (
                smallest_policy_block_drop_triggering_any_failure
            ),
            "first_drop_failure_metrics": first_drop_failure_metrics,
            "utility_floor_survives_all_tested_drops": (
                utility_floor_survives_all_tested_drops
            ),
        },
        "acceptance_note": (
            "Across both current scenarios, the present acceptance floors have effectively zero slack for reduced "
            "policy blocking: even the first tested five-point drop triggers at least one seed-level floor failure. "
            "Any future refusal-direction run that lowers policy blocking should therefore be reported as a bounded "
            "trade-off study, not as a drop-in preservation of the current safety envelope, unless it adds compensating "
            "controls that keep these floor checks green."
        ),
    }


def main() -> None:
    artifact = build_artifact()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
