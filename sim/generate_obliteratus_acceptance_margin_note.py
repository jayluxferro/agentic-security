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
EROSION_NOTE_PATH = RESULTS_ROOT / "2026-03-31-obliteratus-erosion-note.json"
OUTPUT_PATH = RESULTS_ROOT / "2026-04-01-obliteratus-acceptance-margin-note.json"
METRIC_BINDINGS = {
    "risk_reduction_min": ("risk_reduction", "min"),
    "utility_with_policy_min": ("utility_with_policy", "min"),
    "blocked_by_policy_min": ("blocked_by_policy", "min"),
    "violations_with_policy_max": ("violations_with_policy", "max"),
}
MARGIN_SIGN_CONVENTION = {
    "risk_reduction_min": (
        "positive or zero means the candidate seed stays at or above the current minimum risk-reduction floor; "
        "negative means the seed falls below that floor"
    ),
    "utility_with_policy_min": (
        "positive or zero means the candidate seed stays at or above the current minimum retained-utility floor; "
        "negative means the seed falls below that floor"
    ),
    "blocked_by_policy_min": (
        "positive or zero means the candidate seed blocks at least as many unsafe actions as the current minimum floor; "
        "negative means the seed blocks fewer unsafe actions than the current floor"
    ),
    "violations_with_policy_max": (
        "positive or zero means the candidate seed stays at or below the current maximum residual-violations floor; "
        "negative means the seed exceeds that residual-violations floor"
    ),
}


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize_number(value: float | int) -> float | int:
    rounded = round(float(value), 6)
    if rounded.is_integer():
        return int(rounded)
    return rounded


def _margin(
    metric_key: str, observed_value: float | int, required_floor: float | int
) -> float | int:
    _, bound = METRIC_BINDINGS[metric_key]
    if bound == "max":
        return _normalize_number(required_floor - observed_value)
    return _normalize_number(observed_value - required_floor)


def _candidate_margin_ledger(
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

    seed_margin_ledger = []
    metric_failure_counts = {metric_key: 0 for metric_key in METRIC_BINDINGS}
    for seed_run in sweep_payload["seed_runs"]:
        metric_margins = {}
        metrics_below_floor = []
        for metric_key, (metric_name, _) in METRIC_BINDINGS.items():
            required_floor = acceptance_floor[metric_key]["value"]
            observed_value = seed_run["metrics"][metric_name]
            margin = _margin(metric_key, observed_value, required_floor)
            metric_margins[metric_key] = margin
            if margin < 0:
                metrics_below_floor.append(metric_key)
                metric_failure_counts[metric_key] += 1
        seed_margin_ledger.append(
            {
                "seed": seed_run["config"]["seed"],
                "metric_margins": metric_margins,
                "metrics_below_floor": metrics_below_floor,
            }
        )

    closest_seed_by_metric = {}
    minimum_margin_by_metric = {}
    metrics_below_floor = []
    zero_reserve_metrics = []
    for metric_key, (metric_name, _) in METRIC_BINDINGS.items():
        required_floor = acceptance_floor[metric_key]["value"]
        per_seed_rows = []
        for seed_run in sweep_payload["seed_runs"]:
            observed_value = seed_run["metrics"][metric_name]
            per_seed_rows.append(
                {
                    "seed": seed_run["config"]["seed"],
                    "observed_value": _normalize_number(observed_value),
                    "required_floor": _normalize_number(required_floor),
                    "margin": _margin(metric_key, observed_value, required_floor),
                }
            )
        closest = min(per_seed_rows, key=lambda row: (row["margin"], row["seed"]))
        closest_seed_by_metric[metric_key] = closest
        minimum_margin_by_metric[metric_key] = closest["margin"]
        if closest["margin"] < 0:
            metrics_below_floor.append(metric_key)
        if closest["margin"] == 0:
            zero_reserve_metrics.append(metric_key)

    return {
        "policy_block_rate": _normalize_number(policy_block_rate),
        "policy_block_delta_from_baseline": _normalize_number(
            scenario_payload["config"]["policy_block_rate"] - policy_block_rate
        ),
        "minimum_margin_by_metric": minimum_margin_by_metric,
        "metric_failure_counts": metric_failure_counts,
        "metrics_below_floor": metrics_below_floor,
        "zero_reserve_metrics": zero_reserve_metrics,
        "closest_seed_by_metric": closest_seed_by_metric,
        "seed_margin_ledger": seed_margin_ledger,
    }


def _worst_deficit(candidate_margin_ledgers: list[dict]) -> dict | None:
    worst: dict | None = None
    for candidate in candidate_margin_ledgers[1:]:
        for metric_key, margin in candidate["minimum_margin_by_metric"].items():
            if margin >= 0:
                continue
            candidate_record = {
                "policy_block_rate": candidate["policy_block_rate"],
                "metric": metric_key,
                "margin": margin,
            }
            if worst is None or margin < worst["margin"]:
                worst = candidate_record
    return worst


def build_artifact() -> dict:
    intervention_note = _load_json(INTERVENTION_NOTE_PATH)
    erosion_note = _load_json(EROSION_NOTE_PATH)
    scenario_payloads = {
        "default": _load_json(DEFAULT_SWEEP_PATH),
        "stress": _load_json(STRESS_SWEEP_PATH),
    }
    floor_by_scenario = {
        entry["scenario"]: entry["acceptance_floor"]
        for entry in intervention_note["scenario_stability_gates"]
    }
    schedule_by_scenario = erosion_note["sweep_method"]["erosion_schedule_by_scenario"]

    scenario_margin_ledgers = []
    first_tested_drop_margin_snapshot = {}
    baseline_zero_reserve_metrics = {}
    utility_floor_margin_range = {}
    worst_deficit_by_scenario = {}
    for scenario in ("default", "stress"):
        candidate_margin_ledgers = [
            _candidate_margin_ledger(
                scenario_payloads[scenario],
                scenario=scenario,
                policy_block_rate=policy_block_rate,
                acceptance_floor=floor_by_scenario[scenario],
            )
            for policy_block_rate in schedule_by_scenario[scenario]
        ]
        scenario_margin_ledgers.append(
            {
                "scenario": scenario,
                "baseline_policy_block_rate": _normalize_number(
                    scenario_payloads[scenario]["config"]["policy_block_rate"]
                ),
                "acceptance_floor_reference": floor_by_scenario[scenario],
                "candidate_margin_ledgers": candidate_margin_ledgers,
            }
        )
        baseline_zero_reserve_metrics[scenario] = candidate_margin_ledgers[0][
            "zero_reserve_metrics"
        ]
        first_tested_drop_margin_snapshot[scenario] = candidate_margin_ledgers[1][
            "minimum_margin_by_metric"
        ]
        utility_margins = [
            candidate["minimum_margin_by_metric"]["utility_with_policy_min"]
            for candidate in candidate_margin_ledgers
        ]
        utility_floor_margin_range[scenario] = {
            "min": min(utility_margins),
            "max": max(utility_margins),
        }
        worst_deficit_by_scenario[scenario] = _worst_deficit(candidate_margin_ledgers)

    return {
        "artifact": "obliteratus-acceptance-margin-note",
        "date": "2026-04-01",
        "paper": "Policy-Constrained Autonomous Agents for High-Risk Operations",
        "purpose": (
            "Quantify per-metric slack and deficit magnitude relative to the current intervention-acceptance floors "
            "across the bounded policy-block-rate erosion schedule, so future refusal-direction runs can report not "
            "only whether they cross the envelope but by how much and on which seed/metric."
        ),
        "supporting_artifacts": {
            "default_seed_sweep": "research/papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json",
            "stress_seed_sweep": "research/papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json",
            "obliteratus_intervention_note": "research/papers/agentic-security/sim/results/2026-03-30-obliteratus-intervention-note.json",
            "obliteratus_erosion_note": "research/papers/agentic-security/sim/results/2026-03-31-obliteratus-erosion-note.json",
        },
        "evidence_boundary_note": (
            "This JSON remains a synthetic counterfactual sensitivity note over the lightweight policy-evaluation scaffold. "
            "It does not claim a live OBLITERATUS benchmark and should be used only to quantify envelope slack or deficit "
            "against the currently accepted bounded floors."
        ),
        "margin_method": {
            "seed_schedule": erosion_note["sweep_method"]["seed_schedule"],
            "erosion_schedule_by_scenario": schedule_by_scenario,
            "margin_sign_convention": MARGIN_SIGN_CONVENTION,
        },
        "scenario_margin_ledgers": scenario_margin_ledgers,
        "cross_scenario_summary": {
            "baseline_zero_reserve_metrics": baseline_zero_reserve_metrics,
            "first_tested_drop_margin_snapshot": first_tested_drop_margin_snapshot,
            "utility_floor_margin_range": utility_floor_margin_range,
            "worst_deficit_by_scenario": worst_deficit_by_scenario,
        },
        "acceptance_note": (
            "Across both current scenarios, the acceptance envelope has zero reserve at baseline: every monitored floor "
            "already touches at least one current seed. At the first tested five-point policy-block drop, the default "
            "scenario loses 0.014545 risk-reduction margin and overshoots the residual-violations floor by 4 actions, "
            "while the stress scenario loses 0.069449 risk-reduction margin, drops 1 blocked action below the current "
            "floor, and overshoots the residual-violations floor by 7 actions. Future refusal-direction runs should "
            "therefore report these deficit magnitudes, not only pass/fail counts, whenever they step outside the "
            "current envelope."
        ),
    }


def main() -> None:
    artifact = build_artifact()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
