#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
import math
import random
import statistics
from dataclasses import asdict, dataclass
from pathlib import Path


@dataclass
class EvalConfig:
    seed: int = 42
    n_tasks: int = 200
    base_violation_rate: float = 0.18
    policy_block_rate: float = 0.72
    utility_penalty: float = 0.08


def run(cfg: EvalConfig, scenario: str | None = None) -> dict:
    violations_without = int(cfg.n_tasks * cfg.base_violation_rate)
    blocked = int(violations_without * cfg.policy_block_rate)
    violations_with = max(0, violations_without - blocked)

    utility_without = 1.0
    utility_with = max(0.0, utility_without - cfg.utility_penalty)

    reduction = 0.0
    residual_share = 0.0
    if violations_without > 0:
        reduction = (violations_without - violations_with) / violations_without
        residual_share = violations_with / violations_without

    payload = {
        "config": asdict(cfg),
        "metrics": {
            "violations_without_policy": violations_without,
            "blocked_by_policy": blocked,
            "violations_with_policy": violations_with,
            "risk_reduction": round(reduction, 6),
            "residual_share_of_baseline": round(residual_share, 6),
            "utility_without_policy": utility_without,
            "utility_with_policy": utility_with,
        },
    }
    if scenario:
        payload["scenario"] = scenario
    return payload


def simulate(cfg: EvalConfig, *, seed: int, scenario: str | None = None) -> dict:
    rng = random.Random(seed)
    violations_without = 0
    blocked = 0
    utility_successes = 0

    for _ in range(cfg.n_tasks):
        if rng.random() < cfg.base_violation_rate:
            violations_without += 1
            if rng.random() < cfg.policy_block_rate:
                blocked += 1
        if rng.random() >= cfg.utility_penalty:
            utility_successes += 1

    violations_with = max(0, violations_without - blocked)
    utility_without = 1.0
    utility_with = utility_successes / cfg.n_tasks if cfg.n_tasks else 0.0

    reduction = 0.0
    residual_share = 0.0
    if violations_without > 0:
        reduction = (violations_without - violations_with) / violations_without
        residual_share = violations_with / violations_without

    payload = {
        "config": {**asdict(cfg), "seed": seed},
        "metrics": {
            "violations_without_policy": violations_without,
            "blocked_by_policy": blocked,
            "violations_with_policy": violations_with,
            "risk_reduction": round(reduction, 6),
            "residual_share_of_baseline": round(residual_share, 6),
            "utility_without_policy": utility_without,
            "utility_with_policy": round(utility_with, 6),
        },
    }
    if scenario:
        payload["scenario"] = scenario
    return payload


def _summary_stats(values: list[float]) -> dict[str, float]:
    mean = statistics.fmean(values)
    std = statistics.stdev(values) if len(values) > 1 else 0.0
    ci95 = 1.96 * std / math.sqrt(len(values)) if len(values) > 1 else 0.0
    return {
        "mean": round(mean, 6),
        "std": round(std, 6),
        "min": round(min(values), 6),
        "max": round(max(values), 6),
        "ci95": round(ci95, 6),
    }


def run_seed_sweep(
    cfg: EvalConfig, *, seeds: list[int], scenario: str | None = None
) -> dict:
    seed_runs = [simulate(cfg, seed=seed, scenario=scenario) for seed in seeds]
    metric_names = (
        "violations_without_policy",
        "blocked_by_policy",
        "violations_with_policy",
        "risk_reduction",
        "residual_share_of_baseline",
        "utility_with_policy",
    )
    summary = {
        metric_name: _summary_stats(
            [float(run["metrics"][metric_name]) for run in seed_runs]
        )
        for metric_name in metric_names
    }
    payload = {
        "config": asdict(cfg),
        "seeds": seeds,
        "seed_runs": seed_runs,
        "summary": summary,
    }
    if scenario:
        payload["scenario"] = scenario
    return payload


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Run the lightweight agentic policy-evaluation scaffold and optionally write JSON output."
    )
    parser.add_argument("--seed", type=int, default=42)
    parser.add_argument("--n-tasks", type=int, default=200)
    parser.add_argument("--base-violation-rate", type=float, default=0.18)
    parser.add_argument("--policy-block-rate", type=float, default=0.72)
    parser.add_argument("--utility-penalty", type=float, default=0.08)
    parser.add_argument(
        "--scenario", help="Optional scenario label to embed in the JSON output."
    )
    parser.add_argument(
        "--simulate",
        action="store_true",
        help="Use stochastic per-task sampling for a single-seed run.",
    )
    parser.add_argument(
        "--seed-sweep",
        nargs="+",
        type=int,
        help="Optional list of seeds for a bounded multi-seed sweep with summary statistics.",
    )
    parser.add_argument("--output", help="Optional path to write the JSON payload.")
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    cfg = EvalConfig(
        seed=args.seed,
        n_tasks=args.n_tasks,
        base_violation_rate=args.base_violation_rate,
        policy_block_rate=args.policy_block_rate,
        utility_penalty=args.utility_penalty,
    )
    if args.seed_sweep:
        payload = run_seed_sweep(cfg, seeds=args.seed_sweep, scenario=args.scenario)
    elif args.simulate:
        payload = simulate(cfg, seed=args.seed, scenario=args.scenario)
    else:
        payload = run(cfg, scenario=args.scenario)
    rendered = json.dumps(payload, indent=2)
    if args.output:
        out_path = Path(args.output)
        out_path.parent.mkdir(parents=True, exist_ok=True)
        out_path.write_text(rendered + "\n", encoding="utf-8")
    print(rendered)


if __name__ == "__main__":
    main()
