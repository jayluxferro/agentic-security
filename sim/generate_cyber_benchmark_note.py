#!/usr/bin/env python3
from __future__ import annotations

import json
from pathlib import Path

SIM_ROOT = Path(__file__).resolve().parent
RESULTS_ROOT = SIM_ROOT / "results"
DEFAULT_SWEEP_PATH = RESULTS_ROOT / "2026-03-17-default-seed-sweep.json"
STRESS_SWEEP_PATH = RESULTS_ROOT / "2026-03-17-stress-seed-sweep.json"
CHALLENGE_REPLAY_PATH = RESULTS_ROOT / "2026-03-27-challenge-replay-note.json"
OUTPUT_PATH = RESULTS_ROOT / "2026-03-27-cyber-benchmark-note.json"


def _load_json(path: Path) -> dict:
    return json.loads(path.read_text(encoding="utf-8"))


def _scenario_mapping(label: str, payload: dict, relative_path: str) -> dict:
    config = payload["config"]
    summary = payload["summary"]
    return {
        "mapping_label": f"{label} scenario replay sweep",
        "artifact_path": relative_path,
        "scenario": payload["scenario"],
        "seeds": payload["seeds"],
        "task_count": config["n_tasks"],
        "baseline_violation_rate": config["base_violation_rate"],
        "policy_block_rate": config["policy_block_rate"],
        "utility_penalty": config["utility_penalty"],
        "mean_risk_reduction": round(summary["risk_reduction"]["mean"], 6),
        "mean_retained_utility": round(summary["utility_with_policy"]["mean"], 6),
        "evidence_boundary": (
            "Five-seed synthetic replay sweep; useful for bounded safety-versus-utility measurements but "
            "not a live benchmark run."
        ),
    }


def _challenge_case_mapping(case: dict) -> dict:
    provenance = case.get("provenance", {})
    return {
        "case_id": case["case_id"],
        "trace_origin": case["trace_origin"],
        "task_class": case["task_class"],
        "source_suite_family": case["source_suite_family"],
        "blocked_or_transformed_tactics": [
            step["tactic"]
            for step in case["steps"]
            if step["policy_decision"] in {"deny", "transform"}
        ],
        "unsafe_side_effect_prevented": case["outcome"]["unsafe_side_effect_prevented"],
        "utility_retained": case["outcome"]["utility_retained"],
        "source_url": provenance.get("source_url"),
        "solution_url": provenance.get("solution_url"),
        "solver_url": provenance.get("solver_url"),
        "evidence_boundary": case["outcome"]["residual_risk"],
    }


def build_artifact() -> dict:
    default_sweep = _load_json(DEFAULT_SWEEP_PATH)
    stress_sweep = _load_json(STRESS_SWEEP_PATH)
    challenge_replay = _load_json(CHALLENGE_REPLAY_PATH)
    challenge_cases = challenge_replay["cases"]
    challenge_summary = challenge_replay["summary"]

    cybereval_family_cases = [
        _challenge_case_mapping(case)
        for case in challenge_cases
        if case["source_suite_family"] == "CyberSecEval 2"
    ]
    cybench_family_cases = [
        _challenge_case_mapping(case)
        for case in challenge_cases
        if case["source_suite_family"] == "Cybench"
    ]
    nyu_family_cases = [
        _challenge_case_mapping(case)
        for case in challenge_cases
        if case["source_suite_family"] == "NYU CTF Bench"
    ]

    artifact = {
        "artifact": "cyber-benchmark-note",
        "date": "2026-03-27",
        "paper": "Policy-Constrained Autonomous Agents for High-Risk Operations",
        "purpose": (
            "Map cited cyber benchmark suites into concrete replay-note roles so the next "
            "external-evaluation pass is structured and reviewable before live benchmark runs."
        ),
        "supporting_artifacts": {
            "default_seed_sweep": "research/papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json",
            "stress_seed_sweep": "research/papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json",
            "challenge_replay_note": "research/papers/agentic-security/sim/results/2026-03-27-challenge-replay-note.json",
        },
        "coverage_snapshot": {
            "challenge_case_count": challenge_summary["case_count"],
            "benchmark_derived_case_count": challenge_summary[
                "benchmark_derived_case_count"
            ],
            "reconstructed_case_count": challenge_summary["reconstructed_case_count"],
            "total_replay_steps": challenge_summary["total_steps"],
            "denied_steps": challenge_summary["denied_steps"],
            "transformed_steps": challenge_summary["transformed_steps"],
            "allowed_steps": challenge_summary["allowed_steps"],
        },
        "suites": [
            {
                "name": "CyberSecEval 2",
                "citation_key": "bhatt2024cyberseceval2",
                "primary_signal_added": "broad cybersecurity evaluation coverage across realistic security tasks",
                "replay_note_role": "candidate source of prompt and tool-use task families for policy replay and refusal-intervention checks",
                "expected_evidence_type": "task-family replay note",
                "current_grounding": [
                    _scenario_mapping(
                        "Default",
                        default_sweep,
                        "research/papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json",
                    ),
                    _scenario_mapping(
                        "Stress",
                        stress_sweep,
                        "research/papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json",
                    ),
                    *cybereval_family_cases,
                ],
                "current_gap": (
                    "Replay-family grounding now exists through the default/stress seed sweeps and the "
                    "reconstructed secret-discovery/exfiltration proxy, but there is still no live CyberSecEval-style "
                    "run with tool logs, scored outcomes, or refusal-intervention checkpoints."
                ),
            },
            {
                "name": "Cybench",
                "citation_key": "zhang2024cybench",
                "primary_signal_added": "explicit capability-and-risk framing for cybersecurity evaluation",
                "replay_note_role": "category map for scoring capability gain against policy-constrained risk and residual unsafe actions",
                "expected_evidence_type": "capability-versus-risk benchmark note",
                "current_grounding": cybench_family_cases,
                "task_class_mapping": {
                    "capability_preserved": [
                        "read-only operational reconnaissance",
                        "operator-facing remediation reporting",
                    ],
                    "capability_denied": ["privilege escalation"],
                    "risk_accounting_artifacts": [
                        "research/papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json",
                        "research/papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json",
                    ],
                },
                "current_gap": (
                    "The task-class mapping gap is now closed for the current bounded Cybench proxy, but the repo still "
                    "lacks a broader category-level benchmark ingestion path with scored task outcomes and multiple challenge classes."
                ),
            },
            {
                "name": "NYU CTF Bench",
                "citation_key": "shao2024nyuctfbench",
                "primary_signal_added": "offensive-security challenge structure through open CTF-style tasks",
                "replay_note_role": "bounded source of multi-step attack-chain replay candidates and representative failure cases",
                "expected_evidence_type": "challenge-case replay note",
                "current_grounding": nyu_family_cases,
                "current_gap": (
                    "Now anchored by three benchmark-derived web traces in the dated challenge-replay note, but still lacks "
                    "a live benchmark run with full tool logs, scored outcomes, and adaptive retry behavior."
                ),
            },
        ],
        "acceptance_note": (
            "This is a benchmark-note artifact, not a claim of benchmark execution. Stronger empirical claims remain gated "
            "on live or replay-backed task runs with logged outcomes."
        ),
    }
    return artifact


def main() -> None:
    artifact = build_artifact()
    OUTPUT_PATH.parent.mkdir(parents=True, exist_ok=True)
    OUTPUT_PATH.write_text(json.dumps(artifact, indent=2) + "\n", encoding="utf-8")
    print(OUTPUT_PATH)


if __name__ == "__main__":
    main()
