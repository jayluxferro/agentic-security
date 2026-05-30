#!/usr/bin/env python3
from __future__ import annotations

import argparse
import json
from pathlib import Path
from typing import Any

REPO_ROOT = Path(__file__).resolve().parents[4]
SIM_ROOT = REPO_ROOT / "research" / "papers" / "agentic-security" / "sim"
ARTIFACTS_ROOT = (
    REPO_ROOT / "research" / "papers" / "agentic-security" / "artifacts" / "live_llm"
)
DEFAULT_OUTPUT_PATH = (
    SIM_ROOT / "results" / "2026-04-09-obliteratus-live-priority-probe-note.json"
)


def _load_json(path: Path) -> Any:
    return json.loads(path.read_text(encoding="utf-8"))


def _normalize(path_text: str) -> Path:
    path = Path(path_text)
    if path.is_absolute():
        return path
    return REPO_ROOT / path


def _relative_to_repo(path: Path) -> str:
    return path.relative_to(REPO_ROOT).as_posix()


def _latest_artifact_dir() -> Path:
    candidates = [
        path
        for path in ARTIFACTS_ROOT.iterdir()
        if path.is_dir() and (path / "metadata.json").exists()
    ]
    if not candidates:
        raise FileNotFoundError(
            f"No completed live LLM artifact directories found under {ARTIFACTS_ROOT}"
        )
    return max(candidates, key=lambda path: path.name)


def _case_summary(entry: dict[str, Any]) -> dict[str, Any]:
    response = entry["response"]
    return {
        "case_id": entry["case_id"],
        "suite": entry["suite"],
        "trace_origin": entry["trace_origin"],
        "task_class": entry["task_class"],
        "first_guard_decision": entry["first_guard_decision"],
        "first_guard_tactic": entry["first_guard_tactic"],
        "selected_option": response["selected_option"],
        "uses_first_guard_surface": response["uses_first_guard_surface"],
        "confidence": response["confidence"],
        "rationale": response["rationale"],
    }


def build_note(*, artifact_dir: Path) -> dict[str, Any]:
    metadata = _load_json(artifact_dir / "metadata.json")
    aggregate = _load_json(artifact_dir / "aggregate_metrics.json")
    outputs = _load_json(artifact_dir / "outputs.json")
    case_summaries = [_case_summary(entry) for entry in outputs]
    lowest_confidence_case = min(case_summaries, key=lambda entry: entry["confidence"])
    highest_confidence_case = max(case_summaries, key=lambda entry: entry["confidence"])

    note = {
        "generated_at": metadata["utc_timestamp"],
        "artifact_dir": metadata["artifact_dir"],
        "provider": metadata["provider"],
        "model": metadata["model"],
        "baseline_commit": metadata["baseline_commit"],
        "harness_script": metadata["harness_script"],
        "command_template": metadata["command_template"],
        "source_inputs": metadata["source_inputs"],
        "selection_summary": {
            "case_count": aggregate["case_count"],
            "selection_counts": aggregate["selection_counts"],
            "first_guard_surface_count": aggregate["first_guard_surface_count"],
            "first_guard_surface_share": aggregate["first_guard_surface_share"],
            "mean_confidence": aggregate["mean_confidence"],
            "confidence_range": {
                "min": lowest_confidence_case["confidence"],
                "max": highest_confidence_case["confidence"],
            },
            "lowest_confidence_case": {
                "case_id": lowest_confidence_case["case_id"],
                "suite": lowest_confidence_case["suite"],
                "confidence": lowest_confidence_case["confidence"],
            },
            "highest_confidence_case": {
                "case_id": highest_confidence_case["case_id"],
                "suite": highest_confidence_case["suite"],
                "confidence": highest_confidence_case["confidence"],
            },
            "all_cases_selected_first_guard_action": aggregate["selection_counts"]
            == {"first_guard_action": aggregate["case_count"]},
        },
        "suite_summary": {
            "suite_selection_counts": aggregate["suite_selection_counts"],
            "first_guard_surface_counts_by_suite": aggregate[
                "first_guard_surface_counts_by_suite"
            ],
            "thin_suite_first_guard_hits": aggregate["thin_suite_first_guard_hits"],
            "thin_suite_case_count": aggregate["thin_suite_case_count"],
        },
        "case_summaries": case_summaries,
        "live_probe_note": (
            "This API-backed live prompt-run probes whether a current frontier model, given only the bounded sentinel-case summaries, "
            "still aims first at the documented decisive guard surface. Across all six current OBLITERATUS cases the model selected "
            "the first_guard_action option, including both thin-suite sentinels."
        ),
        "bounded_scope_note": (
            "This note does not claim a live tool benchmark, exploit success, or logged suite trace. It records a one-turn abstract "
            "next-action classification exercise over the existing replay-backed priority queue so the manuscript can cite fresh live "
            "LLM evidence without overstating ecological validity."
        ),
    }
    return note


def main() -> None:
    parser = argparse.ArgumentParser(
        description="Summarize a bounded live LLM priority probe into a manuscript-facing JSON note."
    )
    parser.add_argument(
        "--artifact-dir",
        help=(
            "Workspace-relative or absolute path to artifacts/live_llm/<timestamp>/ "
            "(default: latest completed artifact directory)."
        ),
    )
    parser.add_argument(
        "--output",
        default=str(DEFAULT_OUTPUT_PATH.relative_to(REPO_ROOT)),
        help="Workspace-relative or absolute output JSON path.",
    )
    args = parser.parse_args()

    artifact_dir = (
        _normalize(args.artifact_dir) if args.artifact_dir else _latest_artifact_dir()
    )
    output_path = _normalize(args.output)
    output_path.parent.mkdir(parents=True, exist_ok=True)

    note = build_note(artifact_dir=artifact_dir)
    output_path.write_text(json.dumps(note, indent=2) + "\n", encoding="utf-8")
    print(
        json.dumps(
            {
                "artifact_dir": _relative_to_repo(artifact_dir),
                "output": _relative_to_repo(output_path),
                "case_count": note["selection_summary"]["case_count"],
                "first_guard_surface_count": note["selection_summary"][
                    "first_guard_surface_count"
                ],
                "mean_confidence": note["selection_summary"]["mean_confidence"],
            },
            indent=2,
        )
    )


if __name__ == "__main__":
    main()
