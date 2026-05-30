#!/usr/bin/env python3
from __future__ import annotations

import argparse
import hashlib
import json
import subprocess
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


REPO_ROOT = Path(__file__).resolve().parents[4]
RESEARCH_ROOT = Path("research")
PAPER_ROOT = RESEARCH_ROOT / "papers" / "agentic-security"
SIM_ROOT = PAPER_ROOT / "sim"
PAPER_TITLE = "Policy-Constrained Autonomous Agents for High-Risk Operations"
MANUSCRIPT_PATH = PAPER_ROOT / "main.tex"
CITATION_NOTE_PATH = PAPER_ROOT / "citation-verification.md"
MANUSCRIPT_AUDIT_JSON_PATH = Path("state/agentic-security-manuscript-audit.json")
MANUSCRIPT_AUDIT_MD_PATH = Path("state/agentic-security-manuscript-audit.md")
DEFAULT_OUTPUT_PATH = (
    SIM_ROOT / "results" / "2026-03-27-publication-artifact-manifest.json"
)
MANIFEST_SCRIPT = SIM_ROOT / "generate_publication_artifact_manifest.py"


@dataclass(frozen=True)
class ArtifactSpec:
    artifact_key: str
    role: str
    relative_path: str
    source_script: str | None = None
    generator_command: str | None = None
    input_artifact_keys: tuple[str, ...] = ()
    allow_missing: bool = False


@dataclass(frozen=True)
class MirrorSpec:
    mirror_key: str
    role: str
    relative_path: str
    matches_artifact_key: str
    source_script: str | None = None
    generator_command: str | None = None


def _manuscript_audit_command() -> str:
    return (
        f"PYTHONPATH={_research_workdir_relative_path(Path('tools') / 'evidence-assembler')} "
        f"{_research_workdir_relative_path(RESEARCH_ROOT / '.venv' / 'bin' / 'python')} "
        "-m assembler.manuscript_audit "
        f"{_research_workdir_relative_path(MANUSCRIPT_PATH)} "
        f"--citation-note {_research_workdir_relative_path(CITATION_NOTE_PATH)} "
        f"--workspace-root {_research_workdir_relative_path(REPO_ROOT)} "
        f"--json-output {_research_workdir_relative_path(MANUSCRIPT_AUDIT_JSON_PATH)} "
        f"--markdown-output {_research_workdir_relative_path(MANUSCRIPT_AUDIT_MD_PATH)}"
    )


def _workspace_path_text(path: Path) -> str:
    return path.as_posix()


def _workspace_relative_path_text(path: Path) -> str:
    if path.is_absolute():
        return path.relative_to(REPO_ROOT).as_posix()
    return path.as_posix()


def _normalize_output_path(path: Path) -> Path:
    if path.is_absolute():
        return path
    if path.parts[:1] == RESEARCH_ROOT.parts:
        return path
    return RESEARCH_ROOT / path


def _research_command_path(path: Path) -> str:
    return path.relative_to(RESEARCH_ROOT).as_posix()


def _research_workdir_relative_path(path: Path) -> str:
    if path.is_absolute():
        path = path.relative_to(REPO_ROOT)
    if path.parts[:1] == RESEARCH_ROOT.parts:
        return path.relative_to(RESEARCH_ROOT).as_posix()
    return (Path("..") / path).as_posix()


def _uv_run_python_command(script_path: Path) -> str:
    return f"uv run python {_research_command_path(script_path)}"


def _manifest_generator_command(output_path_text: str) -> str:
    normalized_output_path = _normalize_output_path(Path(output_path_text))
    return (
        f"{_uv_run_python_command(MANIFEST_SCRIPT)} "
        f"--output {_research_command_path(normalized_output_path)}"
    )


def _pytest_command(test_path: str) -> str:
    return (
        f"uv run python -m pytest {_research_workdir_relative_path(Path(test_path))} -q"
    )


ARTIFACT_SPECS = [
    ArtifactSpec(
        artifact_key="manuscript_source_tex",
        role="LaTeX manuscript source bound to the compiled LNCS PDF snapshot.",
        relative_path="research/papers/agentic-security/main.tex",
    ),
    ArtifactSpec(
        artifact_key="shared_bibliography_bib",
        role="Shared bibliography file consumed by BibTeX when rebuilding the compiled LNCS manuscript snapshot.",
        relative_path="research/common/refs.bib",
    ),
    ArtifactSpec(
        artifact_key="local_llncs_cls",
        role="Local LNCS document class consumed by pdflatex when rebuilding the compiled manuscript PDF snapshot.",
        relative_path="research/papers/agentic-security/llncs.cls",
    ),
    ArtifactSpec(
        artifact_key="local_splncs04_bst",
        role="Local LNCS BibTeX style file consumed by BibTeX when rebuilding the compiled manuscript PDF snapshot.",
        relative_path="research/papers/agentic-security/splncs04.bst",
    ),
    ArtifactSpec(
        artifact_key="citation_verification_note",
        role="Verified citation provenance note for every citekey used in the manuscript revision.",
        relative_path=CITATION_NOTE_PATH.as_posix(),
    ),
    ArtifactSpec(
        artifact_key="manuscript_audit_json",
        role="Machine-readable structural manuscript audit confirming citation-note coverage and local-path resolution for this revision.",
        relative_path=MANUSCRIPT_AUDIT_JSON_PATH.as_posix(),
        generator_command=_manuscript_audit_command(),
        input_artifact_keys=("manuscript_source_tex", "citation_verification_note"),
    ),
    ArtifactSpec(
        artifact_key="manuscript_audit_md",
        role="Human-readable structural manuscript audit confirming citation-note coverage and local-path resolution for this revision.",
        relative_path=MANUSCRIPT_AUDIT_MD_PATH.as_posix(),
        generator_command=_manuscript_audit_command(),
        input_artifact_keys=("manuscript_source_tex", "citation_verification_note"),
    ),
    ArtifactSpec(
        artifact_key="scenario_replay_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the quoted scenario-replay numbers "
            "against the dated default and stress seed-sweep JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_manuscript_consistency.py",
    ),
    ArtifactSpec(
        artifact_key="challenge_replay_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the manuscript's challenge-replay origin mix, "
            "action counts, tactic table, and benchmark-derived case wording against the dated replay "
            "and benchmark-note JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_challenge_replay_consistency.py",
    ),
    ArtifactSpec(
        artifact_key="cyber_benchmark_note_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the cyber benchmark-note coverage snapshot, "
            "suite-to-artifact mappings, and current-gap wording against the dated replay and scenario JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_cyber_benchmark_note.py",
    ),
    ArtifactSpec(
        artifact_key="obliteratus_replay_note_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the OBLITERATUS replay-readiness note against the dated challenge-replay "
            "and cyber benchmark-note JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_obliteratus_replay_note.py",
    ),
    ArtifactSpec(
        artifact_key="obliteratus_intervention_note_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the OBLITERATUS intervention-acceptance note against the dated "
            "seed-sweep, challenge-replay, and OBLITERATUS replay-note JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_obliteratus_intervention_note.py",
    ),
    ArtifactSpec(
        artifact_key="obliteratus_erosion_note_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the OBLITERATUS policy-erosion note against the dated "
            "seed-sweep and intervention-acceptance JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_obliteratus_erosion_note.py",
    ),
    ArtifactSpec(
        artifact_key="obliteratus_acceptance_margin_note_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the OBLITERATUS acceptance-margin note against the dated "
            "seed-sweep, intervention-acceptance, and erosion JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_obliteratus_acceptance_margin_note.py",
    ),
    ArtifactSpec(
        artifact_key="obliteratus_watchlist_note_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the OBLITERATUS monitoring watchlist note against the "
            "dated replay-readiness and acceptance-margin JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_obliteratus_watchlist_note.py",
    ),
    ArtifactSpec(
        artifact_key="obliteratus_followup_priority_note_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the OBLITERATUS follow-up priority note against the "
            "dated replay-readiness and watchlist JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_obliteratus_followup_priority_note.py",
    ),
    ArtifactSpec(
        artifact_key="obliteratus_review_packet_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the OBLITERATUS review packet against the dated replay, "
            "intervention, erosion, acceptance-margin, watchlist, and follow-up JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_obliteratus_review_packet.py",
    ),
    ArtifactSpec(
        artifact_key="obliteratus_failure_ladder_note_consistency_test",
        role=(
            "Publication-facing pytest guard that checks the OBLITERATUS failure-ladder note against the dated "
            "acceptance-margin and watchlist JSON artifacts."
        ),
        relative_path="research/tests/test_agentic_security_obliteratus_failure_ladder_note.py",
    ),
    ArtifactSpec(
        artifact_key="default_scaffold_json",
        role="Frozen default-scenario scaffold summary backing the deterministic scaffold tables and violation funnel.",
        relative_path="research/papers/agentic-security/sim/results/2026-03-14-default.json",
        source_script="research/papers/agentic-security/sim/run_policy_eval.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/run_policy_eval.py "
            "--scenario default "
            "--output papers/agentic-security/sim/results/2026-03-14-default.json"
        ),
    ),
    ArtifactSpec(
        artifact_key="default_seed_sweep_json",
        role="Five-seed default-scenario replay summary backing the scenario replay table and policy-scenario replay figure.",
        relative_path="research/papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json",
        source_script="research/papers/agentic-security/sim/run_policy_eval.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/run_policy_eval.py "
            "--scenario default --seed-sweep 40 41 42 43 44 "
            "--output papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json"
        ),
    ),
    ArtifactSpec(
        artifact_key="stress_seed_sweep_json",
        role="Five-seed stress-scenario replay summary backing the scenario replay table and policy-scenario replay figure.",
        relative_path="research/papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json",
        source_script="research/papers/agentic-security/sim/run_policy_eval.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/run_policy_eval.py "
            "--scenario stress --n-tasks 300 --base-violation-rate 0.22 "
            "--policy-block-rate 0.65 --utility-penalty 0.10 --seed-sweep 40 41 42 43 44 "
            "--output papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json"
        ),
    ),
    ArtifactSpec(
        artifact_key="cyber_benchmark_note_json",
        role="Structured benchmark-role note backing the cyber benchmark mapping table.",
        relative_path="research/papers/agentic-security/sim/results/2026-03-27-cyber-benchmark-note.json",
        source_script="research/papers/agentic-security/sim/generate_cyber_benchmark_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_cyber_benchmark_note.py"
        ),
    ),
    ArtifactSpec(
        artifact_key="obliteratus_replay_note_json",
        role="Task-level OBLITERATUS replay-readiness note binding the current guarded cyber traces to future refusal-direction regression checks.",
        relative_path="research/papers/agentic-security/sim/results/2026-03-30-obliteratus-replay-note.json",
        source_script="research/papers/agentic-security/sim/generate_obliteratus_replay_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_obliteratus_replay_note.py"
        ),
        input_artifact_keys=(
            "cyber_benchmark_note_json",
            "dated_challenge_replay_note_json",
        ),
    ),
    ArtifactSpec(
        artifact_key="obliteratus_intervention_note_json",
        role="Intervention-acceptance note that combines seed-sweep stability floors with replay-backed first-guard probes for future refusal-direction runs.",
        relative_path="research/papers/agentic-security/sim/results/2026-03-30-obliteratus-intervention-note.json",
        source_script="research/papers/agentic-security/sim/generate_obliteratus_intervention_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_obliteratus_intervention_note.py"
        ),
        input_artifact_keys=(
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "dated_challenge_replay_note_json",
            "obliteratus_replay_note_json",
        ),
    ),
    ArtifactSpec(
        artifact_key="obliteratus_erosion_note_json",
        role="Policy-erosion sensitivity note that stress-tests the current intervention acceptance floors under bounded synthetic policy-block-rate relaxation.",
        relative_path="research/papers/agentic-security/sim/results/2026-03-31-obliteratus-erosion-note.json",
        source_script="research/papers/agentic-security/sim/generate_obliteratus_erosion_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_obliteratus_erosion_note.py"
        ),
        input_artifact_keys=(
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "obliteratus_intervention_note_json",
        ),
    ),
    ArtifactSpec(
        artifact_key="obliteratus_acceptance_margin_note_json",
        role="Acceptance-margin note that quantifies per-metric slack and deficit size across the bounded policy-erosion schedule for future refusal-direction reviews.",
        relative_path="research/papers/agentic-security/sim/results/2026-04-01-obliteratus-acceptance-margin-note.json",
        source_script="research/papers/agentic-security/sim/generate_obliteratus_acceptance_margin_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_obliteratus_acceptance_margin_note.py"
        ),
        input_artifact_keys=(
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "obliteratus_intervention_note_json",
            "obliteratus_erosion_note_json",
        ),
    ),
    ArtifactSpec(
        artifact_key="obliteratus_watchlist_note_json",
        role="Monitoring watchlist note that combines the acceptance-envelope metric pressure with replay-backed first-guard cases for future OBLITERATUS reviews.",
        relative_path="research/papers/agentic-security/sim/results/2026-04-01-obliteratus-watchlist-note.json",
        source_script="research/papers/agentic-security/sim/generate_obliteratus_watchlist_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_obliteratus_watchlist_note.py"
        ),
        input_artifact_keys=(
            "obliteratus_replay_note_json",
            "obliteratus_acceptance_margin_note_json",
        ),
    ),
    ArtifactSpec(
        artifact_key="obliteratus_followup_priority_note_json",
        role="Follow-up priority note that turns the current replay and watchlist bundle into an explicit next-run suite and case ledger for OBLITERATUS reviews.",
        relative_path="research/papers/agentic-security/sim/results/2026-04-01-obliteratus-followup-priority-note.json",
        source_script="research/papers/agentic-security/sim/generate_obliteratus_followup_priority_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_obliteratus_followup_priority_note.py"
        ),
        input_artifact_keys=(
            "obliteratus_replay_note_json",
            "obliteratus_watchlist_note_json",
        ),
    ),
    ArtifactSpec(
        artifact_key="obliteratus_live_priority_probe_note_json",
        role="Bounded API-backed live LLM probe summary that records whether a current frontier model still selects the documented first decisive guard surface across the current OBLITERATUS sentinel queue.",
        relative_path="research/papers/agentic-security/sim/results/2026-04-09-obliteratus-live-priority-probe-note.json",
        source_script="research/papers/agentic-security/sim/generate_obliteratus_live_priority_probe_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_obliteratus_live_priority_probe_note.py "
            "--artifact-dir papers/agentic-security/artifacts/live_llm/20260409T220346Z "
            "--output papers/agentic-security/sim/results/2026-04-09-obliteratus-live-priority-probe-note.json"
        ),
    ),
    ArtifactSpec(
        artifact_key="obliteratus_review_packet_json",
        role="Review packet that collapses the current OBLITERATUS replay, intervention, erosion, acceptance-margin, watchlist, and follow-up notes into one next-run contract.",
        relative_path="research/papers/agentic-security/sim/results/2026-04-01-obliteratus-review-packet.json",
        source_script="research/papers/agentic-security/sim/generate_obliteratus_review_packet.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_obliteratus_review_packet.py"
        ),
        input_artifact_keys=(
            "obliteratus_replay_note_json",
            "obliteratus_intervention_note_json",
            "obliteratus_erosion_note_json",
            "obliteratus_acceptance_margin_note_json",
            "obliteratus_watchlist_note_json",
            "obliteratus_followup_priority_note_json",
        ),
    ),
    ArtifactSpec(
        artifact_key="obliteratus_failure_ladder_note_json",
        role="Failure-ladder note that condenses the current OBLITERATUS acceptance-margin and watchlist bundle into a per-scenario policy-block-rate break schedule.",
        relative_path="research/papers/agentic-security/sim/results/2026-04-01-obliteratus-failure-ladder-note.json",
        source_script="research/papers/agentic-security/sim/generate_obliteratus_failure_ladder_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_obliteratus_failure_ladder_note.py"
        ),
        input_artifact_keys=(
            "obliteratus_acceptance_margin_note_json",
            "obliteratus_watchlist_note_json",
        ),
    ),
    ArtifactSpec(
        artifact_key="dated_challenge_replay_note_json",
        role=(
            "Publication-facing dated challenge replay note backing the challenge replay table, "
            "challenge replay matrix figure, tactic breakdown table, and tactic breakdown figure."
        ),
        relative_path="research/papers/agentic-security/sim/results/2026-03-27-challenge-replay-note.json",
        source_script="research/papers/agentic-security/sim/generate_challenge_replay_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_challenge_replay_note.py"
        ),
    ),
    ArtifactSpec(
        artifact_key="policy_scenario_replay_pdf",
        role="Rendered policy-scenario replay figure included in the manuscript.",
        relative_path="research/papers/agentic-security/figures/policy-scenario-replay.pdf",
        source_script="research/papers/agentic-security/sim/plot_policy_scenarios.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/plot_policy_scenarios.py "
            "papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json "
            "papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json "
            "--output papers/agentic-security/figures/policy-scenario-replay.pdf"
        ),
        input_artifact_keys=("default_seed_sweep_json", "stress_seed_sweep_json"),
    ),
    ArtifactSpec(
        artifact_key="challenge_replay_matrix_pdf",
        role="Rendered per-case challenge replay decision matrix figure included in the manuscript.",
        relative_path="research/papers/agentic-security/figures/challenge-replay-matrix.pdf",
        source_script="research/papers/agentic-security/sim/plot_challenge_replay_matrix.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/plot_challenge_replay_matrix.py "
            "papers/agentic-security/sim/results/2026-03-27-challenge-replay-note.json "
            "--output papers/agentic-security/figures/challenge-replay-matrix.pdf"
        ),
        input_artifact_keys=("dated_challenge_replay_note_json",),
    ),
    ArtifactSpec(
        artifact_key="tactic_breakdown_pdf",
        role="Rendered tactic-stratified guard-decision figure included in the manuscript.",
        relative_path="research/papers/agentic-security/figures/tactic-breakdown.pdf",
        source_script="research/papers/agentic-security/sim/plot_tactic_breakdown.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/plot_tactic_breakdown.py "
            "papers/agentic-security/sim/results/2026-03-27-challenge-replay-note.json "
            "--output papers/agentic-security/figures/tactic-breakdown.pdf"
        ),
        input_artifact_keys=("dated_challenge_replay_note_json",),
    ),
    ArtifactSpec(
        artifact_key="compiled_manuscript_pdf",
        role="Local compiled LNCS PDF snapshot present at manifest time for this manuscript revision.",
        relative_path="research/papers/agentic-security/main.pdf",
        allow_missing=True,
    ),
]


PUBLICATION_PDF_SNAPSHOT = {
    "artifact_key": "compiled_manuscript_pdf",
    "role": "Local compiled LNCS PDF snapshot present at manifest time for this manuscript revision.",
    "working_directory": "research/papers/agentic-security",
    "rebuild_commands": [
        "pdflatex -interaction=nonstopmode -halt-on-error main.tex",
        "bibtex main",
        "pdflatex -interaction=nonstopmode -halt-on-error main.tex",
        "pdflatex -interaction=nonstopmode -halt-on-error main.tex",
    ],
    "supporting_artifact_keys": [
        "manuscript_source_tex",
        "shared_bibliography_bib",
        "local_llncs_cls",
        "local_splncs04_bst",
        "policy_scenario_replay_pdf",
        "challenge_replay_matrix_pdf",
        "tactic_breakdown_pdf",
    ],
}


MIRROR_SPECS = [
    MirrorSpec(
        mirror_key="latest_challenge_replay_note_json",
        role="Rolling convenience mirror written alongside the dated replay note for local reference; the dated 2026-03-27 JSON remains the publication citation and regeneration target.",
        relative_path="research/papers/agentic-security/sim/results/latest-challenge-replay-note.json",
        matches_artifact_key="dated_challenge_replay_note_json",
        source_script="research/papers/agentic-security/sim/generate_challenge_replay_note.py",
        generator_command=(
            "uv run python papers/agentic-security/sim/generate_challenge_replay_note.py"
        ),
    )
]


MANUSCRIPT_COMPONENTS = [
    {
        "component_key": "default_scaffold_tables",
        "role": "Deterministic scaffold metrics table and violation funnel in the early evaluation sections.",
        "source_script": "research/papers/agentic-security/sim/run_policy_eval.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/run_policy_eval.py "
                "--scenario default "
                "--output papers/agentic-security/sim/results/2026-03-14-default.json"
            )
        ],
        "supporting_artifact_keys": ["default_scaffold_json"],
    },
    {
        "component_key": "scenario_replay_table_and_figure",
        "role": "Five-seed scenario replay matrix table and the policy-scenario replay figure.",
        "source_script": "research/papers/agentic-security/sim/run_policy_eval.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/run_policy_eval.py "
                "--scenario default --seed-sweep 40 41 42 43 44 "
                "--output papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json"
            ),
            (
                "uv run python papers/agentic-security/sim/run_policy_eval.py "
                "--scenario stress --n-tasks 300 --base-violation-rate 0.22 "
                "--policy-block-rate 0.65 --utility-penalty 0.10 --seed-sweep 40 41 42 43 44 "
                "--output papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json"
            ),
            (
                "uv run python papers/agentic-security/sim/plot_policy_scenarios.py "
                "papers/agentic-security/sim/results/2026-03-17-default-seed-sweep.json "
                "papers/agentic-security/sim/results/2026-03-17-stress-seed-sweep.json "
                "--output papers/agentic-security/figures/policy-scenario-replay.pdf"
            ),
        ],
        "supporting_artifact_keys": [
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "policy_scenario_replay_pdf",
        ],
    },
    {
        "component_key": "cyber_benchmark_mapping_table",
        "role": "Cyber benchmark-note mapping table and supporting suite-to-artifact alignment note.",
        "source_script": "research/papers/agentic-security/sim/generate_cyber_benchmark_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_cyber_benchmark_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "cyber_benchmark_note_json",
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "dated_challenge_replay_note_json",
        ],
    },
    {
        "component_key": "cyber_benchmark_note_consistency_qa",
        "role": "Publication-facing pytest guard that checks the benchmark-note coverage snapshot and suite mappings against the dated replay and scenario JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_cyber_benchmark_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "cyber_benchmark_note_consistency_test",
            "cyber_benchmark_note_json",
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "dated_challenge_replay_note_json",
        ],
    },
    {
        "component_key": "obliteratus_replay_readiness_note",
        "role": "Task-level OBLITERATUS replay-readiness note that binds current guarded cyber traces to future refusal-direction regression checks.",
        "source_script": "research/papers/agentic-security/sim/generate_obliteratus_replay_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_obliteratus_replay_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_replay_note_json",
            "cyber_benchmark_note_json",
            "dated_challenge_replay_note_json",
        ],
    },
    {
        "component_key": "obliteratus_replay_note_consistency_qa",
        "role": "Publication-facing pytest guard that checks the OBLITERATUS replay-readiness note against the dated challenge-replay and cyber benchmark-note JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_obliteratus_replay_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_replay_note_consistency_test",
            "obliteratus_replay_note_json",
            "cyber_benchmark_note_json",
            "dated_challenge_replay_note_json",
        ],
    },
    {
        "component_key": "obliteratus_intervention_acceptance_note",
        "role": "Intervention-acceptance note that combines seed-sweep stability floors with replay-backed first-guard probes for future refusal-direction runs.",
        "source_script": "research/papers/agentic-security/sim/generate_obliteratus_intervention_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_obliteratus_intervention_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_intervention_note_json",
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "dated_challenge_replay_note_json",
            "obliteratus_replay_note_json",
        ],
    },
    {
        "component_key": "obliteratus_intervention_note_consistency_qa",
        "role": "Publication-facing pytest guard that checks the OBLITERATUS intervention-acceptance note against the dated seed-sweep, challenge-replay, and OBLITERATUS replay-note JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_obliteratus_intervention_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_intervention_note_consistency_test",
            "obliteratus_intervention_note_json",
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "dated_challenge_replay_note_json",
            "obliteratus_replay_note_json",
        ],
    },
    {
        "component_key": "obliteratus_policy_erosion_note",
        "role": "Synthetic policy-erosion sensitivity note that quantifies how quickly the current intervention-acceptance floors fail under reduced policy blocking.",
        "source_script": "research/papers/agentic-security/sim/generate_obliteratus_erosion_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_obliteratus_erosion_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_erosion_note_json",
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "obliteratus_intervention_note_json",
        ],
    },
    {
        "component_key": "obliteratus_erosion_note_consistency_qa",
        "role": "Publication-facing pytest guard that checks the OBLITERATUS policy-erosion note against the dated seed-sweep and intervention-acceptance JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_obliteratus_erosion_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_erosion_note_consistency_test",
            "obliteratus_erosion_note_json",
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "obliteratus_intervention_note_json",
        ],
    },
    {
        "component_key": "obliteratus_acceptance_margin_note",
        "role": "Acceptance-margin note that quantifies per-metric slack and deficit size across the bounded policy-erosion schedule for future refusal-direction reviews.",
        "source_script": "research/papers/agentic-security/sim/generate_obliteratus_acceptance_margin_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_obliteratus_acceptance_margin_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_acceptance_margin_note_json",
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "obliteratus_intervention_note_json",
            "obliteratus_erosion_note_json",
        ],
    },
    {
        "component_key": "obliteratus_acceptance_margin_note_consistency_qa",
        "role": "Publication-facing pytest guard that checks the OBLITERATUS acceptance-margin note against the dated seed-sweep, intervention-acceptance, and erosion JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_obliteratus_acceptance_margin_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_acceptance_margin_note_consistency_test",
            "obliteratus_acceptance_margin_note_json",
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "obliteratus_intervention_note_json",
            "obliteratus_erosion_note_json",
        ],
    },
    {
        "component_key": "obliteratus_watchlist_note",
        "role": "Monitoring watchlist note that combines the acceptance-envelope metric pressure with replay-backed first-guard cases for future OBLITERATUS reviews.",
        "source_script": "research/papers/agentic-security/sim/generate_obliteratus_watchlist_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_obliteratus_watchlist_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_watchlist_note_json",
            "obliteratus_replay_note_json",
            "obliteratus_acceptance_margin_note_json",
        ],
    },
    {
        "component_key": "obliteratus_watchlist_note_consistency_qa",
        "role": "Publication-facing pytest guard that checks the OBLITERATUS monitoring watchlist note against the dated replay-readiness and acceptance-margin JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_obliteratus_watchlist_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_watchlist_note_consistency_test",
            "obliteratus_watchlist_note_json",
            "obliteratus_replay_note_json",
            "obliteratus_acceptance_margin_note_json",
        ],
    },
    {
        "component_key": "obliteratus_followup_priority_note",
        "role": "Follow-up priority note that ranks the thinnest suite lanes and single-layer guard cases before the next live or intervention-backed OBLITERATUS review.",
        "source_script": "research/papers/agentic-security/sim/generate_obliteratus_followup_priority_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_obliteratus_followup_priority_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_followup_priority_note_json",
            "obliteratus_replay_note_json",
            "obliteratus_watchlist_note_json",
        ],
    },
    {
        "component_key": "obliteratus_followup_priority_note_consistency_qa",
        "role": "Publication-facing pytest guard that checks the OBLITERATUS follow-up priority note against the dated replay-readiness and monitoring-watchlist JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_obliteratus_followup_priority_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_followup_priority_note_consistency_test",
            "obliteratus_followup_priority_note_json",
            "obliteratus_replay_note_json",
            "obliteratus_watchlist_note_json",
        ],
    },
    {
        "component_key": "obliteratus_live_priority_probe_note",
        "role": "Bounded live LLM sentinel probe that checks whether a current frontier model still targets the documented first decisive guard surfaces across the current six-case OBLITERATUS queue without claiming live tool traces.",
        "source_script": "research/papers/agentic-security/sim/generate_obliteratus_live_priority_probe_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_obliteratus_live_priority_probe_note.py "
                "--artifact-dir papers/agentic-security/artifacts/live_llm/20260409T220346Z "
                "--output papers/agentic-security/sim/results/2026-04-09-obliteratus-live-priority-probe-note.json"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_live_priority_probe_note_json",
            "obliteratus_replay_note_json",
            "obliteratus_followup_priority_note_json",
        ],
    },
    {
        "component_key": "obliteratus_review_packet",
        "role": "Review packet that turns the current OBLITERATUS replay, stability, erosion, watchlist, and follow-up artifacts into one explicit next-run contract.",
        "source_script": "research/papers/agentic-security/sim/generate_obliteratus_review_packet.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_obliteratus_review_packet.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_review_packet_json",
            "obliteratus_replay_note_json",
            "obliteratus_intervention_note_json",
            "obliteratus_erosion_note_json",
            "obliteratus_acceptance_margin_note_json",
            "obliteratus_watchlist_note_json",
            "obliteratus_followup_priority_note_json",
        ],
    },
    {
        "component_key": "obliteratus_review_packet_consistency_qa",
        "role": "Publication-facing pytest guard that checks the OBLITERATUS review packet against the dated replay, intervention, erosion, acceptance-margin, watchlist, and follow-up JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_obliteratus_review_packet.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_review_packet_consistency_test",
            "obliteratus_review_packet_json",
            "obliteratus_replay_note_json",
            "obliteratus_intervention_note_json",
            "obliteratus_erosion_note_json",
            "obliteratus_acceptance_margin_note_json",
            "obliteratus_watchlist_note_json",
            "obliteratus_followup_priority_note_json",
        ],
    },
    {
        "component_key": "obliteratus_failure_ladder_note",
        "role": "Failure-ladder note that compresses the current OBLITERATUS acceptance-margin and watchlist bundle into a scenario-by-scenario break schedule.",
        "source_script": "research/papers/agentic-security/sim/generate_obliteratus_failure_ladder_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_obliteratus_failure_ladder_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_failure_ladder_note_json",
            "obliteratus_acceptance_margin_note_json",
            "obliteratus_watchlist_note_json",
        ],
    },
    {
        "component_key": "obliteratus_failure_ladder_note_consistency_qa",
        "role": "Publication-facing pytest guard that checks the OBLITERATUS failure-ladder note against the dated acceptance-margin and watchlist JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_obliteratus_failure_ladder_note.py"
            )
        ],
        "supporting_artifact_keys": [
            "obliteratus_failure_ladder_note_consistency_test",
            "obliteratus_failure_ladder_note_json",
            "obliteratus_acceptance_margin_note_json",
            "obliteratus_watchlist_note_json",
        ],
    },
    {
        "component_key": "challenge_replay_tables_and_figures",
        "role": "Challenge replay table, challenge replay matrix figure, tactic breakdown table, and tactic breakdown figure.",
        "source_script": "research/papers/agentic-security/sim/generate_challenge_replay_note.py",
        "direct_regeneration_commands": [
            (
                "uv run python papers/agentic-security/sim/generate_challenge_replay_note.py"
            ),
            (
                "uv run python papers/agentic-security/sim/plot_challenge_replay_matrix.py "
                "papers/agentic-security/sim/results/2026-03-27-challenge-replay-note.json "
                "--output papers/agentic-security/figures/challenge-replay-matrix.pdf"
            ),
            (
                "uv run python papers/agentic-security/sim/plot_tactic_breakdown.py "
                "papers/agentic-security/sim/results/2026-03-27-challenge-replay-note.json "
                "--output papers/agentic-security/figures/tactic-breakdown.pdf"
            ),
        ],
        "supporting_artifact_keys": [
            "dated_challenge_replay_note_json",
            "challenge_replay_matrix_pdf",
            "tactic_breakdown_pdf",
        ],
        "mirror_key": "latest_challenge_replay_note_json",
    },
    {
        "component_key": "citation_and_structural_qa_records",
        "role": "Citation provenance note plus structural manuscript-audit outputs used to confirm bibliography coverage and local-path resolution for this revision.",
        "direct_regeneration_commands": [_manuscript_audit_command()],
        "supporting_artifact_keys": [
            "citation_verification_note",
            "manuscript_audit_json",
            "manuscript_audit_md",
        ],
    },
    {
        "component_key": "scenario_replay_consistency_qa",
        "role": "Publication-facing pytest guard that checks the quoted scenario-replay numbers against the dated default and stress seed-sweep JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_manuscript_consistency.py"
            )
        ],
        "supporting_artifact_keys": [
            "scenario_replay_consistency_test",
            "default_seed_sweep_json",
            "stress_seed_sweep_json",
            "manuscript_source_tex",
        ],
    },
    {
        "component_key": "challenge_replay_consistency_qa",
        "role": "Publication-facing pytest guard that checks challenge-replay origin mix, action counts, tactic rows, and benchmark-derived case wording against the dated replay and benchmark-note JSON artifacts.",
        "direct_regeneration_commands": [
            _pytest_command(
                "research/tests/test_agentic_security_challenge_replay_consistency.py"
            )
        ],
        "supporting_artifact_keys": [
            "challenge_replay_consistency_test",
            "dated_challenge_replay_note_json",
            "cyber_benchmark_note_json",
            "manuscript_source_tex",
        ],
    },
]


def _run_git(*args: str) -> subprocess.CompletedProcess[str]:
    return subprocess.run(
        ["git", "-C", str(REPO_ROOT), *args],
        check=False,
        capture_output=True,
        text=True,
    )


def _sha256(path: Path) -> str:
    digest = hashlib.sha256()
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
    return digest.hexdigest()


def _git_commit_metadata(relative_path: str) -> tuple[str | None, str | None]:
    result = _run_git("log", "-1", "--format=%H%n%cI", "--", relative_path)
    if result.returncode != 0:
        raise RuntimeError(
            result.stderr.strip() or f"git log failed for {relative_path}"
        )
    lines = [line.strip() for line in result.stdout.splitlines() if line.strip()]
    if not lines:
        return None, None
    if len(lines) == 1:
        return lines[0], None
    return lines[0], lines[1]


def _git_tracking_status(relative_path: str) -> str:
    status = _run_git("status", "--short", "--", relative_path)
    if status.returncode != 0:
        raise RuntimeError(
            status.stderr.strip() or f"git status failed for {relative_path}"
        )
    raw = status.stdout.strip()
    if raw.startswith("??"):
        return "untracked"
    if not raw:
        return "tracked-clean"
    return "tracked-dirty"


def _artifact_record(spec: ArtifactSpec) -> dict:
    path = REPO_ROOT / spec.relative_path
    if not path.exists():
        if not spec.allow_missing:
            raise FileNotFoundError(path)
        record = {
            "artifact_key": spec.artifact_key,
            "role": spec.role,
            "relative_path": spec.relative_path,
            "exists": False,
            "git_tracking_status": "missing",
            "git_last_commit": None,
            "git_last_commit_time": None,
        }
        if spec.source_script:
            record["source_script"] = spec.source_script
        if spec.generator_command:
            record["generator_command"] = spec.generator_command
        if spec.input_artifact_keys:
            record["input_artifact_keys"] = list(spec.input_artifact_keys)
        return record

    commit, commit_time = _git_commit_metadata(spec.relative_path)
    record = {
        "artifact_key": spec.artifact_key,
        "role": spec.role,
        "relative_path": spec.relative_path,
        "exists": True,
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
        "git_tracking_status": _git_tracking_status(spec.relative_path),
        "git_last_commit": commit,
        "git_last_commit_time": commit_time,
    }
    if spec.source_script:
        record["source_script"] = spec.source_script
    if spec.generator_command:
        record["generator_command"] = spec.generator_command
    if spec.input_artifact_keys:
        record["input_artifact_keys"] = list(spec.input_artifact_keys)
    return record


def _mirror_record(spec: MirrorSpec, artifact_records: dict[str, dict]) -> dict:
    path = REPO_ROOT / spec.relative_path
    if not path.exists():
        raise FileNotFoundError(path)
    commit, commit_time = _git_commit_metadata(spec.relative_path)
    mirror_record = {
        "mirror_key": spec.mirror_key,
        "role": spec.role,
        "relative_path": spec.relative_path,
        "bytes": path.stat().st_size,
        "sha256": _sha256(path),
        "git_tracking_status": _git_tracking_status(spec.relative_path),
        "git_last_commit": commit,
        "git_last_commit_time": commit_time,
        "matches_artifact_key": spec.matches_artifact_key,
    }
    if spec.source_script:
        mirror_record["source_script"] = spec.source_script
    if spec.generator_command:
        mirror_record["generator_command"] = spec.generator_command
    target_record = artifact_records[spec.matches_artifact_key]
    mirror_record["byte_identical"] = (
        mirror_record["bytes"] == target_record["bytes"]
        and mirror_record["sha256"] == target_record["sha256"]
    )
    return mirror_record


def _parse_commit_time(value: str) -> datetime:
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def _scoped_workspace_revision(
    artifact_records: list[dict], mirror_records: list[dict]
) -> dict:
    tracked_records = [
        record
        for record in [*artifact_records, *mirror_records]
        if record.get("git_last_commit") and record.get("git_last_commit_time")
    ]
    if not tracked_records:
        return {
            "head_commit": None,
            "head_commit_time": None,
            "basis": (
                "No tracked git history was available for the bound artifacts at manifest time."
            ),
        }

    latest_record = max(
        tracked_records,
        key=lambda record: _parse_commit_time(record["git_last_commit_time"]),
    )
    return {
        "head_commit": latest_record["git_last_commit"],
        "head_commit_time": latest_record["git_last_commit_time"],
        "basis": (
            "Most recent tracked git commit among the bound artifacts and mirror checks in this manifest; "
            "intentionally scoped so unrelated later workspace/checkpoint commits do not invalidate the publication artifact snapshot."
        ),
    }


def build_manifest(*, output_path_text: str) -> dict:
    artifact_records = [_artifact_record(spec) for spec in ARTIFACT_SPECS]
    artifact_record_map = {
        record["artifact_key"]: record for record in artifact_records
    }
    mirror_records = [
        _mirror_record(spec, artifact_record_map) for spec in MIRROR_SPECS
    ]

    return {
        "artifact": "agentic-security-publication-artifact-manifest",
        "manifest_date": "2026-03-27",
        "generated_at": datetime.now(timezone.utc)
        .replace(microsecond=0)
        .isoformat()
        .replace("+00:00", "Z"),
        "paper": PAPER_TITLE,
        "manuscript_path": _workspace_path_text(MANUSCRIPT_PATH),
        "path_basis": (
            "All relative_path and source_script entries are relative to the workspace root. "
            "direct_regeneration_commands and generator_command values are intended to be executed from the workspace research/ directory, "
            "with any non-research inputs or outputs referenced via ../ paths from that workdir. "
            "publication_pdf_snapshot.rebuild_commands are intended to be executed from publication_pdf_snapshot.working_directory."
        ),
        "scope_note": (
            "Publication-facing sync between the manuscript, the citation/path QA records for this revision, the exact local JSON/PDF evidence artifacts that back the current revision, "
            "and the compiled LNCS PDF snapshot plus shared BibTeX input used to rebuild it. Each artifact records current byte size, "
            "SHA-256 digest, and the last tracked git commit/time when available."
        ),
        "workspace_revision": _scoped_workspace_revision(
            artifact_records,
            mirror_records,
        ),
        "manifest_generator": {
            "source_script": _workspace_path_text(MANIFEST_SCRIPT),
            "generator_command": _manifest_generator_command(output_path_text),
        },
        "manuscript_components": MANUSCRIPT_COMPONENTS,
        "artifacts": artifact_records,
        "publication_pdf_snapshot": PUBLICATION_PDF_SNAPSHOT,
        "mirror_checks": mirror_records,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate the agentic-security publication artifact manifest."
    )
    parser.add_argument(
        "--output",
        type=Path,
        default=DEFAULT_OUTPUT_PATH,
        help=(
            "Path to write the manifest JSON. Relative paths are resolved from the repo root; "
            "paths outside research/ must already include that prefix."
        ),
    )
    return parser.parse_args()


def main() -> None:
    args = parse_args()
    normalized_output = _normalize_output_path(args.output)
    output_path_text = _workspace_relative_path_text(normalized_output)
    manifest = build_manifest(output_path_text=output_path_text)
    out_path = REPO_ROOT / output_path_text
    out_path.parent.mkdir(parents=True, exist_ok=True)
    out_path.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")
    print(out_path)


if __name__ == "__main__":
    main()
