#!/usr/bin/env bash
set -euo pipefail

# Wrapper for running OBLITERATUS benchmark flows for agentic/LLM-security study.
# NOTE: Run in a properly provisioned GPU environment when model benchmarks are enabled.

ROOT="$(cd "$(dirname "$0")/../../.." && pwd)"
OBLIT_DIR="$ROOT/external/OBLITERATUS"

if [[ ! -d "$OBLIT_DIR" ]]; then
  echo "[!] OBLITERATUS repo not found at: $OBLIT_DIR"
  echo "    Expected clone path: research/external/OBLITERATUS"
  exit 1
fi

cd "$OBLIT_DIR"

echo "[+] OBLITERATUS path: $OBLIT_DIR"
echo "[+] Suggested first step: uv sync (or pip install -e .)"

echo "[+] Example benchmark entrypoint:"
echo "    python scripts/benchmark_sota_comparison.py"

echo "[+] Example abliteration comparison:"
echo "    python scripts/abliteration_comparison.py"

echo "[+] Record outputs for manuscript in:"
echo "    $ROOT/papers/agentic-security/sim/results/obliteratus/"
