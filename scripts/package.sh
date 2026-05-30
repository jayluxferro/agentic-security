#!/bin/bash
# Package agentic-security LaTeX source for IEEE TIFS submission
# Excludes compiled PDF, includes only source + figures needed to compile
set -e

SCRIPT_DIR="$(cd "$(dirname "$0")" && pwd)"
PROJECT_DIR="$(dirname "$SCRIPT_DIR")"
ZIPNAME="agentic-security-tifs-$(date +%Y%m%d).zip"
TMPDIR=$(mktemp -d)

echo "Packaging LaTeX source for IEEE TIFS submission..."

# LaTeX source
cp "$PROJECT_DIR/main.tex" "$TMPDIR/"
cp "$PROJECT_DIR/main.bbl" "$TMPDIR/"
cp "$PROJECT_DIR/refs.bib" "$TMPDIR/"
cp "$PROJECT_DIR/IEEEtran.cls" "$TMPDIR/" 2>/dev/null || true

# Figures
cp -r "$PROJECT_DIR/figures" "$TMPDIR/figures"

# Experiment metadata — compact JSON summaries
mkdir -p "$TMPDIR/experiments/results"
for f in metrics.json scenario_bank.json rule_analysis.json false_negative_analysis.json \
         inter_rater_results.json fleiss_kappa.json llama_guard_results.json \
         learned_baseline.json judge_sensitivity.json; do
    src="$PROJECT_DIR/experiments/results/$f"
    if [ -f "$src" ]; then
        cp "$src" "$TMPDIR/experiments/results/"
    fi
done

# Remove any stray build artifacts
find "$TMPDIR" -name '*.aux' -delete
find "$TMPDIR" -name '*.log' -delete

# Create zip
cd "$TMPDIR"
zip -r "$ZIPNAME" . > /dev/null
mv "$ZIPNAME" "$PROJECT_DIR/"
cd "$PROJECT_DIR"
rm -rf "$TMPDIR"

echo "Done: $ZIPNAME ($(du -h "$ZIPNAME" | cut -f1))"
echo "Contents:"
unzip -l "$ZIPNAME"
