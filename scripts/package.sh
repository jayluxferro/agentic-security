#!/bin/bash
# Package agentic-security paper for conference submission
set -e

PAPER_DIR="$(cd "$(dirname "$0")/../paper" 2>/dev/null && pwd || cd "$(dirname "$0")/.." && pwd)"
ZIPNAME="agentic-security-$(date +%Y%m%d).zip"
TMPDIR=$(mktemp -d)

echo "Packaging for submission..."

# Paper source
if [ -d "$PAPER_DIR/paper" ]; then
    cp paper/main.tex "$TMPDIR/"
    cp -r paper/figures "$TMPDIR/figures" 2>/dev/null || true
else
    cp main.tex "$TMPDIR/"
    cp -r figures "$TMPDIR/figures" 2>/dev/null || true
fi

# Experiment artifacts — results only, not scripts
mkdir -p "$TMPDIR/experiments/results"
for f in experiments/results/metrics.json experiments/results/scenario_bank.json; do
    if [ -f "$f" ]; then
        cp "$f" "$TMPDIR/$f"
    fi
done

# Clean build artifacts
find "$TMPDIR" -name '*.aux' -delete
find "$TMPDIR" -name '*.log' -delete

# Create zip
cd "$TMPDIR"
zip -r "$ZIPNAME" . > /dev/null
mv "$ZIPNAME" "$OLDPWD/"
cd "$OLDPWD"
rm -rf "$TMPDIR"

echo "Done: $ZIPNAME ($(du -h "$ZIPNAME" | cut -f1))"
