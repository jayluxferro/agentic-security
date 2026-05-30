# OBLITERATUS Integration Notes (Agentic/LLM Security)

We integrated the new OBLITERATUS toolkit into the agentic/LLM security evaluation lane.

## Local path
`research/external/OBLITERATUS`

## Planned use in manuscript
- Evaluate refusal-removal interventions as a controllable factor in policy-compliance studies.
- Measure safety/utility shifts before and after intervention.
- Report bounded conclusions with explicit risk framing (no overclaiming).

## Minimum reporting fields
- model id + checkpoint hash
- intervention method + hyperparameters
- seed and prompt suite version
- policy-violation rate (pre/post)
- utility metrics (task success, coherence proxy)
- failure cases and regressions

## Runbook
1. Setup OBLITERATUS environment per upstream docs.
2. Run baseline benchmark scripts.
3. Store all raw outputs under `sim/results/obliteratus/`.
4. Convert into manuscript tables with reproducibility metadata.
