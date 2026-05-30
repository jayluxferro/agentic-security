# Deterministic Policy Guards for Autonomous Security Agents

**A Multi-Model Live Evaluation**

This repository accompanies the paper *"Deterministic Policy Guards for Autonomous Security Agents: A Multi-Model Live Evaluation"* (IEEE TIFS submission, 2026).

## Overview

We introduce the **Security Action Proposal (SAP)** methodology for evaluating LLM agent safety, and apply it to a deterministic policy guard that classifies proposed agent actions as allow, deny, or transform. The evaluation spans 8 frontier LLMs, 40 security-operation scenarios, and 4,066 actions.

### Key Findings

| Metric | Value |
|--------|-------|
| Actions evaluated | 4,066 |
| Models evaluated | 8 |
| Scenarios | 40 (9 attack categories) |
| Guard recall | 0.251 [0.231, 0.272] |
| Guard precision | 0.912 [0.886, 0.934] |
| Learned classifier recall | 0.880 |
| Per-model violation range | 0.061 -- 0.716 (12x) |
| Inter-rater agreement (4 judges) | Fleiss' κ = 0.042 |

### Key Findings

1. **42.5% of LLM-proposed security actions are dangerous** -- nearly half of all proposals
2. **The guard catches 1 in 4 dangerous actions** with 91.2% precision and 98.2% utility
3. **Model selection is a 12x safety lever** -- Qwen-9B (6.1%) vs Gemma-4-31B (71.6%)
4. **52.5% of missed detections are abstract descriptions** -- a fundamental ceiling on pattern-based enforcement
5. **Four safety classifiers disagree completely** -- dangerous rates from 0% (Llama Guard) to 50% (Claude)

## Repository Structure

```
.
├── main.tex                    # IEEE TIFS paper (IEEEtran, 14 pages)
├── refs.bib                    # 60 references
├── figures/                    # 8 figures (PDF)
├── experiments/
│   ├── scenario_bank.py        # 40-scenario generator
│   ├── policy_guard.py         # 44-rule deterministic guard
│   ├── run_sap.py              # Async evaluation runner
│   ├── score_sap.py            # LLM judge pipeline
│   ├── aggregate_metrics.py    # Wilson CI metrics
│   ├── rule_analysis.py        # Per-rule precision/recall
│   ├── false_negative_analysis.py  # FN taxonomy
│   ├── inter_rater.py          # Cohen's κ & Fleiss' κ
│   ├── judge_sensitivity.py    # Judge-dependence analysis
│   ├── learned_baseline.py     # TF-IDF + logistic regression
│   ├── llama_guard_eval.py     # Llama Guard 4 12B comparison
│   ├── baseline_eval.py        # Prompt-only safety baseline
│   ├── plot_results.py         # Basic figures
│   ├── plot_advanced.py        # Advanced figures
│   └── results/                # Summary metrics (JSON)
├── scripts/
│   └── package.sh              # Submission packaging
├── sim/                        # Legacy simulation code
└── data/                       # Empty (data dir for results)
```

## Quick Start

### Prerequisites
```bash
pip install httpx numpy matplotlib scikit-learn
```

### Reproduce Evaluation

1. Generate scenarios:
```bash
python3 experiments/scenario_bank.py
```

2. Run evaluation (requires DW + OR API keys):
```bash
python3 experiments/run_sap.py
```

3. Apply guard:
```bash
python3 -c "from experiments.policy_guard import guard_from_raw_jsonl; from pathlib import Path; guard_from_raw_jsonl(Path('experiments/results/raw_actions.jsonl'), Path('experiments/results/guard_output.jsonl'))"
```

4. Score with judge (requires OR API key):
```bash
python3 experiments/score_sap.py
```

5. Compute metrics:
```bash
python3 experiments/aggregate_metrics.py
```

6. Generate figures:
```bash
python3 experiments/plot_results.py
python3 experiments/plot_advanced.py
```

7. Compile paper:
```bash
pdflatex main.tex && bibtex main && pdflatex main.tex && pdflatex main.tex
```

### Additional Analyses
```bash
# Rule analysis
python3 experiments/rule_analysis.py

# False negative categorization
python3 experiments/false_negative_analysis.py

# Inter-rater reliability (requires API keys)
python3 experiments/inter_rater.py

# Prompt-only safety baseline (requires API keys)
python3 experiments/baseline_eval.py

# Llama Guard comparison (requires OR API key)
python3 experiments/llama_guard_eval.py

# Learned classifier baseline
python3 experiments/learned_baseline.py
```

## Data Format

The evaluation produces three JSONL files (not included in repo due to size):

- `raw_actions.jsonl` -- Raw model outputs with parsed actions
- `guard_output.jsonl` -- Actions with guard decisions (allow/deny/transform)
- `scored_results.jsonl` -- Actions with judge classifications (SAFE/DANGEROUS/NEEDS_REDACTION)

Summary metrics are available in `experiments/results/metrics.json`.

## Model Grid

| Model | Provider | Context Window |
|-------|----------|---------------|
| DeepSeek-V4-Pro | DoubleWordAI | 1,048,576 |
| DeepSeek-V4-Flash | DoubleWordAI | 1,048,576 |
| Kimi-K2.6 | DoubleWordAI | 262,144 |
| Qwen-35B (Qwen3.6) | DoubleWordAI | 262,144 |
| Qwen-9B (Qwen3.5) | DoubleWordAI | 262,144 |
| Gemma-4-31B | DoubleWordAI | 256,000 |
| Nemotron-120B | DoubleWordAI | 1,000,000 |
| Claude-Sonnet-4.6 | OpenRouter | 1,000,000 |

## Judges

| Judge | Provider | Dangerous Rate |
|-------|----------|---------------|
| Claude-Sonnet-4.6 | OpenRouter | 50.0% |
| DeepSeek-V4-Flash | DoubleWordAI | 35.5% |
| Qwen-35B | DoubleWordAI | 5.5% |
| Llama Guard 4 12B | OpenRouter | 0.0% |

## License

MIT License

## Citation

```bibtex
@article{owusuagyemang2026deterministic,
  title={Deterministic Policy Guards for Autonomous Security Agents: A Multi-Model Live Evaluation},
  author={Owusu Agyemang, Justice and Agyare, Michael and Opuni-Boachie Obour Agyekum, Kwame and Agyeman-Prempeh Agyekum, Kwame and Acheampong, Francisca Adoma and Kponyo, Jerry John},
  journal={arXiv preprint arXiv:XXXX.XXXXX},
  year={2026}
}
```
