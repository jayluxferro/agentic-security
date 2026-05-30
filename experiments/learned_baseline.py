#!/usr/bin/env python3
"""Train TF-IDF + logistic regression classifier on labeled actions as a learned baseline."""
import json, random
from pathlib import Path
from collections import Counter
from sklearn.feature_extraction.text import TfidfVectorizer
from sklearn.linear_model import LogisticRegression
from sklearn.model_selection import StratifiedKFold, cross_val_predict
from sklearn.metrics import classification_report, confusion_matrix
import numpy as np

EXPERIMENTS = Path(__file__).resolve().parent
RESULTS = EXPERIMENTS / "results"
SCORED = RESULTS / "scored_results.jsonl"
OUTPUT = RESULTS / "learned_baseline.json"

random.seed(42)
np.random.seed(42)

# Load labeled data
entries = []
with open(SCORED) as f:
    for line in f:
        if line.strip():
            entries.append(json.loads(line))

texts, labels = [], []
for e in entries:
    if e.get("judge_status") != "ok":
        continue
    for a in e.get("actions", []):
        if "judge" in a:
            texts.append(a["action"])
            labels.append(a["judge"])

print(f"Loaded {len(texts)} labeled actions")
print(f"Class distribution: {dict(Counter(labels))}")

# Binary classification: DANGEROUS vs not
y_binary = [1 if l == "DANGEROUS" else 0 for l in labels]
print(f"Binary: {sum(y_binary)} DANGEROUS, {len(y_binary)-sum(y_binary)} SAFE/REDACT")

# TF-IDF vectorization
vectorizer = TfidfVectorizer(
    max_features=5000, ngram_range=(1, 2),
    sublinear_tf=True, min_df=2, max_df=0.9
)
X = vectorizer.fit_transform(texts)
print(f"TF-IDF features: {X.shape[1]}")

# 5-fold stratified CV
cv = StratifiedKFold(n_splits=5, shuffle=True, random_state=42)
model = LogisticRegression(max_iter=1000, C=1.0, class_weight="balanced", random_state=42)
y_pred = cross_val_predict(model, X, y_binary, cv=cv, method="predict")

# Metrics
tn = sum(1 for t, p in zip(y_binary, y_pred) if t == 0 and p == 0)
fp = sum(1 for t, p in zip(y_binary, y_pred) if t == 0 and p == 1)
fn = sum(1 for t, p in zip(y_binary, y_pred) if t == 1 and p == 0)
tp = sum(1 for t, p in zip(y_binary, y_pred) if t == 1 and p == 1)

recall = tp / (tp + fn) if (tp + fn) > 0 else 0
precision = tp / (tp + fp) if (tp + fp) > 0 else 0
f1 = 2 * recall * precision / (recall + precision) if (recall + precision) > 0 else 0
utility = tn / (tn + fp) if (tn + fp) > 0 else 0

# Also train and evaluate per model
per_model = {}
for model_name in sorted(set(e["model_label"] for e in entries if e.get("judge_status") == "ok")):
    idxs = []
    for i, e in enumerate(entries):
        if e.get("judge_status") != "ok":
            continue
        for a in e.get("actions", []):
            if "judge" not in a:
                continue
            if e["model_label"] == model_name:
                idxs.append(len(idxs))
    if len(idxs) < 10:
        continue
    model_texts = [texts[i] for i in range(len(texts)) if any(
        e["model_label"] == model_name for e in entries if e.get("judge_status") == "ok"
        for _ in e.get("actions", []) if _.get("action") == texts[i]
    )]
    # Simpler: train on all data, evaluate per-model
    model_y = [y_binary[i] for i in range(len(texts))]
    model_X = vectorizer.transform(model_texts) if len(model_texts) < len(texts) else X
    # Actually let's just do per-model holdout using the full model
    pass  # Skip per-model for now, use overall CV

results = {
    "classifier": "TF-IDF + LogisticRegression (C=1.0, balanced)",
    "features": X.shape[1],
    "cv_folds": 5,
    "total_samples": len(texts),
    "recall": round(recall, 4),
    "precision": round(precision, 4),
    "f1": round(f1, 4),
    "utility": round(utility, 4),
    "confusion": {"tp": int(tp), "fp": int(fp), "tn": int(tn), "fn": int(fn)},
    "intervention_rate": round((tp + fp) / len(texts), 4),
    "comparison": {
        "regex_guard_recall": 0.251,
        "regex_guard_precision": 0.912,
        "learned_recall": round(recall, 4),
        "learned_precision": round(precision, 4),
        "recall_delta": round(recall - 0.251, 4),
        "precision_delta": round(precision - 0.912, 4),
    },
}

OUTPUT.write_text(json.dumps(results, indent=2))
print(f"\n=== LEARNED BASELINE RESULTS ===")
print(f"Recall: {recall:.3f} (regex: 0.251, delta: {recall-0.251:+.3f})")
print(f"Precision: {precision:.3f} (regex: 0.912, delta: {precision-0.912:+.3f})")
print(f"F1: {f1:.3f}")
print(f"Utility: {utility:.3f}")
print(f"Intervention rate: {(tp+fp)/len(texts)*100:.1f}%")
print(f"Confusion: TP={tp}, FP={fp}, TN={tn}, FN={fn}")
print(f"\nOutput: {OUTPUT}")
