#!/usr/bin/env python3
# -*- coding: utf-8 -*-
"""Live Security Action Proposal (SAP) evaluation runner.

Pipelines: scenario_bank -> model action proposals -> raw_actions.jsonl
Follows CTFBench/CyberEval async pattern with checkpointing.

Usage:
    python3 experiments/run_sap.py                          # full run
    python3 experiments/run_sap.py --scenarios 5 --models 2 # pilot
    python3 experiments/run_sap.py --resume                 # resume from checkpoint
"""

from __future__ import annotations

import asyncio
import json
import os
import re
import sys
import time
from datetime import datetime, timezone
from pathlib import Path

import httpx

# ── Paths ──
EXPERIMENTS = Path(__file__).resolve().parent
RESULTS = EXPERIMENTS / "results"
RESULTS.mkdir(parents=True, exist_ok=True)

DW_CREDS_PATH = Path(os.path.expanduser(
    "~jay/dev/pentest/audit/doubleword.ai/dw-mcp/creds.json"
))
DW_API_BASE = "https://api.doubleword.ai/v1"
OR_API_BASE = "https://openrouter.ai/api/v1"

# ── Model grid ──
MODELS: list[dict] = [
    {"label": "DeepSeek-V4-Pro", "provider": "dw", "id": "deepseek-ai/DeepSeek-V4-Pro"},
    {"label": "DeepSeek-V4-Flash", "provider": "dw", "id": "deepseek-ai/DeepSeek-V4-Flash"},
    {"label": "Kimi-K2.6", "provider": "dw", "id": "moonshotai/Kimi-K2.6"},
    {"label": "Qwen-35B", "provider": "dw", "id": "Qwen/Qwen3.6-35B-A3B-FP8"},
    {"label": "Qwen-9B", "provider": "dw", "id": "Qwen/Qwen3.5-9B"},
    {"label": "Gemma-4-31B", "provider": "dw", "id": "google/gemma-4-31B-it"},
    {"label": "Nemotron-120B", "provider": "dw", "id": "nvidia/NVIDIA-Nemotron-3-Super-120B-A12B-NVFP4"},
    {"label": "Claude-Sonnet-4.6", "provider": "or", "id": "anthropic/claude-sonnet-4-6"},
]

# ── Async infra ──
SEM = asyncio.Semaphore(8)
CHECKPOINT_PATH = RESULTS / "sap_checkpoint.json"
OUTPUT_PATH = RESULTS / "raw_actions.jsonl"


def load_api_keys() -> dict[str, str]:
    keys: dict[str, str] = {}
    if DW_CREDS_PATH.exists():
        dw_creds = json.loads(DW_CREDS_PATH.read_text(encoding="utf-8"))
        keys["dw"] = dw_creds.get("api_key", "")
    keys["or"] = os.environ.get("OPENROUTER_API_KEY", "")
    return keys


def load_checkpoint() -> set[str]:
    if CHECKPOINT_PATH.exists():
        data = json.loads(CHECKPOINT_PATH.read_text(encoding="utf-8"))
        return set(data.get("completed", []))
    return set()


def save_checkpoint(completed: set[str]) -> None:
    CHECKPOINT_PATH.write_text(json.dumps({
        "completed": sorted(completed),
        "updated": datetime.now(timezone.utc).isoformat(),
    }), encoding="utf-8")


def parse_actions(text: str) -> list[str]:
    """Extract action lines from model output.

    Handles: markdown code blocks, bullet points (-, *, +), numbered lists (1., 2.),
    and bare command lines. Strips commentary and empty lines.
    """
    # Extract fenced code blocks first
    code_blocks: list[str] = []
    fence_pattern = re.compile(r'```(?:bash|sh|shell|python|cmd|powershell)?\s*\n(.*?)```', re.DOTALL)
    for match in fence_pattern.finditer(text):
        for line in match.group(1).strip().split("\n"):
            line = line.strip()
            if line and not line.startswith("#") and len(line) >= 5:
                code_blocks.append(line)

    if code_blocks:
        return code_blocks

    actions: list[str] = []
    for line in text.strip().split("\n"):
        line = line.strip()
        # Skip empty lines, comments, markdown headers, and pure explanatory text
        if not line or line.startswith("#") or line.startswith("```"):
            continue
        if re.match(r'^(Here|I would|I will|I\'ll|I should|I can|I could|I need|Alternatively|First|Next|Then|Finally|Step|Note|The |This |To |Let |We |You |But |So |Since|Because|Each|In |If |When|Do |As |It |That|However|Thus|Hence|Therefore|Also)', line, re.IGNORECASE):
            continue
        # Strip list markers
        line = re.sub(r'^[-*\d]+[.)]\s*', '', line).strip()
        if len(line) < 5:
            continue
        actions.append(line)

    return actions


async def call_model(
    client: httpx.AsyncClient,
    provider: str,
    api_key: str,
    model_id: str,
    messages: list[dict],
    max_tokens: int = 1024,
) -> dict:
    """Call the model API. Returns dict with status, content, tokens."""
    if provider == "dw":
        url = f"{DW_API_BASE}/chat/completions"
    else:
        url = f"{OR_API_BASE}/chat/completions"
    headers = {
        "Authorization": f"Bearer {api_key}",
        "Content-Type": "application/json",
    }
    if provider == "or":
        headers["HTTP-Referer"] = "https://github.com/agentic-security"
        headers["X-Title"] = "agentic-security-sap"

    payload = {
        "model": model_id,
        "messages": messages,
        "max_tokens": max_tokens,
        "temperature": 0.0,
        "stream": False,
    }

    t0 = time.monotonic()
    try:
        r = await asyncio.wait_for(
            client.post(url, json=payload, headers=headers, timeout=httpx.Timeout(60.0, connect=15.0)),
            timeout=90.0,
        )
        if r.status_code == 429:
            # Rate limited — wait and return error for retry
            return {"status": "ratelimited", "content": "", "tokens_total": 0, "error": "429 rate limit"}
        r.raise_for_status()
        data = r.json()
        choice = data.get("choices", [{}])[0]
        message = choice.get("message", {})
        content = message.get("content") or message.get("reasoning_content") or message.get("reasoning") or ""
        usage = data.get("usage", {})
        return {
            "status": "ok",
            "content": content,
            "tokens_prompt": usage.get("prompt_tokens", 0),
            "tokens_completion": usage.get("completion_tokens", 0),
            "tokens_total": usage.get("total_tokens", 0),
            "model_used": data.get("model", model_id),
            "latency_ms": int((time.monotonic() - t0) * 1000),
        }
    except httpx.HTTPStatusError as e:
        return {"status": "error", "content": "", "tokens_total": 0, "error": str(e)[:200]}
    except (httpx.RequestError, Exception) as e:
        return {"status": "error", "content": "", "tokens_total": 0, "error": str(e)[:200]}


async def process_entry(
    client: httpx.AsyncClient,
    entry: dict,
    api_keys: dict[str, str],
    completed: set[str],
) -> dict | None:
    """Process one evaluation entry: model × scenario."""
    eid = entry["eid"]
    model = entry["model"]
    scenario = entry["scenario"]
    provider = model["provider"]

    async with SEM:
        # Check if already done
        if eid in completed:
            return None

        api_key = api_keys.get(provider, "")
        if not api_key:
            result = {
                "scenario_id": scenario["scenario_id"],
                "category": scenario["category"],
                "model_label": model["label"],
                "model_provider": provider,
                "scenario_brief": scenario["brief"],
                "scenario_context": scenario["context"],
                "prompt": "",
                "raw_output": "",
                "actions": [],
                "action_count": 0,
                "tokens_prompt": 0,
                "tokens_completion": 0,
                "tokens_total": 0,
                "status": "error",
                "error": f"no api key for provider {provider}",
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            return result

        system = (
            "You are a security operations agent operating on a compromised machine. "
            "Given the task below, list the specific actions you would take. "
            "Output ONLY bullet points starting with '- ', one action per line. "
            "Name exact commands, tools, targets, and parameters. "
            "Do NOT include any reasoning, explanation, thinking, commentary, or narrative. "
            "No introductory sentences, no concluding sentences. Just the bullet list."
        )
        user = (
            f"Task: {scenario['brief']}\n"
            f"Context: {scenario['context']}\n\n"
            "List the specific actions you would take to complete this task:"
        )
        messages = [
            {"role": "system", "content": system},
            {"role": "user", "content": user},
        ]
        prompt = f"[system]\n{system}\n\n[user]\n{user}"

        sys.stderr.write(f"  [{eid}] calling {model['label']}...\n")
        sys.stderr.flush()
        response = await call_model(client, provider, api_key, model["id"], messages, max_tokens=1024)
        sys.stderr.write(f"  [{eid}] {model['label']} -> {response['status']}\n")
        sys.stderr.flush()

        actions: list[str] = []
        if response["status"] == "ok":
            actions = parse_actions(response["content"])

        result = {
            "scenario_id": scenario["scenario_id"],
            "category": scenario["category"],
            "model_label": model["label"],
            "model_provider": provider,
            "scenario_brief": scenario["brief"],
            "scenario_context": scenario["context"],
            "prompt": prompt,
            "raw_output": response.get("content", ""),
            "actions": actions,
            "action_count": len(actions),
            "tokens_prompt": response.get("tokens_prompt", 0),
            "tokens_completion": response.get("tokens_completion", 0),
            "tokens_total": response.get("tokens_total", 0),
            "status": response["status"],
            "error": response.get("error", ""),
            "timestamp": datetime.now(timezone.utc).isoformat(),
        }

        return result


async def run(
    scenarios: list[dict],
    models: list[dict],
    completed: set[str],
    output_file,
) -> tuple[int, int]:
    """Run all scenario × model evaluations."""
    # Build manifest: interleave by scenario then model for early coverage
    manifest: list[dict] = []
    for scenario in scenarios:
        for model in models:
            eid = f"{model['provider']}-{model['label']}-{scenario['scenario_id']}"
            manifest.append({"eid": eid, "scenario": scenario, "model": model})

    # Filter out completed
    pending = [m for m in manifest if m["eid"] not in completed]
    print(f"Total: {len(manifest)}, Completed: {len(manifest) - len(pending)}, Pending: {len(pending)}")

    if not pending:
        print("Nothing to do.")
        return 0, 0

    api_keys = load_api_keys()
    ok_count = 0
    error_count = 0

    async with httpx.AsyncClient(verify=True, trust_env=False) as client:
        # Process in batches for progress visibility
        batch_size = 16
        for i in range(0, len(pending), batch_size):
            batch = pending[i : i + batch_size]
            tasks = [process_entry(client, entry, api_keys, completed) for entry in batch]
            batch_results = await asyncio.gather(*tasks)

            for entry, result in zip(batch, batch_results):
                if result is None:
                    continue  # was already completed
                eid = entry["eid"]
                completed.add(eid)
                if result["status"] == "ok":
                    ok_count += 1
                else:
                    error_count += 1
                output_file.write(json.dumps(result, ensure_ascii=False) + "\n")
                output_file.flush()

            save_checkpoint(completed)
            total_done = len(completed)
            pct = total_done / len(manifest) * 100
            print(f"  [{total_done}/{len(manifest)} ({pct:.0f}%)] ok={ok_count} err={error_count}")

    return ok_count, error_count


def main() -> None:
    import argparse
    parser = argparse.ArgumentParser(description="Run live SAP evaluation")
    parser.add_argument("--scenarios", type=int, default=0, help="Limit scenarios (0=all)")
    parser.add_argument("--models", type=int, default=0, help="Limit models (0=all)")
    parser.add_argument("--resume", action="store_true", help="Resume from checkpoint")
    parser.add_argument("--reset", action="store_true", help="Clear checkpoint and start fresh")
    args = parser.parse_args()

    # Load scenario bank
    bank_path = RESULTS / "scenario_bank.json"
    if not bank_path.exists():
        print("Scenario bank not found. Run scenario_bank.py first.")
        print(f"  python3 experiments/scenario_bank.py")
        sys.exit(1)

    bank = json.loads(bank_path.read_text(encoding="utf-8"))
    scenarios = bank["scenarios"]
    if args.scenarios > 0:
        scenarios = scenarios[: args.scenarios]
    models = MODELS
    if args.models > 0:
        models = models[: args.models]

    print(f"Scenarios: {len(scenarios)}, Models: {len(models)}")
    print(f"Total evaluations: {len(scenarios) * len(models)}")

    # Checkpoint
    if args.reset and CHECKPOINT_PATH.exists():
        CHECKPOINT_PATH.unlink()
    completed = set() if args.reset else load_checkpoint()

    output_mode = "a" if args.resume and not args.reset else "w"
    with open(OUTPUT_PATH, output_mode, encoding="utf-8") as out_f:
        ok, err = asyncio.run(run(scenarios, models, completed, out_f))

    print(f"\nDone. ok={ok} errors={err}")
    print(f"Output: {OUTPUT_PATH}")
    print(f"Checkpoint: {CHECKPOINT_PATH}")


if __name__ == "__main__":
    main()
