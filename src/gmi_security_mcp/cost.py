"""Cost estimation from models-80.json, never from hard-coded prices.

Source of the formula: the Security Audit Tool, index.html typicalCost
and maxCost, and run_benchmark.py estimate_cost_usd.
  prompt tokens: about 4 characters per token, plus 150 for the prompt
  typical completion: 250 tokens
  maximum completion: max_tokens
  safe upper bound (runner): 250 prompt tokens and 2500 completion
  tokens per finding

Pricing is read from models-80.json at runtime. A model with no flat
per-token pricing is unpriced: its cost is None, never invented.
"""

import json
import math
from pathlib import Path

PROMPT_OVERHEAD_TOKENS = 150
TYPICAL_COMPLETION_TOKENS = 250
SAFE_PROMPT_TOKENS = 250
SAFE_COMPLETION_TOKENS = 2500
# Observed prompt-token maxima from live usage. Sol reports about 4550
# prompt tokens per call, almost all provider-side cached tokens.
OBSERVED_PROMPT_TOKENS = {"openai/gpt-6.1-sol": 4550}

DEFAULT_SPEND_CAP_USD = 1.00
MAX_SPEND_CAP_USD = 5.00


def _pricing_file_candidates():
    here = Path(__file__).resolve()
    return [
        here.parent / "models-80.json",
        here.parents[2] / "models-80.json",
        Path.cwd() / "models-80.json",
    ]


def load_pricing(path=None):
    """Return {model_id: (prompt_price, completion_price)}.

    Skips models with no flat prompt/completion pricing. When a model
    id appears twice, a paid entry wins over a free ($0) one, so an
    estimate is never $0 for a model that is actually billed.
    """
    candidates = [Path(path)] if path else _pricing_file_candidates()
    data = None
    for candidate in candidates:
        if candidate.is_file():
            data = json.loads(candidate.read_text())
            break
    if data is None:
        raise FileNotFoundError("models-80.json not found in " + str(candidates))
    entries = data.get("data", data) if isinstance(data, dict) else data
    pricing = {}
    for model in entries:
        model_id = model.get("id")
        price = model.get("pricing") or {}
        if not isinstance(price, dict):
            continue
        if "prompt" not in price or "completion" not in price:
            continue
        try:
            prompt_price = float(price.get("prompt") or 0)
            completion_price = float(price.get("completion") or 0)
        except (TypeError, ValueError):
            continue
        existing = pricing.get(model_id)
        if existing is None:
            pricing[model_id] = (prompt_price, completion_price)
        elif existing[0] + existing[1] == 0 and prompt_price + completion_price > 0:
            pricing[model_id] = (prompt_price, completion_price)
    return pricing


def estimate_prompt_tokens(text):
    """Prompt tokens for a text: 150 overhead plus about 1 per 4 chars."""
    length = 0 if text is None else len(text)
    return PROMPT_OVERHEAD_TOKENS + math.ceil(length / 4)


def typical_cost_usd(model, text, max_tokens, pricing=None):
    """Typical cost: estimated prompt tokens plus 250 completion tokens."""
    prices = pricing if pricing is not None else load_pricing()
    entry = prices.get(model)
    if entry is None:
        return None
    prompt_price, completion_price = entry
    prompt_tokens = estimate_prompt_tokens(text)
    return prompt_tokens * prompt_price + TYPICAL_COMPLETION_TOKENS * completion_price


def max_cost_usd(model, text, max_tokens, pricing=None):
    """Maximum cost: estimated prompt tokens plus max_tokens completion."""
    prices = pricing if pricing is not None else load_pricing()
    entry = prices.get(model)
    if entry is None:
        return None
    prompt_price, completion_price = entry
    prompt_tokens = estimate_prompt_tokens(text)
    return prompt_tokens * prompt_price + max_tokens * completion_price


def safe_upper_bound_usd(model, n_findings, pricing=None):
    """Safe upper bound per finding, as in run_benchmark.py: 250 prompt
    tokens (4550 for gpt-6.1-sol, observed) and 2500 completion tokens."""
    prices = pricing if pricing is not None else load_pricing()
    entry = prices.get(model)
    if entry is None:
        return None
    prompt_price, completion_price = entry
    prompt_tokens = OBSERVED_PROMPT_TOKENS.get(model, SAFE_PROMPT_TOKENS)
    return n_findings * (
        prompt_tokens * prompt_price + SAFE_COMPLETION_TOKENS * completion_price
    )


def cost_from_usage(usage, model, pricing=None):
    """Actual cost from API usage tokens. 0 when usage or pricing is missing."""
    if not isinstance(usage, dict):
        return 0.0
    prices = pricing if pricing is not None else load_pricing()
    entry = prices.get(model)
    if entry is None:
        return 0.0
    prompt_price, completion_price = entry
    prompt_tokens = usage.get("prompt_tokens") or 0
    completion_tokens = usage.get("completion_tokens") or 0
    try:
        return float(prompt_tokens) * prompt_price + float(
            completion_tokens
        ) * completion_price
    except (TypeError, ValueError):
        return 0.0


def estimate_cost(model, text_length_chars, max_tokens=2500, n_findings=1, pricing=None):
    """Estimate for estimate_cost tool: no API call, no spend.

    Returns a dict with typical_usd, max_usd, prompt_tokens_estimate,
    pricing, and priced. Unpriced models return priced False and null
    costs, never an invented price.
    """
    prices = pricing if pricing is not None else load_pricing()
    entry = prices.get(model)
    prompt_tokens = estimate_prompt_tokens("x" * max(0, int(text_length_chars)))
    if entry is None:
        return {
            "model": model,
            "priced": False,
            "typical_usd": None,
            "max_usd": None,
            "prompt_tokens_estimate": prompt_tokens,
            "pricing": None,
            "message": (
                "This model has no flat per-token pricing, so its cost "
                "cannot be estimated. Pick a priced model instead."
            ),
        }
    prompt_price, completion_price = entry
    typical = n_findings * (
        prompt_tokens * prompt_price + TYPICAL_COMPLETION_TOKENS * completion_price
    )
    maximum = n_findings * (
        prompt_tokens * prompt_price + max_tokens * completion_price
    )
    return {
        "model": model,
        "priced": True,
        "typical_usd": typical,
        "max_usd": maximum,
        "prompt_tokens_estimate": prompt_tokens,
        "pricing": {"prompt": prompt_price, "completion": completion_price},
        "message": None,
    }
