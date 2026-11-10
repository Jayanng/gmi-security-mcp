# Data sources

Copied 2026-11-10 from the Security Audit Tool build, with the
source and date noted for each file. Nothing here is invented.

## models-80.json

Source: the live GMI model list fetched 2026-11-10 with
`list-models` through the GMI Inference API. 80 entries, 80 unique
ids, saved verbatim in the API response shape. Replaces
models-82.json, which held the 2026-11-08 list: 82 entries, 81
unique ids, with `inclusionAI/Ling-3.0-flash-fin` listed twice.

Live re-check 2026-11-10, before the Phase 6 release: the live
list has 80 models. `inclusionAI/Ling-3.0-flash-fin` is gone
entirely, no replacement model was added, and pricing is unchanged
on all 79 shared models, including `google/gemini-3.5-flash-lite`
(prompt $0.000000300, completion $0.000002500 per token).
`gmicloud/Ripple-65B-Preview` still has no flat pricing (null) and
is treated as unpriced.

Live re-check 2026-11-10, before the v0.5.0 release: the live
list has 73 models, 73 unique, down from 80. Two consecutive
calls returned the same 73. Removed, 7 models:
`Qwen/Qwen3-Next-80B-A3B-Instruct`, `moonshotai/Kimi-K2-Instruct-0905`,
`moonshotai/Kimi-K2.6`, `openai/gpt-5.4`, `openai/gpt-5.4-mini`,
`openai/gpt-5.4-nano`, `openai/gpt-5.4-pro`. Pricing is unchanged
on all 73 shared models, including `google/gemini-3.5-flash-lite`.
`gmicloud/Ripple-65B-Preview` still has no flat pricing (null)
and is treated as unpriced. Both copies of the file were
regenerated from the live list; the filename `models-80.json`
is kept because cost.py, pyproject.toml, and this file all
reference it by that name, and the count in the name is not a
guarantee: GMI rotates models, and the file is re-checked live
before each release.

Live re-check 2026-11-10, in the v0.5.1 fix pass: the live
list still has 73 models, 73 unique, no removals, no
additions, pricing unchanged on all 73 shared models.
`gmicloud/Ripple-65B-Preview` still has no flat pricing (null)
and is treated as unpriced. Both copies of the file were
compared against the live list; no change was needed.

Live re-check 2026-11-10, in the v0.5.2 fix pass: the live
list still has 73 models, 73 unique, no removals, no
additions, pricing unchanged on all 73 shared models.
`gmicloud/Ripple-65B-Preview` still has no flat pricing (null)
and is treated as unpriced. No model was invented and no
pricing was changed; both copies were compared against the
live list and no change was needed.

A second copy lives at `src/gmi_security_mcp/models-80.json` so
the installed package can read pricing. The two copies must be
kept identical; the repo-root copy is the source of truth.

## dataset.json

Source: `~/workspace/gmi-clouder/security-benchmark-push/dataset.json`.
50 findings, 25 real and 25 false positive, 14 categories. Not run
through this server yet in Phase 1. No score is claimed on it until
it is run. Live runs since: v0.5.0 Phase A2, 48/50, accuracy 0.960;
v0.5.1 fix pass, 2026-11-10, google/gemini-3.5-flash-lite Stage 1
only, 47/50, accuracy 0.940, precision 1.000, recall 0.880,
0 unparsed, $0.0136399. Failures S10, S11, S24, all real triaged
false_positive. v0.5.2 fix pass, 2026-11-10, after the
presence-flaw prompt clause: 47/50 again, same three failures,
$0.0151149; see DECISIONS.md section 23.

## dataset-v2.json

Source: `~/workspace/gmi-clouder/security-benchmark-push/dataset-v2.json`.
56 findings, 28 real and 28 false positive. First live run in
the v0.5.1 fix pass, 2026-11-10, google/gemini-3.5-flash-lite
Stage 1 only: 53 of 56 correct, accuracy 0.946, precision
1.000, recall 0.893, 0 unparsed, $0.015404. Failures S10, S11,
S24, all real triaged false_positive, the same three that fail
on dataset.json. All 6 new v2 items (S26 to S28, F26 to F28)
pass. MockLLM floor before the live run: 57/57.

## examples/

`examples-12.json` was extracted 2026-11-10 from
`~/workspace/gmi-clouder/security-benchmark-push/index.html`,
variables `EXAMPLES` and `EXAMPLE_META`, verbatim. Expected
verdicts come from `live-triage-examples.md`: examples 1 to 9
real, 10 to 12 false positive. One Markdown file per example was
generated from the same data. The `check` field is set only when
the example maps cleanly onto one of the 7 known checks; otherwise
it is null, so no finding is forced into a check it is not.
