# Data sources

Copied 2026-11-10 from the Security Audit Tool build, with the
source and date noted for each file. Nothing here is invented.

## models-82.json

Source: `~/workspace/gmi-clouder/security-benchmark-push/models-82.json`,
the live GMI model list fetched 2026-11-08. 82 entries, 81 unique
ids. The duplicate is `inclusionAI/Ling-3.0-flash-fin`, listed once
free ($0) and once paid; the paid entry is kept so estimates are
never $0 for a billed model. `gmicloud/Ripple-65B-Preview` has no
flat pricing (null) and is treated as unpriced.

Live re-check 2026-11-10: the live list-models call returned 80
models. `google/gemini-3.5-flash-lite` is still present with the
same pricing (prompt $0.000000300, completion $0.000002500 per
token). Pricing must be re-checked live again before release.

A second copy lives at `src/gmi_security_mcp/models-82.json` so
the installed package can read pricing. The two copies must be
kept identical; the repo-root copy is the source of truth.

## dataset.json

Source: `~/workspace/gmi-clouder/security-benchmark-push/dataset.json`.
50 findings, 25 real and 25 false positive, 14 categories. Not run
through this server yet in Phase 1. No score is claimed on it until
it is run.

## dataset-v2.json

Source: `~/workspace/gmi-clouder/security-benchmark-push/dataset-v2.json`.
56 findings, 28 real and 28 false positive. Not run yet. No score
is claimed on it until it is run.

## examples/

`examples-12.json` was extracted 2026-11-10 from
`~/workspace/gmi-clouder/security-benchmark-push/index.html`,
variables `EXAMPLES` and `EXAMPLE_META`, verbatim. Expected
verdicts come from `live-triage-examples.md`: examples 1 to 9
real, 10 to 12 false positive. One Markdown file per example was
generated from the same data. The `check` field is set only when
the example maps cleanly onto one of the 7 known checks; otherwise
it is null, so no finding is forced into a check it is not.
