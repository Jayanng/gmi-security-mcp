# gmi-security-mcp

A security MCP server for coding agents, backed by GMI Inference.

Your agent in Claude Code, Codex, or Cursor calls the tools while it
works in a repo. It sends one finding plus the relevant code to GMI,
gets a structured verdict back, and knows the cost before the run.
No model is pre-selected. No verdict is ever invented. An unparsed
reply is no verdict, never clean.

This is the companion to the Security Audit Tool,
https://github.com/Jayanng/gmi-benchmark, which does the same triage
in the browser. Same prompts, same JSON schema, same verdict rules,
same cost estimator, so a finding triaged here gives the same answer
as the same finding triaged there.

## What it does

- `triage_semgrep_finding`: triage one semgrep or scanner finding.
  One validated verdict, with severity, confidence, reason, fix,
  stage used, latency, tokens, and cost.
- `estimate_cost`: estimate a run with no API call and no spend.

Planned, not built yet: `repo_scan`, `check_osv_advisory`,
`explain_cve`, and `draft_private_disclosure`. See DECISIONS.md.

## Quick start

Requires Python 3.13 and a GMI Inference API key.

```bash
git clone https://github.com/Jayanng/gmi-security-mcp
cd gmi-security-mcp
python3 -m venv .venv
.venv/bin/pip install -e .
export GMI_API_KEY="your-gmi-key"
```

Check the server lists its tools, with no key needed for that step:

```bash
.venv/bin/python -m gmi_security_mcp.server --list-tools
```

Run it as a stdio MCP server:

```bash
.venv/bin/gmi-security-mcp
```

## Add it to your editor

Claude Code (`.mcp.json` in your project, or `~/.claude.json`):

```json
{
  "mcpServers": {
    "gmi-security-mcp": {
      "command": "/path/to/gmi-security-mcp/.venv/bin/gmi-security-mcp",
      "env": {
        "GMI_API_KEY": "your-gmi-key"
      }
    }
  }
}
```

Codex (`~/.codex/config.toml`):

```toml
[mcp_servers.gmi-security-mcp]
command = "/path/to/gmi-security-mcp/.venv/bin/gmi-security-mcp"
env = { GMI_API_KEY = "your-gmi-key" }
```

Cursor (`.cursor/mcp.json` in your project):

```json
{
  "mcpServers": {
    "gmi-security-mcp": {
      "command": "/path/to/gmi-security-mcp/.venv/bin/gmi-security-mcp",
      "env": {
        "GMI_API_KEY": "your-gmi-key"
      }
    }
  }
}
```

Editor configs are shown as written, not yet tested end to end.
That test is part of a later phase, and the result will be recorded
here when it is done. Do not assume a client works until it is tested.

## Tools

### triage_semgrep_finding

Input:

- `finding`: string, required, the semgrep or scanner finding text
- `code`: string, required, the code around the finding, max 40,000 characters
- `file`: string, optional, relative path in the repo
- `line`: integer, optional, 1 or above
- `check`: string, optional, one of the 7 known checks
- `stage1_model`: string, required, no default
- `stage2_model`: string, optional, required when `two_stage` is true
- `two_stage`: boolean, default false
- `threshold`: number, default 0.8, 0 to 1
- `max_tokens`: integer, default 2500, one of 800, 1200, 2500
- `spend_cap_usd`: number, default 1.00, at most 5.00

Output: one validated finding object, plus `stage_used`,
`escalated`, `escalation_failed`, `usage`, `cost_usd`,
`estimate_usd`, `unparsed`, `error`. When the reply is unparsed,
`verdict` is null, `unparsed` is true, and the result says plainly
that the finding is not clean.

Two-stage rules: Stage 2 runs only when `two_stage` is true and
Stage 1 confidence is below the threshold, or Stage 1 is unparsed,
or Stage 1 errored. When Stage 2 fails, the Stage 1 verdict is kept
and flagged as `escalation_failed`, not presented as two-stage
verified.

### estimate_cost

Input: `model`, `text_length_chars`, `max_tokens` (default 2500),
`n_findings` (default 1). Output: `typical_usd`, `max_usd`,
`prompt_tokens_estimate`, and the per-token pricing used. A model
with no flat per-token pricing returns `priced: false` and null
costs. No API call is made.

## Known checks

SQL injection, Cross-site scripting (XSS), Authentication and
session flaws, Hardcoded secrets, Weak cryptography, Server-side
request forgery (SSRF), Path traversal. A check outside this list is
sanitised to letters, numbers, space, hyphen, and parentheses only.

## Models

81 unique models, priced in `models-82.json`. No model is
pre-selected. Every tool that needs a model refuses until the caller
names one. Reasoning-heavy models (DeepSeek, thinking, R1,
reasoning) can spend their whole completion budget thinking and
return no JSON, so they are a poor pick for large inputs. That
warning is recorded in the code, not hidden.

## How it works

POST `https://api.gmi-serving.com/v1/chat/completions`, temperature
0, system role plus a user message that wraps the audited code in
`---` delimiters and labels it as untrusted data. Timeout 120
seconds, one retry on timeout only, with a 300 second timeout. A
POST is never retried for a lost response, because a POST that
reached the API is billed even if the response is lost.

Prompt tokens are estimated at about 4 characters per token plus
150 for the prompt. Typical completion is 250 tokens, maximum is
`max_tokens`. Pricing comes from `models-82.json`, read at runtime,
never hard-coded in code.

## Cost

Real costs from live testing of the same prompts in the audit tool:

- A single finding, typical: $0.0001 to $0.001.
- Gemini 3.5 Flash Lite on a full file, 4,615 prompt tokens,
  5 completion tokens: $0.001397.
- The 12 examples in `examples/` through this server with Gemini
  3.5 Flash Lite: under $0.02. See the test log for the actual run.

Every tool response includes the estimate made before the call and
the actual cost from API usage, so the agent can show what a run
will cost and what it did cost. The default spend cap is $1.00 per
tool call. It cannot be raised above $5.00.

## Privacy and security

- The GMI key comes from the `GMI_API_KEY` environment variable
  only. Never from a file, never in a log, never in a tool result,
  never sent anywhere except directly to
  `https://api.gmi-serving.com/v1`.
- Only the finding and the redacted code snippet are sent to GMI.
  No file paths outside the repo, no user name, no repo URL, no
  GitHub token.
- Secrets are redacted before any API call. A snippet containing a
  value shaped like a key, token, or password has it replaced with
  `[REDACTED]`, and the result notes that.
- The server is local only. No network listener, no port, no
  database, no background daemon. It starts when the client starts
  it and exits when the client closes stdio.
- Logs carry tool name, model, tokens, cost, latency, verdict
  counts, and errors only. No key, no secret, no full code snippet.

## Limitations

- Unparsed is unparsed, not clean. A timeout is the same.
- The model can be wrong. A verdict is a triage opinion on the code
  shown, not proof. A finding marked false positive on a short
  snippet can still be real in the full repo.
- Reasoning-heavy models can return no JSON after spending their
  full completion budget. The cost of that spend is still billed.
- Prices change. `models-82.json` is re-checked live before a
  release, and the server refuses unpriced models rather than
  inventing a price.
- Editor coverage is untested in this phase. See the quick start
  note above.

## Examples

12 real examples in `examples/examples-12.json`, with expected
verdicts: 9 real, 3 false positive. Log4Shell CVE-2021-44228,
FAB Azure JWT CVE-2026-59243, Spring4Shell CVE-2022-22965,
MOVEit CVE-2023-34362, Apache CVE-2021-41773, Struts
CVE-2017-5638, PAN-OS CVE-2024-3400, XZ CVE-2024-3094, Pickle
CWE-502, plus 3 false positives from the 50-finding dataset.

Run them through the live server with:

```bash
python3 scripts/run-12-examples.py
```

That script needs `GMI_API_KEY` set and spends under $0.02 with
Gemini 3.5 Flash Lite. Unit tests need no key and no network:

```bash
python3 -m pytest tests/ -q
```

## Repo structure

```text
gmi-security-mcp/
  README.md
  DECISIONS.md
  DATA_SOURCES.md
  pyproject.toml
  src/gmi_security_mcp/
    server.py      stdio MCP server, the two tools
    gmi.py         GMI client, timeout, retry, cost from usage
    prompts.py     TRIAGE_PROMPT, REPO_PROMPT, SYSTEM_ROLE, verbatim
    validate.py    balanced JSON extraction, verdict validation
    cost.py        pricing from models-82.json, estimates, cap check
    redact.py      secret redaction before any API call
  tests/
    test_validate.py
    test_cost_redact.py
    test_server_logic.py
  scripts/
    run-12-examples.py   live test, 12 examples, real GMI calls
  models-82.json   pricing, 82 entries, 81 unique ids
  dataset.json     50 findings, 25 real, 25 false positive
  dataset-v2.json  56 findings, not run yet, no score claimed on it
  examples/        the 12 examples, one file each, plus examples-12.json
```

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
python3 -m pytest tests/ -q
```

## License

MIT. See LICENSE.
