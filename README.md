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
- `repo_scan`: scan a repo with semgrep and osv-scanner, then
  two-stage triage of each finding. Returns a JSON report with
  totals, per-finding verdicts, skipped findings with reasons,
  the OSV section, and estimate versus actual cost. A dry run runs
  the scanners and estimates the cost with no GMI calls.
- `check_osv_advisory`: check one lockfile against OSV with the
  local osv-scanner. Returns advisories as facts: id, package,
  installed version, fixed version, severity, summary, and link.
  No GMI call is made.
- `explain_cve`: explain a CVE, GHSA, or OSV id from its OSV
  advisory, with citations. When no advisory with that exact id
  exists, returns found false and invents nothing. When a model
  is named, GMI writes one plain-language paragraph from the
  retrieved advisory only.
- `estimate_cost`: estimate a run with no API call and no spend.

Planned, not built yet: `draft_private_disclosure`. See DECISIONS.md.

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
verified. A single-stage unparsed answer gets one retry with a
shorter prompt, for non-reasoning models only. Reasoning-heavy
models (DeepSeek, thinking, R1, reasoning) get no retry, and a
warning is returned when one faces an input over about 3,000
prompt tokens.

### repo_scan

Input:

- `repo_path`: string, required, local directory, must exist
- `stage1_model`, `stage2_model`: strings, required, no defaults
- `threshold`: number, default 0.8, 0 to 1
- `max_tokens`: integer, default 2500, one of 800, 1200, 2500
- `spend_cap_usd`: number, default 1.00, at most 5.00
- `semgrep_config`: string, default
  `p/default,p/security-audit,p/python,p/javascript,p/secrets`
- `include_tests`: boolean, default false
- `max_files`: integer, default 10
- `max_file_kb`: integer, default 40
- `max_total_kb`: integer, default 200
- `dry_run`: boolean, default false, scanners run, no GMI calls
- `write_report`: string, optional, path for a Markdown report,
  only if the user asked

Output: a report object with `repo_path`, `files_scanned`,
`findings_total`, `findings_real`, `findings_false_positive`,
`findings_no_verdict`, `findings` (one validated object per
finding, with file, line, rule id, check, verdict, severity,
confidence, reason, fix, stage, cost), `skipped` (findings left
out, with reasons), `osv` (lockfile results, separate section),
`total_cost_usd`, `estimate_usd`, `max_estimate_usd`,
`stopped_early`, and `errors`. When the remaining budget cannot
cover the next finding, triage stops early and the report says so
plainly. Findings in files over `max_file_kb` are skipped unless
the caller raises the cap.

Semgrep runs with one `--config` flag per config. A single flag
with a comma-separated list is not valid semgrep input: semgrep
treats the whole string as one config name, fails to download it,
and returns zero findings. Measured 2026-11-10 on gmi-benchmark,
ssh-mcp-server, and axios: the full default set returned exactly
the same findings as `p/default` alone, so the extra configs add
coverage in principle but no extra findings on those repos.

Semgrep rule ids map to the 7 known checks by table plus keyword
fallback. Unmapped rules report check `other`, never a known
check they are not.

### check_osv_advisory

Input: `lockfile_path`, required, and `ecosystem`, optional,
auto-detected from the filename when missing. Supported files:
package-lock.json, package.json, requirements.txt,
requirements.lock, Pipfile.lock, poetry.lock, go.mod, go.sum,
Cargo.lock, Gemfile.lock, composer.lock.

Output: `ecosystem`, `packages_scanned`, `packages_parsed`,
`vulnerable_packages`, `advisories` (id, CVE alias when one
exists, package, installed version, fixed version, severity,
summary, link), and `unresolved_packages` with reasons. Packages
with only a version range and no exact version are unresolved,
never given a verdict. `package.json` and `go.sum` are parsed
locally only: osv-scanner has no extractor for them. No GMI call
is made, because an advisory is a fact from OSV, not a model
opinion. A fixed version is reported only when the advisory
states one. The deepmerge advisory for CVE-2026-93753 lists a
last affected version of 4.3.1 and no fixed version, so that field
is null, not guessed.

### explain_cve

Input: `advisory_id`, required (CVE-YYYY-NNNNN,
GHSA-xxxx-xxxx-xxxx, or OSV id), `package` and `version`,
optional, `stage1_model`, optional, `max_tokens`, default 2500,
`spend_cap_usd`, default 1.00.

Output: `found`, `advisory` (id, aliases, summary, details, CVSS
score computed from the CVSS 3.1 vector when the record carries
one, severity label, fixed versions from the advisory ranges,
per-package affected info, references, publication date),
`explanation`, `explanation_source` (`gmi` or `advisory`),
`citations`, and `cost_usd`. When no advisory with the exact id
exists, `found` is false and nothing is invented. When no model
is named, the explanation is the advisory summary itself and no
GMI call is made. The CVSS score is computed from the vector with
the CVSS 3.1 formula, so Log4Shell CVE-2021-44228 reports 10.0.
Its advisory fixed versions are 2.15.0, 2.3.1, and 2.12.2. The
example text in this repo says upgrade to 2.17.1 or later, which
is the recommended version covering the whole Log4Shell family,
not the fixed version the advisory records for this CVE.

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
- `repo_scan` on Jayanng/gmi-benchmark with Gemini Stage 1 and
  Qwen 3.8 Flash Stage 2, default caps: $0.00, 0 findings triaged,
  run_benchmark.py has 0 findings. With the file cap raised to
  200 KB, 2 findings triaged, both false positive, $0.001227.
- `repo_scan` on classfang/ssh-mcp-server with the file cap raised
  to 100 KB: 13 findings triaged, all false positive, 0 unparsed,
  $0.006877. The known host-key finding is not among them: semgrep
  has no rule for missing SSH host key verification, so the scan
  cannot return it. That is a scanner gap, recorded, not a pass.
- `explain_cve` on CVE-2021-44228 with Gemini 3.5 Flash Lite:
  $0.0010385.

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
- Semgrep rules miss some flaws. The ssh-mcp-server host-key
  finding is a missing-logic flaw no semgrep rule covers, so
  repo_scan does not return it. A clean repo_scan means no
  semgrep finding triaged real, not that the repo has no flaws.
- osv-scanner needs exact versions and network access to the OSV
  API. A lockfile with only ranges, or a machine that cannot reach
  the OSV API, yields no dependency verdicts, and the report says
  so instead of implying the dependencies are clean.
- A fixed version is reported only when the advisory states one.
  Some advisories list only a last affected version.

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
Gemini 3.5 Flash Lite. Scan a repo live with:

```bash
python3 scripts/run-repo-scan.py --repo /path/to/repo --dry-run
python3 scripts/run-repo-scan.py --repo /path/to/repo
```

Check a lockfile and explain a CVE live with:

```bash
python3 scripts/run-osv-check.py --lockfile /path/package-lock.json
python3 scripts/run-osv-check.py --explain CVE-2021-44228 --model google/gemini-3.5-flash-lite
```

Unit tests need no key and no network:

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
    server.py      stdio MCP server, the five tools
    gmi.py         GMI client, timeout, retry, cost from usage
    prompts.py     TRIAGE_PROMPT, REPO_PROMPT, SYSTEM_ROLE, verbatim
    validate.py    balanced JSON extraction, verdict validation
    cost.py        pricing from models-82.json, estimates, cap check
    redact.py      secret redaction before any API call
    scanners.py    semgrep and osv-scanner runs, rule to check map
    lockfiles.py   lockfile parsing, exact versions only
    osv.py         OSV API lookup, advisory summary, scanner parsing
    cvss.py        CVSS 3.1 base score from a vector string
    report.py      repo_scan JSON and Markdown report output
  tests/
    test_validate.py
    test_cost_redact.py
    test_server_logic.py
    test_triage_retry.py
    test_cvss.py
    test_lockfiles.py
    test_osv.py
    test_scanners.py
    test_repo_scan.py
    fixtures/      small lockfiles for the parser tests
  scripts/
    run-12-examples.py   live test, 12 examples, real GMI calls
    run-repo-scan.py     live test, repo_scan, real GMI calls
    run-osv-check.py     live test, OSV tools, real GMI calls for explain
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
