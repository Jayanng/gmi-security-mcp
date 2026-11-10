# Tutorial: gmi-security-mcp

Every command below was run during the Phase 6 build on 2026-11-10,
and the output shown is the real output of that run. Nothing here
is invented. Where an output is long, the part left out is named
and the numbers shown are untouched.

You need Python 3.13 and a GMI Inference API key. The build machine
had only Python 3.12.3, so Python 3.13.18 was installed with `uv
python install 3.13` first. On a machine that already has Python
3.13, skip that step.

## 1. Install, one command, verify with `mcp-test`

```bash
pip install git+https://github.com/Jayanng/gmi-security-mcp
export GMI_API_KEY="your-gmi-key"
```

The install was tested in a fresh Python 3.13 venv, installed from
the checkout with pip, and again with pipx. Both put
`gmi-security-mcp` and `mcp-test` on PATH. Check the server lists
its tools, with no key needed for that step:

```bash
gmi-security-mcp --list-tools
```

```text
triage_semgrep_finding
repo_scan
check_osv_advisory
explain_cve
draft_private_disclosure
estimate_cost
```

Run the 12-example test:

```bash
mcp-test
```

```text
tools: triage_semgrep_finding, estimate_cost, repo_scan, check_osv_advisory, explain_cve, draft_private_disclosure
estimate for 12 examples: typical $0.014498, max $0.081998
 1 log4shell  expected real           got real           PASS $0.000349
 2 fabjwt     expected real           got real           PASS $0.000315
 3 spring     expected real           got false_positive FAIL $0.000334
 4 moveit     expected real           got real           PASS $0.000284
 5 apachepath expected real           got false_positive FAIL $0.000276
 6 struts     expected real           got false_positive FAIL $0.000248
 7 panos      expected real           got real           PASS $0.000315
 8 xz         expected real           got false_positive FAIL $0.000412
 9 pickle     expected real           got real           PASS $0.000306
10 ssrffp     expected false_positive got false_positive PASS $0.000225
11 xssfp      expected false_positive got false_positive PASS $0.000266
12 sqlifp     expected false_positive got false_positive PASS $0.000216
passed 8/12, unparsed 0, total cost $0.003546
```

`mcp-test` exits non-zero when not all 12 pass, so this run exits
1. That is the known state of the examples, not a broken install.
The four failures are the CVE-description examples (spring,
apachepath, struts, xz), all judged false positive at confidence
1.0 because the example text describes a CVE and shows no code
sink. Earlier runs on the same examples passed 9, 10, and 9 of 12,
so the count moves run to run on those four. The install is good
when the server lists all six tools and the test runs to a total
cost under $0.02.

## 2. Add the server to Claude Code

Claude Code 2.1.322 was installed for this test with `npm install
-g @anthropic-ai/claude-code`. The command below uses the absolute
path to the venv binary that was installed in step 1. After a pipx
install, the command is just `gmi-security-mcp`, and it goes in the
same place.

```bash
claude mcp add gmi-security-mcp -e GMI_API_KEY="your-gmi-key" -- /home/hatch/workspace/gmi-clouder/.scratch/phase6/fresh-venv/bin/gmi-security-mcp
```

```text
Added stdio MCP server gmi-security-mcp with command: /home/hatch/workspace/gmi-clouder/.scratch/phase6/fresh-venv/bin/gmi-security-mcp  to local config
File modified: /home/hatch/.claude.json [project: /home/hatch]
Checking MCP server health…

gmi-security-mcp: /home/hatch/workspace/gmi-clouder/.scratch/phase6/fresh-venv/bin/gmi-security-mcp  - ✔ Connected
```

The health check spawns the server and completes the MCP
handshake, which includes tools/list. Confirm it with:

```bash
claude mcp list
```

```text
gmi-security-mcp:
  Scope: Local config (private to you in this project)
  Status: ✔ Connected
  Type: stdio
  Command: /home/hatch/workspace/gmi-clouder/.scratch/phase6/fresh-venv/bin/gmi-security-mcp
  Args:
  Environment:
GMI_API_KEY=<redacted>
```

An agent-side tool call inside Claude Code was not tested in this
build, because the build machine is not logged in to Claude Code.
The test registration was removed afterwards with `claude mcp
remove gmi-security-mcp -s local`, and no key material was left in
the config.

The same server was registered in Codex 0.164.0 with `codex mcp
add gmi-security-mcp --env GMI_API_KEY="your-gmi-key" --
gmi-security-mcp`. `codex mcp list` showed it, and tools/list
against the exact registered command returned all six tools.
Codex is not logged in on the build machine either, so no
agent-side call was tested there, and the registration was removed
afterwards. Cursor was not tested: it is a desktop GUI app and was
not installed on the build machine. Its snippet is in
`install/cursor.json`, as written.

## 3. Triage one finding

This step triages the Log4Shell example, the same finding
`mcp-test` runs as example 1, and prints the raw JSON result.
`scripts/call-tool.py` calls one tool and prints its result. The
finding text is read from `examples/examples-12.json`, not typed
by hand, so the run below is exactly reproducible.

```bash
python3 - <<'EOF' > /tmp/triage-args.json
import json
ex = json.load(open('examples/examples-12.json'))['examples'][0]
args = {"finding": ex["finding"], "code": ex["finding"], "stage1_model": "google/gemini-3.5-flash-lite", "max_tokens": 2500, "spend_cap_usd": 1.00}
print(json.dumps(args))
EOF
python3 scripts/call-tool.py triage_semgrep_finding "$(cat /tmp/triage-args.json)"
```

That call returned:

```json
{
  "verdict": "real",
  "severity": "critical",
  "confidence": 1.0,
  "reason": "Untrusted username parameter is logged directly using a vulnerable version of Log4j 2, enabling remote code execution via JNDI lookups.",
  "fix": "Upgrade Log4j to version 2.17.1 or later, or set log4j2.formatMsgNoLookups=true.",
  "model": "google/gemini-3.5-flash-lite",
  "stage_used": "stage1",
  "latency_seconds": 2.51,
  "cost_usd": 0.0003489,
  "estimate_usd": 0.000715,
  "unparsed": false,
  "error": null
}
```

The full result also carries a `usage` object with the token
counts: 413 prompt tokens, 88 completion tokens, 501 total, 0
reasoning tokens. Cost $0.0003489, inside the $0.000715 estimate.

## 4. Scan a repo

The sample repo is Jayanng/gmi-benchmark, the audit tool repo,
cloned fresh for this run. semgrep 1.79.0 was installed in the
tutorial venv. The bug-bounty machine has semgrep 1.184.0. Both
are recorded because the version differs by machine.

```bash
git clone --depth 1 https://github.com/Jayanng/gmi-benchmark /tmp/gmi-benchmark-tut
```

Dry run first. No GMI calls, scanners run, cost estimated:

```bash
python3 scripts/run-repo-scan.py --repo /tmp/gmi-benchmark-tut --dry-run
```

```text
tools: triage_semgrep_finding, estimate_cost, repo_scan, check_osv_advisory, explain_cve, draft_private_disclosure
repo: /tmp/gmi-benchmark-tut
findings: total 2, triaged 0, real 0, false_positive 0, no_verdict 0
skipped: 2
  skipped index.html:7 - file is 142.8 KB, over the 40 KB per-file cap
  skipped index.html:18 - file is 142.8 KB, over the 40 KB per-file cap
cost: actual $0.000000, estimate typical $0.0, max $0.0, stopped_early=True (dry run: scanners ran, GMI cost estimated, no API calls made)
```

Both semgrep findings are in index.html, which is 142.8 KB, over
the 40 KB per-file cap, so both are skipped and nothing is
triaged. Raise the file cap to 200 KB and run it live:

```bash
python3 scripts/run-repo-scan.py --repo /tmp/gmi-benchmark-tut --max-file-kb 200
```

```text
tools: triage_semgrep_finding, estimate_cost, repo_scan, check_osv_advisory, explain_cve, draft_private_disclosure
repo: /tmp/gmi-benchmark-tut
findings: total 2, triaged 2, real 0, false_positive 2, no_verdict 0
skipped: 0
  index.html:7 other          false_positive conf 0.95 stage stage1 $0.000573
  index.html:18 other          false_positive conf 0.95 stage stage1 $0.000644
cost: actual $0.001217, estimate typical $0.0024565200000000002, max $0.01582152, stopped_early=False (None)
```

Both findings are missing-integrity flags on CDN script tags,
triaged false positive at 0.95. run_benchmark.py has 0 findings,
which matches the audit tool live test. Actual cost $0.001217 is
inside the typical estimate of $0.002457.

## 5. Check a lockfile

The sample is the axios package-lock.json, 679 packages, with
osv-scanner 2.7.0. No GMI call is made for this tool. The first
osv-scanner run on a fresh machine took about 80 seconds while it
fetched vulnerability data; later runs use its cache and take
seconds.

```bash
python3 scripts/run-osv-check.py --lockfile /path/to/axios/package-lock.json
```

```text
tools: triage_semgrep_finding, estimate_cost, repo_scan, check_osv_advisory, explain_cve, draft_private_disclosure
lockfile /home/hatch/workspace/gmi-clouder/.scratch/axios-test/package-lock.json: ecosystem npm, parsed 679 packages, scanned 679, vulnerable 2, unresolved 0, error=None
  deepmerge 4.3.1 CVE-2026-93753 fixed=None cvss=5.3: deepmerge mergeObject() allows prototype poisoning of returned objects
  minimatch 10.2.6 CVE-2026-118764 fixed=11.0.1 cvss=6.9: minimatch has potential denial of service via globparts amplification
```

Two public dependency CVEs, both already known. deepmerge has no
fixed version in its advisory, only a last affected version of
4.3.1, so the fixed field is null, not guessed. Neither package is
imported by axios lib code.

## 6. Draft a disclosure

The sample is the ssh-mcp-server host-key finding from the bug
bounty work: missing SSH host key verification, no hostVerifier,
known_hosts never consulted, version 1.11.0. The draft is produced
locally. No GMI call, nothing sent.

```bash
python3 scripts/call-tool.py draft_private_disclosure '{"finding": {"verdict": "real", "severity": "medium", "confidence": 0.9, "reason": "ssh-mcp-server never verifies the SSH server host key: no hostVerifier in buildClientConfig, known_hosts never consulted.", "fix": "Add a hostVerifier that checks the presented host key against ~/.ssh/known_hosts, or against a configured trustedHostKey fingerprint, and fail closed on mismatch.", "line": 1706, "check": "Authentication and session flaws"}, "repo": "classfang/ssh-mcp-server", "include_fix": true}'
```

The result reports `sent: false` and `written_to: null`. The draft
starts:

```text
# DRAFT, NOT SUBMITTED, DO NOT SEND WITHOUT USER APPROVAL

Target: classfang/ssh-mcp-server
Title: Authentication and session flaws: ssh-mcp-server never verifies the SSH server host key: no hostVerifier in buildClientConfig, known_hosts never consulted.
Severity: medium
Confidence: 0.90
```

And it ends with these next steps:

```text
Report privately first. GitHub Private Vulnerability Reporting needs a GitHub sign-in; use it where it is enabled for this repo.
A public issue needs your approval for that exact destination. Do not open one for a security flaw without it.
Do not open a PR with the fix yet: a public PR discloses the flaw, so disclose privately first and let the maintainer fix it.
Coordinated disclosure deadline: 90 days after the first report, unless the maintainer agrees a different timeline.
No maintainer contact was supplied. Check the repo for a SECURITY.md or a listed security contact before sending anything.
```

The draft was not sent. Sending it, opening a public issue, or
opening a PR with the fix all need approval for that exact
destination.

## 7. Cost control

Estimate before you run. This call makes no API call and spends
nothing:

```bash
python3 scripts/call-tool.py estimate_cost '{"model": "google/gemini-3.5-flash-lite", "text_length_chars": 1000, "max_tokens": 2500, "n_findings": 1}'
```

```json
{
  "model": "google/gemini-3.5-flash-lite",
  "priced": true,
  "typical_usd": 0.000745,
  "max_usd": 0.006370000000000001,
  "prompt_tokens_estimate": 400,
  "pricing": {
    "prompt": 3e-07,
    "completion": 2.5e-06
  },
  "message": null
}
```

An unpriced model refuses instead of inventing a price:

```bash
python3 scripts/call-tool.py estimate_cost '{"model": "gmicloud/Ripple-65B-Preview", "text_length_chars": 1000, "max_tokens": 2500, "n_findings": 1}'
```

```json
{
  "model": "gmicloud/Ripple-65B-Preview",
  "priced": false,
  "typical_usd": null,
  "max_usd": null,
  "prompt_tokens_estimate": 400,
  "pricing": null,
  "message": "This model has no flat per-token pricing, so its cost cannot be estimated. Pick a priced model instead."
}
```

A cap that cannot cover the run refuses before any API call. This
triage call passed `spend_cap_usd` 0.0001, and no GMI call was
made:

```json
{
  "verdict": null,
  "error": "Estimated maximum cost $0.012680 exceeds the spend cap $0.00. Refusing to run. Lower max_tokens or raise the cap.",
  "cost_usd": null,
  "estimate_usd": 0.000715,
  "max_usd": 0.01268
}
```

The default cap is $1.00 per tool call. It cannot be raised above
$5.00. Every tool response carries the estimate and the actual
cost, so you can see what a run will cost and what it did cost.

## 8. Troubleshooting

Key missing. `mcp-test` with no `GMI_API_KEY` set:

```text
ERROR: GMI_API_KEY is not set.
```

Exit code 2. Set the key in the environment and try again. The
key is never read from a file.

Model not found. An unknown model id gives the same unpriced
answer as Ripple above:

```json
{
  "model": "no-such/model-xyz",
  "priced": false,
  "typical_usd": null,
  "max_usd": null,
  "message": "This model has no flat per-token pricing, so its cost cannot be estimated. Pick a priced model instead."
}
```

semgrep not found. `repo_scan` on a machine with no semgrep on
PATH returns a report with the error named, not a crash:

```json
{
  "findings_total": 0,
  "errors": [
    "scanner binary not found: semgrep"
  ],
  "stopped_early": false
}
```

Unparsed. When a model reply has no JSON in it, the result has
`verdict: null` and `unparsed: true`, and the finding is not
clean. No run in this build hit an unparsed reply. Do not treat
an unparsed finding as safe. Re-run it, or pick a cheaper model
that parses reliably.

Timeout. A GMI call that times out is reported the same way as
unparsed: no verdict, not clean, with latency and cost recorded.
No run in this build hit a timeout. A POST is never retried for a
lost response, because a POST that reached the API is billed even
if the response is lost.

Rate limit. A 429 or other block from the provider is a hard stop
for that run. Do not retry it in a loop. Wait, then run again with
the same cap.
