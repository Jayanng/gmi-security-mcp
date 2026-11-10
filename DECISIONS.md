# Decisions

Recorded 2026-11-10, Phase 0. Updated as later phases decide the
open items. No decision here is a guess: each one names its source.

## 1. Language: Python 3.13

Python, not Node. The reuse is Python already: the benchmark runner
holds the proven chat call, the balanced JSON extraction, the exact
verdict parser, and the cost estimator. The scanners are Python and
CLI tools. The MCP Python SDK is the reference SDK for stdio
servers. Verified on the build machine 2026-11-10: Python 3.13.5.

## 2. Repo: Jayanng/gmi-security-mcp, public, MIT

Checked first on GitHub 2026-11-10: `Jayanng/gmi-security-mcp`
returned 404, so the name was free. Created public with
`gh repo create` on the bug-bounty machine. License: MIT, chosen by
the user 2026-11-10. Repo: https://github.com/Jayanng/gmi-security-mcp

## 3. MCP Python SDK: official SDK 2.3.0

Researched 2026-11-10. The official MCP Python SDK is at version
2.3.0 (2 Oct 2026), speaking protocol revision 2026-07-28 while
still serving clients on the older 2025-11-25 revision. The
high-level server class was renamed in v2: `FastMCP` is now
`MCPServer`, imported as `from mcp.server import MCPServer`, and
the old import `from mcp.server.fastmcp import FastMCP` raises
`ModuleNotFoundError`. The standalone `fastmcp` package (Prefect,
4.1.1) is a different project and is not used here.

Verified by installing `mcp==2.3.0` in a venv on the build machine
and running a two-tool prototype over stdio with the SDK client:
`tools/list` returned both tools and both calls returned correct
results. Sources: the official SDK "What's new in v2" page,
https://py.sdk.modelcontextprotocol.io/whats-new/, and a 2026
build guide, https://www.ajayk.sh/blog/build-mcp-server-python-typescript-guide/

## 4. Registry: official MCP Registry, Phase 7

Chosen best target: the official MCP Registry at
registry.modelcontextprotocol.io. It is the canonical metadata
catalogue for public MCP servers, backed by Anthropic, GitHub,
Microsoft, and PulseMCP, with about 23,700 servers listed as of
August 2026. Publishing uses the `mcp-publisher` CLI with a
`server.json` manifest, namespace `io.github.Jayanng/gmi-security-mcp`,
verified through GitHub OAuth. The registry stores metadata only,
so the package must exist first: a PyPI release is a precondition,
and the registry checks that the publisher owns both the namespace
and the package. The registry is still in preview and may reset
data, so `server.json` stays in version control as the record of
truth. Downstream directories and aggregators read from it, so one
publish reaches them. The GitHub MCP Registry is a downstream
consumer with manual curation, not a separate first target.

Not chosen: Smithery shut down its connection services on 31 Oct
2026, so it is not a publishing route any more. A PR to the
modelcontextprotocol/servers repo is a fallback, not the first
target, because the registry is the canonical route and the servers
repo is a curated list.

Not started in Phase 0 or 1. Phase 7 work: PyPI release, then
`mcp-publisher init`, `login github`, `validate`, `publish`.
Sources: https://www.stackone.com/blog/mcp-registry-how-to-get-listed/,
https://www.voxgig.uk/howto/list-a-server-in-the-mcp-registry,
https://indexagentica.com/guides/publish-an-mcp-server/

## 5. Semgrep config: start narrow, then layer security-audit

Researched 2026-11-10. Standard practice across the sources is
consistent: start with `p/default`, about 600 high-confidence rules
with low false positive rates, and layer on broader sets one at a
time. `p/security-audit` is broader and trades precision for
coverage: it catches more, but produces more findings that need
triage. `p/secrets` and language packs (`p/python`,
`p/javascript`) are added for the stack in use. Starting with
`p/security-audit` plus every language pack at once is the fastest
way to get a flood of findings and alert fatigue.

Decision for Phase 2: the default config will be
`p/default,p/security-audit,p/python,p/javascript,p/secrets`,
measured on the real test repos in Phase 2, with the false
positive rate recorded. This differs from the plan's first draft
(`p/python,p/javascript,p/security-audit`) by adding `p/default`
as the high-confidence base and `p/secrets`, because the research
says the base is what keeps the signal high. If Phase 2 shows
`p/security-audit` adding mostly noise on the test repos, the
default drops back to `p/default` plus language packs, and that
change is recorded here.

Sources: https://dev.to/rahulxsingh/semgrep-cli-tutorial-installation-and-first-scan-565,
https://www.thesecurityarchitecturesite.com/articles/semgrep-open-source,
https://provectus.com/blog/shift-left-security-scanning-with-claude-code-semgrep/

## 6. Disclosure template: GitHub Security Lab template, ssh-mcp-server draft as the worked example

Researched 2026-11-10. The best template is the GitHub Security
Lab report template, https://github.com/github/securitylab/blob/main/docs/report-template.md,
used as the structure, with the ssh-mcp-server draft
(`vuln/pending-disclosures/2026-11-07-ssh-mcp-server-host-key.md`)
as the worked example of that structure filled in for a real
finding. The template's shape: title and summary, affected
versions, location, proof, impact, suggested fix, and a disclosure
policy section that asks the maintainer to open a private GitHub
Security Advisory so the report stays private until a fix ships.

Rules that come with it, from the same sources: report privately
first, never a public issue or PR for a security flaw, because a
public PR discloses the flaw. GitHub Private Vulnerability
Reporting is the primary channel where it is enabled. Coordinated
disclosure deadline is 90 days after the first report, per the
Security Lab policy, unless the maintainer agrees a different
timeline. The draft is always a draft: `sent` is always false,
nothing is sent, forked, pushed, or emailed without the user's
approval for that exact destination.

Sources: GitHub Security Lab template above, the CERT/CC
coordinated disclosure guide as summarised at
https://github.com/codecrunchworldwide/c6-cybersecurity-crunch/blob/HEAD/curriculum/week-12-capstone-vulnerability-discovery-and-disclosure/lecture-notes/03-coordinated-disclosure-cve-ghsa-and-certcc.md,
and the ECMWF PVR procedure at
https://github.com/ecmwf/codex/blob/HEAD/Guidelines/Security-Vulnerability-Disclosure.md

## 7. Semgrep config measured, Phase 2, 2026-11-10

Measured on the build machine with semgrep 1.184.0, separate
`--config` flags, on three real repos:

- gmi-benchmark: `p/default` 2 findings, full default set 2
  findings, both `html.security.audit.missing-integrity` WARNING
  in index.html.
- ssh-mcp-server: `p/default` 15 findings, full set 15 findings
  (12 path-traversal, 3 non-literal-regexp). Two are in test files
  and repo_scan excludes them by default, leaving 13.
- axios: `p/default` 20 findings, full set 20 findings.

The full set adds nothing over `p/default` alone on these three
repos, but the default stays
`p/default,p/security-audit,p/python,p/javascript,p/secrets`,
because the research in section 5 says the wider set adds
coverage in principle, and the measured cost of the extra rules
here is zero extra findings to triage.

One real bug caught by the measurement: a single `--config` flag
with a comma-separated list is NOT valid semgrep input. Semgrep
treats the whole string as one config name, fails to download it
(HTTP 404), and returns zero findings with the error buried in
its JSON output. The server always splits the list and passes one
`--config` flag per entry, and the unit tests assert no comma
appears in a config flag.

## 8. explain_cve model is optional, Phase 3, 2026-11-10

The plan schema for explain_cve has no model field, but the
behaviour says GMI writes the explanation, and the no-model
rule says no model is pre-selected. The tool takes an optional
`stage1_model`: when one is named, GMI writes one paragraph from
the retrieved advisory only; when none is named, the explanation
is the advisory summary itself, marked as advisory text, and no
GMI call is made. The advisory data is identical either way.

## 9. Fixed versions come from the advisory, gaps recorded, Phase 3

- deepmerge CVE-2026-93753: the GHSA record lists introduced
  4.2.0 and last affected 4.3.1, with no fixed event. The tool
  returns fixed_version null for it, not a guessed 4.3.2.
- minimatch CVE-2026-118764: the GHSA record lists fixed 11.0.1.
- Log4Shell CVE-2021-44228: the OSV CVE record carries only GIT
  ranges and a CVSS vector with no numeric score. The GHSA alias
  record carries the Maven ranges with fixed 2.15.0, 2.3.1, and
  2.12.2, and the same vector. The tool fetches alias records and
  merges them, and computes CVSS 10.0 from the vector with the
  CVSS 3.1 formula. The plan acceptance says fixed 2.17.1: that
  is the recommended upgrade in our own example text, covering the
  whole Log4Shell family, not the fixed version the advisory
  records for this CVE. The tool reports the advisory faithfully
  and the gap is recorded here and in the audit note.

## 10. osv-scanner network behaviour differs by machine, Phase 3

osv-scanner works on the bug-bounty machine, where it returned
both axios advisories. On the build machine (this VM) its POST to
https://api.osv.dev/v1/querybatch times out, while GETs to the
same host work, so a local osv-scanner run fails after retries
and the tool reports the failure instead of claiming clean. The
check_osv_advisory acceptance run was therefore done on the
bug-bounty machine. Users run the server on their own machines,
where the OSV API is reachable.

## 11. Disclosure drafting, Phase 4, 2026-11-10

Template: the GitHub Security Lab report template, verified live
2026-11-10 at
https://github.com/github/securitylab/blob/main/docs/report-template.md
(summary, product, tested version, details, PoC, impact,
remediation, private Security Advisory request, credit, contact,
disclosure policy with a 90-day deadline). The ssh-mcp-server
host-key draft is the worked example of that structure filled in.
Nothing is invented: version, location, proof, and impact come
from the finding object when supplied and are marked as not
supplied when they are not. Core fields (verdict, severity,
confidence, reason, fix, check, line) pass through
validate.norm_finding, so the severity allowlist and exact-verdict
rule apply to drafts too. The draft text is redacted before it is
returned or written. `sent` is always false; no network call is
made by the tool.

## 12. Qwen 3.8 Flash is a reasoning model in practice, Phase 5, 2026-11-10

Evidence, 2026-11-10, repo_scan on classfang/ssh-mcp-server:
Stage 2 Qwen/Qwen3.8-Flash returned 3,566 reasoning tokens and
took 53 s on one small finding, costing $0.002231 for that
finding alone. Its id carries no reasoning marker, so the
regex (deepseek|thinking|R1|reasoning) did not match it. Fix:
gmi.is_reasoning_model now also matches an explicit set of
models observed returning reasoning tokens, currently only
Qwen/Qwen3.8-Flash, and the warning fires at any input size for
those models, because the slowness showed up on a small input.
Other Qwen3 instruct models show 0 reasoning tokens in the
benchmark runs and are not in the set. A model is added to the
set only with observed reasoning-token evidence, never on a
guess. As a reasoning model it also gets no single-stage unparsed
retry, the same rule as DeepSeek.

## 13. Internal audit F1-F8 applied, Phase 5, 2026-11-10

Mapped to this server, see AUDIT-2026-11-10-phase45.md
(workspace only, not in the public repo):
- F1 severity allowlist in both parsers: parse_triage and
  norm_finding both allowlist severity and exact-match the
  verdict. norm_finding now has a production use: disclosure
  drafts validate their core fields through it.
- F2 JSZip CDN: not applicable, no JavaScript, no CDN, no
  browser code in this repo.
- F3 CSP and frame headers: not applicable, no web server, no
  HTTP endpoint, stdio only.
- F4 POST retry: gmi.chat retries once on timeout only, as the
  plan requires (120 s, then 300 s). Residual risk is recorded:
  a POST that reached the API and then timed out on the response
  could be billed twice. Triage reports the cost of a timed-out
  attempt as unknown, not zero.
- F5 size caps before reading: triage code cap 40,000 chars and
  repo_scan file and snippet caps were already in place.
  read_snippet now streams only the wanted lines instead of
  loading the whole file first.
- F6 balanced JSON plus exact verdict match: validate.py, tested.
- F7 unpriced model refusal: cost.py and all tools, tested.
- F8 system role plus field validation: prompts.py SYSTEM_ROLE,
  `---` delimiters, and validate.py. Prompt-injection test added
  in tests/test_hardening.py.

## 14. Pricing file is models-80.json, Phase 6, 2026-11-10

Live re-check before the Phase 6 release: the GMI model list has
80 models, 80 unique ids. The 2026-11-08 file had 82 entries, 81
unique, with inclusionAI/Ling-3.0-flash-fin listed twice. The live
list drops Ling entirely, adds no replacement, and pricing is
unchanged on all 79 shared models. gmicloud/Ripple-65B-Preview
still has no flat pricing. The file was replaced in place and
renamed to models-80.json in both copies (repo root and
src/gmi_security_mcp/), and cost.py, pyproject.toml, README.md,
and DATA_SOURCES.md were updated to the new name. The old name
would have been wrong by two models.

## 15. Editor testing, Phase 6, 2026-11-10

Claude Code 2.1.322 and Codex 0.164.0 were tested on this
machine: registration plus tools/list, no agent-side tool call,
because the build machine is not logged in to either service.
Claude Code's add command health-checks the server and reported
connected. Codex tools/list was verified against the exact
registered command. Both test registrations were removed
afterwards, and no key material was left in either config.
Cursor was not tested: it is a desktop GUI app and was not
installed on the build machine. The README and tutorial say so
plainly. The build machine had only Python 3.12.3, so Python
3.13.18 was installed with uv before the fresh-venv install
test. The tutorial venv has semgrep 1.79.0; the bug-bounty
machine has 1.184.0. Both versions are recorded where they were
used.

## 16. Demo video is a terminal recording, Phase 6, 2026-11-10

The product is a CLI MCP server, so the demo records a live
terminal, not a web page. Chrome could not be used: the stock
Chromium on this machine refuses to start without a Hatch WebGL
domain policy file and SHA-256, and the contract format of that
file is not documented here, so the terminal was recorded
directly under Xvfb with ffmpeg x11grab instead. The lime cursor
is drawn in the terminal window and follows the real X pointer,
which is moved to each element before acting. Take 1 was
discarded: the live-run wait matched stale dry-run output, the
live run was killed mid-scan before any verdict showed, and the
cursor overlay failed. Take 2 is the delivered video: 57.84
seconds, 1920x1080, 30 fps, real repo_scan run, 2 findings both
false positive, $0.001219.

## Open items

- Registry publish (Phase 7): needs a PyPI release first.
- Disclosure drafting (Phase 4): build the tool from the template
  chosen here.
