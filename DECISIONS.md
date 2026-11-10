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

## Open items

- Registry publish (Phase 7): needs a PyPI release first.
- Semgrep default (Phase 2): measure the chosen set on real repos.
- Disclosure drafting (Phase 4): build the tool from the template
  chosen here.
