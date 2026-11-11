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

## 17. Registry publish, Phase 7, 2026-11-10

Contribution guide verified live 2026-11-10 before any work:
the official quickstart at modelcontextprotocol.info/registry/
quickstart (pinned to registry docs commit 5c3de5c, 2026-11-04),
the package-types doc for PyPI, and the server schema
2025-12-11. The registry is in preview and may reset data.
Publishing needs, in order: a public package on PyPI first
(the registry stores metadata only and checks the package
exists), an `mcp-name: io.github.Jayanng/gmi-security-mcp`
marker in the package README (the PyPI ownership proof, may
sit in an HTML comment, must be followed by a boundary), and
`mcp-publisher login github` (device flow, user enters a code
at github.com/login/device) followed by `mcp-publisher publish`.

Done in this phase:
- `server.json` written from the official schema and examples:
  name `io.github.Jayanng/gmi-security-mcp`, title
  `gmi-security-mcp`, description 77 characters (limit 100),
  version 0.4.0, repository id 1452187638 from
  `gh api repos/Jayanng/gmi-security-mcp`, one PyPI package
  entry (`gmi-security-mcp` 0.4.0, stdio, runtimeHint uvx,
  required secret env var GMI_API_KEY). `mcp-publisher
  validate` (CLI 1.8.8) against the live registry: valid.
  Validate is a pre-check only; publish additionally verifies
  identity and package ownership, so a passing validate is not
  a published result.
- PyPI readiness verified by building the real package on the
  bug-bounty machine (Python 3.13.5): `python -m build`
  produced sdist and wheel 0.4.0, `twine check` passed on
  both, LICENSE is inside both artifacts, models-80.json and
  examples-12.json ship as package data, and the `mcp-name`
  marker is present in the wheel METADATA (the rendered
  README). A fresh venv install from the built wheel reports
  version 0.4.0, lists all six tools, and `__version__` is
  0.4.0. PyPI name check: `https://pypi.org/pypi/
  gmi-security-mcp/json` returns 404, the name is free.
  Registry search for the server name returns 0 servers.
- Two packaging defects found and fixed before any release:
  `__version__` was 0.3.0 while pyproject said 0.4.0
  (the installed `--version` line printed the stale value),
  now 0.4.0 everywhere; the README had no `mcp-name` marker,
  now present as an HTML comment on its own line right after
  the title. The live repo already had a LICENSE file; the
  workspace copy lacked it, which is a workspace-copy gap
  only, not a repo gap.

NOT done, recorded decision not to submit yet, with reasons:
- No PyPI publish was made. No PyPI account or API token for
  Jayanng was available to this build: the Secure Vault holds
  no pypi.org login, no PyPI credential exists in memory, and
  no token was supplied with this task. Publishing to PyPI
  under the user's name needs the user's own PyPI account and
  token (or Trusted Publishing set up in the repo), and that
  step belongs to the user, not to an agent guessing at it.
- No registry publish was made. It is blocked on the PyPI
  release above, and `mcp-publisher login github` is an
  interactive device flow the user must complete in a browser.
  A validate pass does not publish anything.
- No PR to modelcontextprotocol/servers was opened. That repo
  is the fallback, not the first target, and a listing there
  would point at a PyPI package that does not exist yet.
- No $50 is claimed. The merge bar needs a merge into a real
  third-party project; nothing here merged anywhere. This
  phase does not change that, and no GMI form was submitted.

Next steps, in order, for the user or a later run:
1. Create a PyPI account as Jayanng (if none exists) and an
   API token scoped to the `gmi-security-mcp` project, or set
   up PyPI Trusted Publishing for Jayanng/gmi-security-mcp.
2. From the pushed 0.4.0 tree, run `python -m build` and
   `twine upload dist/*`, then confirm
   https://pypi.org/project/gmi-security-mcp/ shows 0.4.0
   with the `mcp-name` line in the rendered README.
3. Run `mcp-publisher login github`, enter the device code,
   then `mcp-publisher publish` from the repo root, and
   confirm with the registry search API.
4. Record the PyPI link and the registry link in this file
   and in SPEND.md; only then is the $50 merge question
   re-opened, and only if a merge into a third-party project
   actually lands.

Minor, non-blocking: the build prints a setuptools
deprecation warning that the `license = {text = "MIT"}` form
in pyproject.toml must be replaced before 2027-02-18. The
build still succeeds and twine check passes; fix it with the
next pyproject change.

## 18. Phase A1, verification, v0.5.0, 2026-11-10

Sources: 0sec-labs/0 triage.md section 3 (per-class oracles) and
verification-result.md (VerificationResult shape), commit
a891ba1cbf95a74e29f1e9789ebf1000ebad91a3, dual MIT OR Apache-2.0,
read live 2026-11-10; Python subprocess and tempfile standard
practice (list-form commands, no shell, timeout, tempfile inside
the repo). Oracle rules adapted into original Python code, no 0
TypeScript copied. NOTICE file added listing the adapted 0 parts
with their MIT OR Apache-2.0 licence. Our code stays MIT.

Decisions:
- verify_finding tool, verify.py module, VerificationResult
  schema in validate.py. confirmed is derived, true only when
  status is reproduced, and never on a regression check.
- Output fields are the plan 4.2 fields plus four extras, each
  needed by a rule in the plan: regression_check (labels a
  false_positive verified as a regression check, not a
  confirmation), patch_passed (patch validation pass/fail),
  warning (host executor warning, and untrusted-PoC warning when
  not run), poc (the generated PoC returned for review).
- Oracles for 5 categories only: SQLi (2 of 3 signals), XSS
  (token in dialog/DOM sink), SSRF (nonce-matched collector
  request), path traversal (/etc/passwd signature), host key
  (wrong-key connection succeeds unverified, fails after fix).
  Other categories return skipped with "no oracle for this
  category". No oracle is invented.
- PoC generation uses the same SYSTEM_ROLE and --- delimiters as
  triage, via POC_PROMPT in prompts.py, and returns ONLY JSON
  {"poc", "language", "notes"}, parsed with the same
  balanced-JSON extraction. An unparsed generation is an error,
  never a pass.
- A generated PoC is untrusted code until reviewed. It is only
  run when run_poc is true. A supplied PoC also needs run_poc
  true. test_command runs a PoC file already in the repo, or the
  written PoC when it names {poc}.
- PoC runner: list-form subprocess only, no shell, 60 s timeout,
  working directory inside the repo, PoC written with tempfile
  inside the repo and removed after the run, child environment
  scrubbed of credential-shaped variables including GMI_API_KEY,
  so a PoC can never read the key from its environment.
- Executor host is the default, with a plain warning in the
  result. Executor docker refuses clearly when Docker is not
  available, never silently choosing host.
- PoC text is NOT redacted. Redacting it mangled a live
  generated PoC in testing: the assigned_secret pattern matches
  `token = "..."`, so the test token became the bare word
  [REDACTED] and the PoC would crash with NameError. Secrets are
  already redacted from the finding before the generation call,
  so the model never sees one, and PoC output is returned only
  as a sha256 hash, never in full.
- Patch validation: same PoC before and after a fix candidate
  given as {"path", "content"} for one repo file. The original
  file bytes are restored after the run. patch_passed is true
  only when the PoC reproduced before and did not reproduce
  after. verify_finding never applies a fix on its own.
- Live key method, same as v0.4.0: the registered custom.gmi-cloud
  credential as an in-memory GMI_API_KEY env surrogate, via
  dynamic_credential_entry, exactly as demo/term-server.py does
  it. Never printed, never written to a file. Live runs used the
  project venv (.venv-local, Python 3.12.3) with paramiko 5.1.0
  installed there for the host-key harness; system Python is
  3.12.3, Python 3.13.18 is at ~/.local/bin/python3.13 via uv.
  The workspace copy is not a git checkout (no .git), so no push
  was made from it; the tree is left ready for Phase A2.
- Live results, 2026-11-10: 3 of 5 oracles reproduced (XSS, path
  traversal, host key), SQLi and SSRF not_reproduced with reasons
  recorded, 0 unparsed, $0.004749 total live spend. See SPEND.md
  and live-verify-phaseA1-2026-11-10.json.
- Known gaps, recorded not hidden: the host-key PoC asserts
  host_key_mismatch rather than measuring the fingerprint against
  a decoy key, so the oracle should require a measured
  fingerprint comparison in a later cut. Generated PoCs can
  hardcode the generation temp dir in sys.path; the run uses a
  fresh temp repo, so PoCs must not depend on absolute temp
  paths. The SQLi oracle reads at most one signal from raw text
  (an SQL error signature), so a PoC that prints no JSON evidence
  can never reach 2 signals; that is by design, the evidence
  object is the path.

## 19. Phase A2, findings store, v0.5.0, 2026-11-10

Sources: 0sec-labs/0 packages/db schema (commit a891ba1,
dual MIT OR Apache-2.0), shape adapted into Python sqlite3
and SQL, no 0 TypeScript copied, see NOTICE; Python sqlite3
docs (WAL mode, foreign keys pragma, one connection per
operation, no shared global connection); plan
plan-10x-5dollar-v050-2026-11-10.md section 5.

Decisions:
- SQLite store, Python sqlite3 stdlib, no new dependency.
  New module src/gmi_security_mcp/store.py, schema in
  migrations/001_init.sql (schema v1) with a schema_version
  table, WAL mode, foreign keys on, one connection per tool
  call via a context manager, no shared global connection.
  Migration is idempotent: a fresh DB migrates to v1, a DB
  with data migrates without losing findings.
- Tables: scans, targets, findings, verdicts, pipelineEvents,
  triageMemories, cases, workItems, artifacts, plus a
  verifications table added in A2 (not in the plan list) so
  mark_confirmed can check for a reproduced verification
  result. findings also carries code (redacted before
  storage) and evidence_json, which the plan list omits but
  get_finding needs. No new dependency, no ORM.
- `check` is a reserved keyword in SQLite, so the column is
  quoted as "check" in the schema and in every SQL statement.
  Python dict keys stay "check". Found by the first store
  test run, fixed before any live run.
- Finding status values, exact: new, triaged, verified,
  confirmed, false_positive, suppressed, fixed. Moves one
  step forward at a time, except any status can move to
  false_positive or suppressed, and false_positive and
  suppressed can move back to triaged when a new scan finds
  the same code again, with the history retained. Every
  status change is a pipeline event with actor and time,
  never silent. Transition rules live in
  validate.validate_status_transition.
- Dedup key is (code_hash, check, file) on the redacted code:
  a re-scan of the same code refreshes the existing finding
  instead of creating a duplicate. Dataset-v2 S10 and F11
  share identical code and check, so the MockLLM floor stores
  55 unique findings from 56 calls, by design.
- Business impact is a JSON object on the finding: label
  Urgent/High/Moderate/Low/Not assessed, affected customers,
  services, data, rationale. update_finding changes business
  impact only, never technical severity, verification,
  review gates, or patch permissions.
- Suppression guard (isDisclosureWorthy): suppressing a
  critical/high finding with business impact Urgent/High is
  refused unless force true and a reason is given; the
  suppression is then recorded with reason and actor, and
  the finding stays visible with status suppressed, never
  deleted.
- Triage memories are scope-matched exactly by global,
  package (top-level directory of the finding file), or
  target (repo path of the finding's scan), and only when the
  check matches. They are shown as a hint with id and reason
  in get_finding; they never auto-reject. Memories are
  created only by a human mark_fp call, never by the server
  alone.
- DB location: per-user default ~/.gmi-security-mcp/
  findings.db. Never commit findings or the DB;
  .gmi-security-mcp/ and findings.db added to .gitignore.
  An explicit db_path is allowed, and the tool result always
  warns that the caller is responsible for not committing it.
  Impl functions treat db_path None as no store, so unit
  tests never touch the real default DB; the MCP tool
  wrappers resolve None to the default path.
- Five new tools, total 12: list_findings (summaries only,
  no code, limit default 20 max 100, opaque offset cursor),
  get_finding (full finding with code, evidence, verdict
  history, pipeline events, verification results, business
  impact, matching memories), update_finding (reason
  required, refuses status skips), mark_fp (reason required,
  scope default target, creates the memory), mark_confirmed
  (reason required, only with a reproduced verification).
- Wiring: triage_semgrep_finding stores its verdict and
  returns finding_id; repo_scan stores every finding and
  returns scan_id, with one finding_id per finding, and a
  dry run writes nothing; verify_finding resolves a
  finding_id from the store, stores the verification result
  and its artifact hashes, and moves a reproduced finding
  to verified; draft_private_disclosure with a finding_id
  refuses a finding not in the store with status confirmed
  or triaged with verdict real and confidence at or above
  0.8, and says why. An inline finding without a finding_id
  keeps the v0.4.0 gate (verdict real, confidence at or
  above 0.8). sent is always false.
- A2 fix to an A1 latent rule, found by the store tests:
  norm_verification_result required every assertion to pass
  on reproduced, but the SQLi oracle reproduces on 2 of 3
  signals, so a real reproduced result failed validation and
  verify_finding returned an internal error. The rule is now
  non-empty assertions with at least one passing assertion;
  a reproduced result with only failing assertions is still
  invalid, and the A1 test for that still passes.
- Live key method, same as A1: the registered
  custom.gmi-cloud credential as an in-memory GMI_API_KEY env
  surrogate, via dynamic_credential_entry, exactly as
  demo/term-server.py does it. Never printed, never written
  to a file. Live runs use the project venv (.venv-local,
  Python 3.12.3); system Python is 3.12.3, Python 3.13.18 is
  at ~/.local/bin/python3.13 via uv. The workspace copy is
  not a git checkout (no .git), so no push was made from it;
  the tree is left ready for Phase A3.
- Live results, 2026-11-10: 12 examples 8/12, 0 unparsed,
  $0.0036083 (fails spring, apachepath, struts, xz, same set as
  Phase 6); 50-finding dataset 48/50, accuracy 0.960,
  precision 1.000, recall 0.920, 0 unparsed, $0.0117724,
  exactly the v0.4.0 run 2 result, so the store did not change
  triage accuracy. Total A2 live $0.0153807, inside the $0.15
  plan bound and the $1.00 per-run cap. Store check on live
  data: 61 unique findings in the default DB (12 + 49,
  S10/F11 deduped), all triaged, 62 verdicts, 61 events.
  See SPEND.md and live-12-results-2026-11-10-phaseA2.json
  and live-dataset50-results-2026-11-10-phaseA2.json.

## 20. Phase A3, custom rules and scope, v0.5.0, 2026-11-10

- Custom semgrep rules pack in `rules/`, one YAML file per
  rule, 8 rules: ssh-missing-host-key-verification (highest
  priority), missing-auth, missing-crypto-verification,
  hardcoded-secret, ssrf-user-input-to-fetch,
  path-traversal-user-input-to-file, sqli-user-input-to-query,
  xss-user-input-to-html-sink. Each maps to one of the 7 known
  checks; the host-key rule carries the check string
  "Missing SSH host key verification", the wording the
  host-key oracle matches on. Severity in list_rules is the
  semgrep YAML severity as-is (WARNING/ERROR), not a mapped
  triage severity.
- Semgrep custom-rule practice, measured, not assumed. Sources:
  semgrep.dev docs on custom rules (patterns, pattern-either,
  pattern-not, metavariable-regex, taint mode, fixtures) and
  the semgrep rule registry. Findings from testing, all
  reproduced with semgrep 1.184.0: a plain-scalar YAML pattern
  containing `{...}` breaks YAML parsing and invalidates the
  whole config, silently returning 0 findings, so all `{...}`
  patterns use block scalars; metavariable-regex is a
  full match on the metavariable text, not a substring, so
  secret-shape regexes need `.*...*` wrapping; a rule listing
  several languages silently stops matching when any pattern
  does not parse in every listed language, so rules use
  language-neutral patterns plus pattern-regex; in taint mode
  a sink fires when tainted data reaches any part of the sink
  call, so multi-argument sinks need focus-metavariable on
  the dangerous argument; semgrep prefixes rule ids with the
  config directory basename, so the loader strips by
  suffix-match against known ids; --config takes separate
  flags per config, never a comma list, which 404s and
  silently returns 0 findings (bug caught in v0.4.0).
- Host-key rule, final version: the readyTimeout object-
  literal branch only, plus an inline connect branch and
  Python paramiko AutoAddPolicy branches. The password and
  privateKey branches were dropped: they matched app-level
  SSHConfig construction sites in command-line-parser.ts,
  false positives on the fixed branch. Exclusions:
  pattern-not-regex for hostVerifier/knownHosts/
  trustedHostKey, three pattern-not-inside blocks for
  post-literal assignment of those fields, and a
  parseArgs exclusion for CLI option definitions. Measured:
  1 hit on real vulnerable ssh-mcp-server src (line 1710,
  true positive), 0 hits on the real fixed branch src, fires
  on the vulnerable fixture and silent on the fixed fixture
  in TS and Python. Known limit: a minimal ssh2 config
  literal with no readyTimeout and no inline connect is
  missed; recorded in rules/README.md.
- Precision measured on test repos, semgrep 1.184.0,
  2026-11-10: whole pack returns exactly 1 hit across
  ssh-mcp-server src and gmi-benchmark-test, the host-key
  true positive. No rule is over the 50% false-positive bar,
  so all 8 are enabled by default. The auth rule flags a
  public route by design (it cannot tell a public route from
  an unprotected admin route); recorded as a known false
  positive, triage decides.
- New module src/gmi_security_mcp/rules.py: RULES registry,
  strip_rule_prefix, find_rules_dir (explicit path, then
  GMI_SECURITY_MCP_RULES_DIR env, then walk-up from the
  file; an explicit path or env value that does not contain
  the pack is authoritative and returns None instead of
  silently falling back), load_rules (registry checked
  against YAML, errors on a missing dir, unparseable YAML,
  or an id mismatch), list_rules.
- New module src/gmi_security_mcp/scope.py: scope file
  {"in_scope": [...], "out_of_scope": [...]}, hostnames
  case-insensitive, leading *. wildcard only, IPv4 CIDR
  supported, IPv6 CIDR refused with a clear message, exact-
  host rules allow any path and port, exclusions always win,
  empty allowlist denies all. Scope is a destination policy,
  NOT authorisation to test, NOT an OS sandbox; said so in
  the tool result and the README. A scope file alone never
  activates checks; only scope_enable does. --require-scope
  and env GMI_REQUIRE_SCOPE=1 fail closed. In v0.5.0 scope
  applies to repo_scan, verify_finding, and any tool reading
  a repo path or running a PoC, and draft_private_disclosure
  when writing a file: a repo-path and PoC boundary, not a
  live-web boundary, no live web tool yet. --allow-apply
  double gate: any tool call that writes a file needs
  --allow-apply (or env GMI_ALLOW_APPLY=1) plus the exact
  candidate in the call; portable workflow JSON cannot grant
  it, because the tools take no allow_apply parameter.
  Engagement profiles standard 5 rps and conservative 1 rps,
  full jitter; the limiter guarantees the gap between GMI
  calls is at least the profile interval, so the rate is
  never exceeded. In v0.5.0 the rate limit applies to GMI
  calls, no live web calls yet. Docker executor option
  documented, not default; when Docker is unavailable the
  PoC runner refuses clearly, never silently chooses host.
- The --allow-apply gate sits in the MCP wrappers, not the
  impls, so the A1 impl tests stay green and the tool is the
  product boundary. repo_scan with write_report and no
  --allow-apply refuses the whole call. The rate limiter
  lives in scope.py and is hooked into gmi.chat before the
  POST; a throttle failure never blocks the call.
- repo_scan change: the custom pack runs as its own --config
  value in addition to the unchanged default config set
  (p/default, p/security-audit, p/python, p/javascript,
  p/secrets). Custom findings go through the same path
  resolution, exclusion, and dedup as default findings, are
  tagged source custom-rule with the bare rule id, and are
  merged before triage. A custom finding the default run
  already reported (same rule, file, line) is dropped, so
  one finding is never triaged twice. A missing pack warns
  and the default scan continues; a custom run that errors
  reports errors, never an empty list passed off as clean.
- New tools, total 15: list_rules (no GMI call, $0),
  scope_enable (scope_file + repo_path), scope_disable
  (repo_path). Keep enable and disable separate, never one
  tool doing both. Counted in a test, not guessed.
- Tests: 42 new (18 in tests/test_rules.py, 24 in
  tests/test_scope.py), 257 total, all pass. Per-rule
  fixture tests run the real semgrep binary (1.184.0) and
  assert each rule fires on its vulnerable fixtures and is
  silent on its fixed fixtures. The repo_scan MockLLM test
  returns the host-key finding with source custom-rule and
  stores it. The scope tests cover in/out, exclusion-wins,
  empty allowlist, IPv4 CIDR, IPv6 refusal, wildcard,
  explicit-enable-only, the --require-scope gate, the
  --allow-apply double gate on all three writing tools, the
  Docker-unavailable refusal, and the rate limiter with a
  fake clock. One test-ordering bug found and fixed during
  the run: a scope test set GMI_REQUIRE_SCOPE directly on
  os.environ, which leaked into later test files; it now
  uses monkeypatch.setenv. A rules test found a real loader
  bug: find_rules_dir fell back to the checkout pack when
  an explicit rules_dir did not exist; explicit paths are
  now authoritative. A test found a real merge bug: the
  custom run reused the stub default runner in tests and
  doubled the findings; the merged list now dedups across
  runs.
- Live results, 2026-11-10: one repo_scan on
  classfang/ssh-mcp-server with the custom pack, Gemini
  google/gemini-3.5-flash-lite Stage 1 only (same model as
  Stage 2), estimate typical $0.0221956 max $0.1796956 from
  --dry-run, actual $0.005798, 14 findings triaged (13
  default + 1 custom), 0 real, 13 false_positive, 1
  no_verdict (ssh-config-parser.ts:222, both stages returned
  no valid JSON verdict). The custom rule found the known
  host-key flaw at line 1710, stored as
  fnd_758e44abf1d74cb8, but Gemini triaged it false_positive
  at confidence 0.9. The triage prompt frames real as
  untrusted input reaching a dangerous sink, and a missing-
  verification flaw is not a tainted flow. The prompt was
  not reworded and the scan was not re-run. verify_finding
  refused a confirmation run by design (stored verdict
  false_positive); the run used regression_check=true. PoC
  generation attempt 1 was unparsed ($0.000815); one retry
  of a failed generation succeeded ($0.000812). The oracle
  reproduced (assertion wrong_host_key_connection_succeeded
  passed), status reproduced, confirmed false, stored as
  verification ver_800c64d591894259. The finding stays
  triaged/false_positive by design. Total A3 live $0.007425.
  See SPEND.md and AUDIT-2026-11-10-phaseA3.md. The A3
  acceptance chain stops at triage: rule found it, triage
  missed it, oracle reproduced it. Follow-up decision needed
  on a missing-verification clause in the triage prompt,
  dataset-tested before it ships.
- /tmp on this VM is a 512M tmpfs and was wiped between
  commands during this session (all /tmp run scripts lost,
  including the A1/A2 scripts). Live-run scripts now live
  in ~/workspace/gmi-clouder/.scratch/, not /tmp.

## 21. Release v0.5.0, 2026-11-10

- Version 0.5.0 everywhere: pyproject.toml, __init__.py
  __version__, server.json (package version and top-level
  version), README, CHANGELOG.md. server.json re-validated
  with mcp-publisher validate 1.8.8 against the live
  registry: valid.
- pyproject.toml license fixed to the SPDX form
  (`license = "MIT"`). Build with `python -m build`
  (build 1.6.1) produced gmi_security_mcp-0.5.0.tar.gz and
  gmi_security_mcp-0.5.0-py3-none-any.whl; `twine check`
  passed on both. Built metadata carries
  License-Expression: MIT. No deprecation warning.
- CHANGELOG.md written, Keep a Changelog, SemVer, from
  v0.4.0. README updated: What is new in 0.5.0, Verification,
  Findings, Custom Rules, Scope, Limitations, Cost, Models,
  repo structure. TUTORIAL.md gained sections 9 to 12
  (verify a finding, list findings, run the custom rules,
  enable scope), all real commands and real output, verified
  by running each command.
- README intro fixed to the allowed cross-reference line
  only: "This server shares triage logic with an earlier,
  separately submitted product." The previous paragraph
  named the first product and linked its repo and live site;
  that is removed in v0.5.0, per the plan section 10.3 rule
  and the separation rule. No link, no product name, no
  joint branding.
- models-80.json re-checked live twice, same result: 73
  models, 73 unique, down from 80. Removed: Qwen/Qwen3-Next-
  80B-A3B-Instruct, moonshotai/Kimi-K2-Instruct-0905,
  moonshotai/Kimi-K2.6, openai/gpt-5.4, openai/gpt-5.4-mini,
  openai/gpt-5.4-nano, openai/gpt-5.4-pro. Pricing unchanged
  on all 73 shared models. Ripple still unpriced (null).
  Both copies (repo root and src/) regenerated from the live
  list and kept identical. The filename models-80.json is
  kept because cost.py, pyproject.toml, and DATA_SOURCES.md
  all reference it by that name; the count in the name is
  not a guarantee. Recorded in DATA_SOURCES.md.
- Install re-test, v0.5.0: the 0.5.0 wheel installs cleanly
  in a fresh Python 3.13 venv (the wheel requires
  >=3.13; a 3.12 venv refuses it, as designed) and lists
  15 tools. Codex 0.164.0 re-tested: `codex mcp add` with
  the installed binary, `codex mcp list` shows it,
  tools/list against the exact registered command returned
  all 15 tools, registration removed afterwards. Claude Code
  could not be re-tested: the CLI is not installed on this
  VM. Cursor not tested: desktop GUI, not on this VM.
- Registry/PyPI publish still blocked (section 17): user
  PyPI token and GitHub device-flow login needed. Recorded,
  not attempted. No post to X, no GMI form, no disclosure,
  no PR.
- /tmp on this VM is wiped between commands (all /tmp run
  scripts lost mid-session, including the A1/A2 scripts).
  Live-run and tutorial scripts now live in
  ~/workspace/gmi-clouder/.scratch/, not /tmp.

## 22. Fix pass after v0.5.0, 2026-11-10

Fixes every open item from the v0.5.0 audits and the A3
acceptance miss, then an internal audit of the changed code,
then the audit fixes. Version 0.5.1, patch: every change is
a bug fix, no new tools, no new API surface, no signature
changes. The host-key oracle now enforces the same-format
fingerprint check its contract already described; that is a
correctness fix to a documented contract, not a new contract.

- P0, A3 acceptance: the custom host-key rule found the
  ssh-mcp-server finding at line 1710, but v0.5.0 triage
  called it false_positive at 0.9 while the oracle
  reproduced it. Fixed in two parts. First, TRIAGE_PROMPT
  gains one narrow missing-verification clause: a finding is
  also real when the code shown is the complete
  configuration or setup for a security-sensitive operation
  and it omits a required verification with no equivalent
  check in the code shown. This is the deliberate exception
  to the do-not-reword rule, decided here, not a quiet edit.
  Second, repo_scan now attaches factual absence evidence
  for custom-rule findings: new `count_field_occurrences`
  in scanners.py counts the rule's `absence_fields` in the
  finding's file (hostVerifier, knownHosts, trustedHostKey
  for the host-key rule) and appends the count to the
  finding text sent to triage, labelled as checked evidence,
  not a model claim. The prompt clause alone did not flip
  the live finding (repo_scan 1: still false_positive,
  0.8); the clause plus the evidence did (repo_scan 2: real,
  0.95). The 50-line snippet cannot show whether a
  verification is set later in a 200-line function; the
  file-wide count answers exactly that.
- Live results, google/gemini-3.5-flash-lite Stage 1 only.
  Dataset-50: 47/50, accuracy 0.940, precision 1.000,
  recall 0.880, 0 unparsed, $0.0136399. Failures are S10,
  S11, S24, all real triaged false_positive; S10 and S24
  also failed in v0.5.0 Phase A2, S11 is a known
  flip-flopper. One below the 48/50 bar, recorded honestly,
  not re-run to chase a better number. Dataset-v2, first
  live score: 53/56, accuracy 0.946, precision 1.000,
  recall 0.893, 0 unparsed, $0.015404; same three failures,
  all 6 new v2 items pass. MockLLM floors first, $0.00:
  dataset-50 51/51, dataset-v2 57/57, evidence run 14
  findings with 1 real (host-key). Repo_scan on
  ssh-mcp-server: 14 findings, 1 real (host-key,
  fnd_758e44abf1d74cb8), 13 false_positive, $0.005954.
  Verify of the host-key finding with the fixture PoC:
  reproduced, confirmed true, $0.00 GMI, measured
  fingerprints b9:4d:...:d1:f7 vs 78:4a:...:13:9c. The
  finding is verified in the default store.
- P1: scope port entry `example.com:443` is now refused
  plainly ("scope entries do not include ports ... use
  'example.com' without the port"), no IPv6 mention. Other
  colon forms still get the IPv6 refusal. Host-key PoC now
  measures the mismatch: oracle_host_key requires both
  fingerprints present, different, and in the same format.
  Generated PoCs no longer get the absolute repo path in
  the generation prompt and the prompt forbids absolute and
  temporary paths; the fix-pass generated PoC had no
  absolute sys.path and no hardcoded temp dir.
- Left open from v0.4.0: `_tool_json` guard now has a unit
  test (new tests/test_mcp_test.py, 6 tests). The test also
  asserts the mcp-test default model lives in the test
  script only. The setuptools SPDX license form was already
  in v0.5.0 and the rebuild shows no deprecation warning.
  osv-scanner re-tested on this VM 2026-11-10: 2-package
  requirements file succeeded in 14.6s; the earlier POST
  timeout did not reproduce this pass. Cursor still not
  tested (desktop GUI, not on this VM). Claude Code and
  Codex not tested as agents; agent-side testing was done
  through Muse instead, see below.
- Agent-side testing, Muse: this Muse agent drove the MCP
  stdio server with a ClientSession and called all 15 tools
  (tools/list, estimate_cost, 3 triages, list/get/update
  findings, verify with the SQLi fixture PoC reproduced and
  confirmed, mark_confirmed, mark_fp, repo_scan, osv,
  explain_cve, draft disclosure sent false, list_rules,
  scope_enable/disable). 15/15 passed, $0.001867. The temp
  repo_scan found 3 real findings on a one-vulnerability
  repo: the intended SQLi plus two rule hits on the SQLi
  harness line, which is dedup by (rule_id, file, line) by
  design. Only Muse is claimed, by this method.
- Models re-checked live 2026-11-10: 73 models, 73 unique,
  no removals, no additions, pricing unchanged, Ripple
  still unpriced. Recorded in DATA_SOURCES.md.
- Internal audit of the changed code (report workspace-only,
  AUDIT-2026-11-10-post-v050.md, never pushed): semgrep
  71 hits (69 fixtures, 1 known osv.py false positive,
  1 test sentinel), trufflehog 0 verified and 0 unverified,
  osv-scanner 111 fixture vulns (all intentionally old
  versions; 113 in v0.5.0, delta is OSV data drift),
  production deps mcp 2.3.0 and PyYAML 6.0.3 with 0 vulns
  by direct OSV query. Two real issues found and fixed in
  this pass: (A1) the host-key oracle claimed same-format
  fingerprints but never checked the format, fixed with
  `_fingerprint_format` and 3 tests; (A2) explain_cve
  crashed the MCP call on an IncompleteRead from the OSV
  API, fixed by catching http.client.HTTPException, OSError,
  and ValueError in `_default_fetch` and 2 tests. The
  agent-side test is what found A2. Full unit suite after
  all fixes: 278 passed, 0 failed.
- Spend, fix pass: live GMI about $0.0494 (dataset-50 $0.0136399,
  repo_scan 1 $0.005872, repo_scan 2 $0.005954, verify PoC
  generation $0.001190, dataset-v2 $0.015404, agent-side
  runs $0.0008 estimated for the first crashed run plus
  $0.000837 and $0.001867, mcp-test 12 examples $0.003798).
  Cumulative with v0.5.0 $0.0275547: about $0.0769 of the
  $5.00 cap. No live spend in the push step. mcp-test on
  0.5.1: 8/12, the same four CVE-description failures as
  Phase 6, 0 unparsed.
- Version 0.5.1 everywhere: pyproject.toml, __init__.py
  __version__, server.json (package version and top-level
  version), README, CHANGELOG.md. server.json re-validated
  with mcp-publisher validate. Rebuilt with
  `python -m build`, `twine check` passed, fresh-venv
  install lists 15 tools.

## 23. Fix pass after v0.5.1, 2026-11-10

Version 0.5.2, patch: every change is a bug fix, no new tools.
One signature gains an optional parameter with a default
(`verify_impl` takes `docker_available=None`, auto-detect
when None), which is a bug fix to test determinism, not a
new API surface. The MCP tool surface is unchanged: 15 tools.

- A7, traversal: `count_field_occurrences` and
  `read_snippet` in scanners.py now resolve the finding
  file through `_safe_repo_path` and return None when the
  path is absolute or climbs out of the repo, including
  through a symlink. `read_snippet` gets the same guard
  because it takes the same semgrep-supplied path; fixing
  one and leaving the sibling open would fail the next
  audit round. Normal relative paths are unaffected: the
  repo_scan call sites pass semgrep-relative paths, and a
  path that cannot be read still yields None, never a
  claimed 0 or an empty snippet. Two new tests per function,
  plus the existing missing-file tests.
- Docker test: `test_verify_docker_executor_refused_when_
  unavailable` failed on the bug-bounty machine (1 failed,
  276 passed, 1 skipped there) because Docker is installed
  there, so auto-detection found the binary and tried to
  run a container, which exited 127 with no JSON evidence.
  The refusal test now forces `docker_available=False`,
  and `verify_impl` forwards it to both `run_poc` calls
  (before and after). A new test forces the auto-detect
  branches with a mocked `shutil.which`, so the suite is
  deterministic on a machine with Docker and on one
  without. The paramiko host-key test skips cleanly where
  paramiko is absent (1 skipped on bug-bounty before the
  fix); paramiko was installed into the bug-bounty venv
  so the test runs there instead of skipping.
- Presence-flaw prompt clause: TRIAGE_PROMPT gains one
  narrow clause, the second deliberate exception to the
  do-not-reword rule. A finding is also real when the code
  shown itself contains the flaw by presence: a hardcoded
  credential or live secret assigned in source, or a
  password or private key written to a log or returned to
  a client, with no masking, placeholder, test-only value,
  or safe source in the code shown. Placeholders, test-only
  values, environment-loaded values, usernames, and public
  keys stay false_positive. Tested MockLLM first ($0.00,
  dataset-50 51/51, dataset-v2 57/57, host-key real, clause
  asserted present in the prompt), then one live dataset-50
  run: 47/50, accuracy 0.940, precision 1.000, recall
  0.880, 0 unparsed, $0.0151149. The clause did not move
  Gemini 3.5 Flash Lite: the same three failures (S10,
  S11, S24, confidences 0.9, 0.9, 0.95, identical to the
  v0.5.1 run) and zero regressions (all 25 false positives
  pass, including F10, F11, F17, F24, F25). The clause is
  kept anyway: it states the correct review policy, costs
  about 60 tokens a call, and broke nothing; the
  missing-verification clause was kept on the same basis
  (it did not flip the host-key finding on its own either).
  Why the clause did not work on this model, verified by
  reconstructing the exact redacted text the model saw:
  redaction collapses S10, F10, and F11 to the same shape
  (`API_KEY = [REDACTED]`), and F11's env-loaded value is
  itself redacted away (`os.environ['API_KEY']` replaced
  wholesale by the assigned_secret pattern). The only
  signal separating real from placeholder is the finding's
  own title and explanation, which the model discounts
  against the code shown, and it fails closed on redacted
  values. For S24 the model sees `password=[REDACTED]` in
  a logger call and still returns false_positive at 0.95.
  That is model judgement on redacted input, not a wording
  gap: no further prompt tweak is planned, because a tweak
  strong enough to force these three risks flipping F10
  and F11, which share the redacted shape. No live
  repo_scan re-run was made for the prompt clause: one
  live run per fix, and the dataset run was the prompt
  fix's run.
- Models re-checked live 2026-11-10: 73 models, 73 unique,
  no removals, no additions, pricing unchanged on all 73
  shared models, Ripple (`gmicloud/Ripple-65B-Preview`)
  still the only unpriced model. List-models is not an
  inference call: $0.00.
- Audit findings A3-A6 from the post-v0.5.0 audit,
  re-checked against current code, all Info, no code fix:
  A3 test sentinel value (test_verify.py line 553,
  test-only, env reset after), A4 osv.py dynamic urllib
  (constant OSV host, advisory id regex-validated, false
  positive documented in code), A5 buggy generated PoC
  (model output, PoCs are reviewed before they run by
  design, evidence contract still in POC_PROMPT), A6 two
  rules on one line are two findings (dedup by rule id,
  file, line, by design, scanners.py line 263).
- Cursor not tested, Claude Code and Codex not tested as
  agents. Muse agent-side 15/15 stands from the v0.5.1
  fix pass; it was not re-run in this pass (no live run
  budget was allocated to it, and no tool surface changed).
  The 12-example live run was not repeated in this pass
  either, for the same reason: one live run per fix, and
  the dataset run was the prompt fix's run.
- Internal audit of the changed code (report workspace-only,
  AUDIT-2026-11-10-fixpass-052.md, never pushed): full
  suite 282 passed locally and on bug-bounty after the
  fixes, semgrep, osv-scanner, and trufflehog re-run, no
  High or Medium open, only the recorded Info items above.
- Spend, this pass: $0.0151149 of the $1.00 cap (one live
  dataset-50 run). Remaining: $0.9848851.
- Version 0.5.2 everywhere: pyproject.toml, __init__.py
  __version__, server.json (package version and top-level
  version), README, CHANGELOG.md. server.json re-validated
  with mcp-publisher validate. Rebuilt with
  `python -m build`, `twine check` passed, fresh-venv
  install lists 15 tools.

## 24. NV-1 fix, confirm flag for generated PoCs, v0.5.3, 2026-11-11

- NV-1, from the internal audit of v0.5.2: when
  `verify_finding` was called with `run_poc` true and no PoC
  supplied, the tool generated the PoC from repo-derived
  content and ran it on the host in the same call, with no
  in-tool review round-trip. The review gate existed only in
  the agent's choice to pass `run_poc` false first.
- Decision, operator-chosen 2026-11-11: use what we use
  here, so it runs on any user coding agent or workflow
  without Docker. No Docker default, no Docker dependency
  in this fix. The fix is an explicit confirm flag, in the
  tool itself.
- Flag name: `confirm_generated_poc`, default false, on
  `verify_finding` and on `verify_impl`. Behaviour:
  generated PoC plus `run_poc` true plus no confirmation
  returns status `skipped`, the PoC in the `poc` field for
  review, `poc_before.ran` false, nothing written or run.
  The caller re-calls with the reviewed PoC supplied as
  `poc` and `run_poc` true, or with `confirm_generated_poc`
  true and `run_poc` true. A caller-supplied PoC runs with
  `run_poc` true and no extra flag, because the caller
  already reviewed it. A `test_command` that runs a PoC
  file already in the repo is also caller-supplied, not
  generated, so it needs no extra flag. The gate is checked
  after PoC generation, so the generation cost is already
  spent when the result returns skipped; that cost is shown
  in `cost_usd` and `estimate_usd`, and no run cost is
  added. Status stays in the existing schema
  (`reproduced`, `not_reproduced`, `skipped`, `error`):
  no new status was invented, so `skipped` is the
  needs-review result.
- Why not Docker: this Muse VM has no Docker, the
  bug-bounty machine has Docker 29.8.2, and an MCP user on
  Claude Code, Codex, Cursor, or a plain MCP client may
  have none. A Docker-only default would refuse generated
  PoC runs for those users. The existing Docker executor
  stays as an option for users who have Docker; it is not
  the gate, and it is not required.
- Tests: 285 pass locally (282 in v0.5.2, 3 new, plus the
  generated-run and prompt-injection tests updated to pass
  `confirm_generated_poc` true). New tests cover the four
  cases: generated without confirmation skipped and not
  run, generated with confirmation reproduced, generated
  reviewed and supplied later runs with no extra flag,
  generated with confirmation that fails the oracle is
  `not_reproduced`, not confirmed.
- Internal audit of the changed code, same method as the
  v0.5.2 audit, report workspace-only,
  AUDIT-2026-11-11-nv1.md, never pushed: no
  High, Medium, or Low open. $0.00 GMI spend, no live
  model call.
- Version 0.5.3 everywhere: pyproject.toml, __init__.py
  __version__, server.json (package version and top-level
  version), README, CHANGELOG.md. server.json re-validated
  with mcp-publisher validate. Rebuilt with
  `python -m build`, `twine check` passed, fresh-venv
  install lists 15 tools.

## Open items

- Registry publish (Phase 7): `server.json` prepared and
  validated, package verified PyPI-ready, but not published.
  Blocked on a user-supplied PyPI credential and the GitHub
  device-flow login. See section 17 for the exact next steps.
- Disclosure drafting (Phase 4): build the tool from the template
  chosen here.
- Generated PoC quality: the fix-pass live verify run generated
  a PoC with a bug (it unpacked None and exited 1 before the
  fallback ran). Model output, not server code; PoCs are
  reviewed before they run, by design. No server fix in 0.5.1
  or 0.5.2. NV-1, the generated PoC running on the host in
  the same call without an in-tool review step, is fixed in
  0.5.3 with `confirm_generated_poc`, section 24.
- Dataset-50 sits at 47/50 live (S10, S11, S24 fail, all real
  triaged false_positive). S11 flips between runs. The
  presence-flaw clause (section 23) did not move Gemini 3.5
  Flash Lite on these three and broke nothing; the gap is
  model judgement on redacted values, recorded honestly,
  not a wording gap. No further prompt change is planned.
  A live repo_scan re-check of the host-key finding after
  the prompt clause was not run in this pass (one live run
  per fix); the MockLLM floor and the unchanged
  missing-verification clause are the evidence. Re-run it
  live before claiming the 0.5.2 repo_scan result, if a
  fresh live number is needed.

## 25. v0.5.4: harness module named in PoC generation, Bearer redaction, 2026-11-11

- SSRF root cause, from the v0.5.3 live agent-side test: the
  PoC generation prompt said "import local harness modules by
  name" but never gave a name. The model invented "harness",
  3/3 live SSRF generations, PoC crashed exit 1 before any
  JSON evidence. The fixture PoC ("import ssrf_harness")
  reproduced, so the oracle and harness were fine.
- Fix: verify.infer_harness_module, explicit name wins, then
  a name in the code text, then the category module only when
  a file with that stem exists in the repo (root first, then
  a bounded walk, 500 files). verify_impl puts "Harness
  module: ssrf_harness" and "Import it exactly as: import
  ssrf_harness" into the prompt, plus "Do not invent, shorten,
  or rename it". POC_PROMPT carries the same rule. New
  optional harness_module argument on verify_finding and
  verify_impl. When nothing is found, the prompt says "No
  harness module name is given" and forbids importing one.
  Same mapping for all five oracle categories.
- Bearer redaction, confirmed by a deterministic check, no
  live call: redact() returned 0 hits for "Authorization:
  Bearer <token>" before this fix. A bearer token in audited
  code would have been sent to the model. Now Bearer tokens
  of 10+ characters are replaced with [REDACTED], scheme word
  kept. Short values left alone, they are placeholders.
- Live-test follow-up, same pass: 2/2 XSS generations wrote a
  payload f-string with a lone `}`, a Python syntax error, so
  the PoC exited 1 with no evidence and the run errored. The
  harness name was right both times (xss_harness), the oracle
  and harness are proven by the fixture PoC, and the server
  correctly refused to judge a run with no evidence. Fix is
  one prompt rule in POC_PROMPT: build payload strings with
  plain concatenation, never an f-string with a literal { or }.
  Unit test pins the rule in the prompt text.
- Residuals checked, not fixed: update_finding can set
  verified without a reproduced verification, only confirmed
  is gated. That is a Phase A2 design decision: verified is
  an operator-set status, the operator is trusted, privilege
  equal to yield, no deterministic PoC proves it is a flaw.
  confirm_generated_poc accepts any truthy value, same as
  every other bool flag in the codebase. Generation cost is
  already spent when the NV-1 gate returns skipped, inherent
  to generating before reviewing. Production deps have no
  lockfile, so osv-scanner does not cover them; checked by
  direct OSV query each audit, clean.
- .gitignore gap from the v0.5.3 live test: adds live-*.json,
  live-*.md, X-THREAD-DRAFT-*.md. Goes out in the v0.5.4 push.

## 26. v0.5.5: harness functions named in PoC generation, 2026-11-11

- SSRF root cause, second half, from the Hermes 15-tool test
  (hermes-test-2026-11-11.md addendum): the v0.5.4 fix named
  the harness module but not the functions inside it. Gemini
  attempt 2 generated a PoC that imported ssrf_harness
  correctly, then called ssrf_harness.fetch(url), a function
  that does not exist, and built its own http.server
  collector instead of using the harness Collector context
  with collector.url + "?nonce=" + nonce. Attempt 3, with the
  failure detail and the exact function name fed back in the
  finding note, did the same. Both ran exit 0 and returned
  not_reproduced, "nonce was sent but the collector saw no
  request". Qwen attempt 1 never generated: HTTP 524
  Cloudflare origin timeout from the GMI inference API,
  246.1s, $0.00. The v0.5.4 Muse live test had reproduced
  SSRF first try ($0.000870), so generation was
  luck-dependent by model and run, not deterministic.
- Fix: verify.HARNESS_USAGE, one entry per oracle category,
  function names plus a minimal usage snippet, every name
  and snippet line taken from the real harness file in
  tests/fixtures/verify_harness/ and the deterministic
  fixture PoC for the category, verified by reading the
  harness source first. sqli: make_db(), vulnerable_query(
  conn, user_input). xss: render_page(query). ssrf:
  Collector() context manager with .url and .seen_paths,
  vulnerable_fetch(url), snippet is the fixture PoC shape
  with ssrf_harness.Collector() as collector and
  vulnerable_fetch(collector.url + "?nonce=" + nonce).
  path_traversal: vulnerable_read(base_dir, user_path),
  snippet is the fixture PoC path, checked character for
  character against poc_traversal.py. host_key:
  start_test_server() returning (port, host_key, stop_fn),
  connect_no_verify(port). verify.harness_usage(category)
  returns the text, "" when there is none. verify_impl
  appends it after the module line, with "use only these
  exact names, do not invent, shorten, or rename a
  function, and do not build your own collector, server,
  database, or renderer". POC_PROMPT carries the same rule
  in generic form. The invented name is named nowhere in
  any prompt: an early draft of POC_PROMPT gave
  ssrf_harness.fetch as a negative example, and the new unit
  test caught it, so the wording is generic, "a function
  name you guess is wrong". The fixed-form functions
  (safe_query, render_page_safe, safe_read, connect_strict)
  are deliberately not listed anywhere in the prompt, so
  the model has no fixed-form name to reach for. The SSRF
  evidence contract no longer says "start a temporary local
  HTTP collector", which invited a home-built collector;
  it now says use the harness Collector and vulnerable_fetch.
- Tests: 10 new, suite 292 to 302. A contract table pins the
  function names per category and checks each one exists as
  a def or class in the real harness file, so a future edit
  cannot invent a function silently. Prompt capture tests
  assert the names and snippet appear for all five
  categories, no invented or fixed-form name appears in
  either prompt, and no functions are offered when no module
  is found. MockLLM tests assert the fixture PoC for SSRF
  and for all five categories uses only the contracted
  functions, invents no fetch(), builds no own collector,
  and the SSRF one reproduces through the oracle with
  confirmation.
- Deferred, not implemented: server-side retry of PoC
  generation with the oracle failure fed back, cap 1 retry,
  only on not_reproduced or error from a generated PoC. It
  does not fit cleanly: the retry would run after the oracle
  verdict, which is after the NV-1 confirm gate has already
  returned or run the first PoC, so a retried PoC is still
  generated code needing review, and a second generation
  inside the same call would either run unreviewed code or
  return a second unreviewed PoC, plus a second spend inside
  one call with its own cap accounting. The caller can
  already retry by re-calling verify_finding with the oracle
  failure in the finding note, which is what the Hermes test
  did by hand. Recorded here as deferred, not forced.
- .gitignore gap from the Hermes test log: adds
  hermes-test-*.md and cursor-test-*.md. Goes out in the
  v0.5.5 push.
- Live re-test, first half: Muse MCP round 1 reproduced
  first try, gemini-3.5-flash-lite, $0.0007041, PoC used
  Collector and vulnerable_fetch, no invented fetch, no
  own collector (live-behaviour-test-v055-2026-11-11-
  round1.json). Hermes Qwen attempts 1-3 then all failed
  the same way, status error, exit 1, no evidence object:
  $0.00427853, $0.0014261, $0.00189469. The generation was
  not the problem: attempt 2 and 3 PoCs used the harness
  correctly, and both reproduce verbatim outside the
  server run (attempt 2 clean reconstruction rc 0, attempt
  3 exact poc string extracted from the log, rc 0, nonce
  matched). Root cause was the PoC child environment, not
  the prompt: the Hermes MCP spawn sets HTTP(S)_PROXY
  without NO_PROXY, so urllib routed the 127.0.0.1
  collector fetch through the egress proxy, which closed
  the connection (RemoteDisconnected). Reproduced the
  mechanism directly: same PoC rc 0 with NO_PROXY set,
  rc 1 with proxy set and NO_PROXY removed. Fix:
  verify._scrubbed_env merges 127.0.0.1 and localhost
  into NO_PROXY and no_proxy for the PoC child, keeping
  existing entries. 3 new unit tests, suite 302 to 305,
  including the regression: SSRF PoC reproduces through
  run_poc with proxy vars set and NO_PROXY absent.
  Hermes re-test after the fix is in the next bullet.
- Live re-test, second half, after the proxy fix: Muse
  round 2 reproduced first try in the hostile env
  (NO_PROXY removed from the server env, proxy vars
  present), gemini-3.5-flash-lite, $0.0006891, PoC the
  fixture shape with Collector and vulnerable_fetch
  (live-behaviour-test-v055-2026-11-11-round2.json).
  Hermes Qwen attempt 4, code fixed but server stale,
  still errored exit 1, $0.00242203: the gateway's MCP
  server process (PID 2656, started 15:51 UTC) predated
  the verify.py fix (15:54 UTC) and Hermes reuses it
  across one-shot sessions, so the running server still
  had the old _scrubbed_env. The stale server process
  was stopped, the gateway left running, and the next
  chat spawned a fresh server (PID 4709, 16:00 UTC).
  Hermes Qwen attempt 5 reproduced, confirmed true,
  exit 0, $0.00124139, nonce_matched_collector_request
  passed. Lesson recorded: after a server code change,
  a Hermes live test must run against a fresh MCP server
  process, not a reused gateway one.
- Live re-test done, internal re-audit done, this pass:
  Muse round 2 and Hermes Qwen attempt 5 both reproduced,
  audit clean, 0 confirmed, see AUDIT-2026-11-11-v055.md
  (workspace only). Pass total about $0.02445 of the
  $1.00 cap.
