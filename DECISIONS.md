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

## Open items

- Registry publish (Phase 7): `server.json` prepared and
  validated, package verified PyPI-ready, but not published.
  Blocked on a user-supplied PyPI credential and the GitHub
  device-flow login. See section 17 for the exact next steps.
- Disclosure drafting (Phase 4): build the tool from the template
  chosen here.
- Phase A3 triage miss (Medium): the triage prompt frames real
  as a tainted flow, so missing-verification flaws such as the
  ssh-mcp-server host-key finding triage false_positive while
  the oracle reproduces them. Follow-up decision needed on a
  missing-verification clause in the triage prompt, tested
  against the 50-finding dataset before it ships. The prompt
  carries a do-not-reword instruction, so this needs a
  deliberate decision, not a quiet edit. See section 20 and
  AUDIT-2026-11-10-phaseA3.md finding 1.
- Phase A3 scope nit (Low): a scope file entry with a port
  (example.com:443) is refused with an IPv6 message. Misleading
  text, fail-closed. See AUDIT-2026-11-10-phaseA3.md finding 2.
