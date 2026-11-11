# Changelog

All notable changes to gmi-security-mcp are documented here.
The format is based on Keep a Changelog, and the project
adheres to Semantic Versioning. Entries from 0.4.0 onward are
recorded in the sections below; the 0.0.1 to 0.3.0 entries at
the end were moved here from the README changelog section in
the 0.5.8 README rewrite, so no history is lost.

## [Unreleased]

### Changed

- README rewritten: 975 lines to 81, short and sharp. The
  detail moved to the reference appendix at the end of
  TUTORIAL.md, and the 0.0.1 to 0.3.0 changelog headlines
  moved to the end of this file. No facts deleted, no version
  bump, no new release for this change.

### Added

- GitHub Actions workflow `.github/workflows/publish.yml`:
  publish to PyPI with Trusted Publishing (OIDC), no API
  token, no password, no secret anywhere. Build job builds
  sdist and wheel with Python 3.13 and checks them with
  twine, then a separate publish job uploads them with
  `pypa/gh-action-pypi-publish@v1.14.2` (pinned to commit
  dc37677b2e1c63e2034f94d8a5b11f265b73ba33), environment `pypi`,
  `permissions: id-token: write`. Every action in the workflow
  is pinned to a full commit SHA, not a mutable tag, verified
  against the GitHub API 2026-11-11, after semgrep flagged the
  tags. Triggers on a published
  GitHub release and on manual workflow_dispatch. It does
  NOT publish anything by itself: the user must first create
  the pending publisher in PyPI, PyPI Project Name
  `gmi-security-mcp`, Owner `Jayanng`, Repository name
  `gmi-security-mcp`, Workflow name `publish.yml`,
  Environment name `pypi`, at
  https://pypi.org/manage/account/publishing/. No version
  bump in this change, version stays 0.5.7, the workflow
  publishes whatever version a release is cut from.

## [0.5.8] - 2026-11-11

### Fixed

- The custom semgrep rules pack ships in the wheel now. The 8 YAML
  files moved from `rules/` at the repo root into
  `src/gmi_security_mcp/rules/` and are package data in
  pyproject.toml (`rules/*.yaml`), with a MANIFEST.in entry so the
  sdist has them too. In 0.5.7 a pure `pip install gmi-security-mcp`
  found 0 rules: `list_rules` errored with "custom rules pack not
  found" and `repo_scan` ran the default semgrep configs only, with
  no missing-SSH-host-key rule. The pack is found with no explicit
  dir and no `GMI_SECURITY_MCP_RULES_DIR` set, verified from a
  fresh-venv install of the local wheel. The test fixtures stay in
  `rules/fixtures/` at the repo root; they are test-only and are
  not shipped.
- The migration SQL ships in the wheel too, for the same reason:
  `migrations/001_init.sql` moved into
  `src/gmi_security_mcp/migrations/` and is package data
  (`migrations/*.sql`). An installed copy now runs the real schema
  instead of the fallback schema in store.py. No other package
  data was missing: models-80.json and examples-12.json already
  shipped, and no other runtime file is read from the repo root.

### Tests, v0.5.8 pass

- Full unit suite: 317 passed, 0 failed, locally (109.71s) and
  on bug-bounty (36.95s). Two new tests: the packaged pack is
  found with no explicit dir and no env var, and the packaged
  migration SQL is present in the package and matches the
  fallback schema statement for statement.

## [0.5.7] - 2026-11-11


### Removed

- No scored corpus is used anywhere in this project any more.
  The two scored test files and the live scored-run script
  are removed from the repo and archived workspace-only at
  `~/workspace/gmi-clouder/.scratch/scored-corpus-archive-2026-11-11/`,
  with sha256 recorded there. `.gitignore` now lists the three
  names so they cannot be re-added by accident. No score from
  them is claimed anywhere in the repo: every scored-corpus
  claim in README, TUTORIAL, CHANGELOG, DECISIONS, and
  DATA_SOURCES is replaced with a spend-only record or a
  removal note. The git history of the earlier versions still
  holds the old scores; nothing is pretended away.
- The scored-corpus floor test in tests/test_store.py is
  removed and replaced with a deterministic store floor test on
  three small local fixtures, with dedup proven by re-triaging
  identical code and check. No score is computed, no corpus
  file is read.

### Changed

- Triage prompt history notes in prompts.py, the redaction
  note in server.py, and the rule-mapping comment in
  scanners.py no longer cite a scored corpus as their test
  evidence; the behaviour itself is unchanged. The 12 real
  Live Triage examples stay, reworded from corpus ids to
  example numbers, they are examples, not a score.

### Tests, v0.5.7 pass

- Full unit suite: 315 passed, 0 failed, locally (65.45s) and
  on bug-bounty (47.86s). Same count as v0.5.6: 1 test replaced
  with 1 test.
- Scanner-verbatim re-audit at $0, report workspace-only
  AUDIT-2026-11-11-v057.md: 135 candidates reviewed, 0
  confirmed, clean.
- Live re-test, Muse MCP stdio, gemini-3.5-flash-lite, real
  local fixtures only: 15 tools, triage SQLi real high 1.0,
  triage parameterised FP false_positive low 1.0, verify
  supplied PoC reproduced confirmed True. Pass total
  $0.0009158 of the $0.50 cap. See DECISIONS.md section 29
  and SPEND.md v0.5.7.

## [0.5.6] - 2026-11-11

### Fixed

- Redaction double count, found while closing gap 5(a):
  api_key = "Bearer <token>" counted 2 before this fix
  (bearer_token, then assigned_secret on the already
  redacted value). One secret value now counts once:
  assigned_secret skips a value already containing
  [REDACTED]. The final text was already correct; only
  the count was wrong. See DECISIONS.md section 28.
- Bare JWT redaction: redact() returned 0 hits for a JWT
  sitting bare in code, for example token = "eyJ...", because
  the assigned_secret pattern needs a key name and plain
  "token" is not one. Bearer JWTs were already redacted in
  v0.5.4. A narrow jwt_token rule now redacts a JWT: first
  segment starts eyJ, two dots, three segments, starts a
  token, at least 20 characters. Short dotted words and
  header-only fragments are left alone. It runs after
  bearer_token and assigned_secret, so a Bearer JWT and an
  api_key JWT each count once, with no double count. See
  DECISIONS.md section 27.

### Closed, not implemented

- Server-side retry of PoC generation, gap 4, deferred in
  v0.5.5: closed as wont-do, final. Running a retried PoC
  under the original confirm flag would run unreviewed
  generated code, and returning it as skipped flips a
  not_reproduced verdict to skipped and loses the run
  record, with carve-outs needed for fix_candidate,
  test_command, supplied PoCs, and error results, plus a
  second prompt length that cannot be bounded upfront
  because the first PoC has no server-side length cap. The
  manual re-call already works: a broken generated PoC
  returns not_reproduced, and the same PoC supplied after
  review reproduces, proven with a deterministic MockLLM
  PoC, $0.00 live spend. See DECISIONS.md section 27.
- Bare high-entropy literals, gap 5(a): a 40-char hex git
  SHA, a 64-char hex digest, a colon-hex fingerprint, and a
  bare base64 value are not redacted, by design. With no key
  name and no distinctive shape they cannot be told apart
  from a public hash or identifier, and PoC output hashes
  are sha256 hex that the oracles read. See DECISIONS.md
  section 27.
- update_finding setting verified without a reproduced
  verification, gap 5(b): accepted design, no change.
  verified is an operator-set intermediate status; only
  confirmed is gated, and it refuses without a reproduced
  verification. See DECISIONS.md section 27.
- confirm_generated_poc accepting truthy values, gap 5(c):
  consistent-by-design, no change. Every bool flag in the
  codebase uses plain truthiness, and the MCP transport
  enforces boolean through the tool annotations. See
  DECISIONS.md section 27.
- Generation cost already spent when the NV-1 gate returns
  skipped, gap 5(d): closed with evidence, no fix needed.
  The skipped result shows cost_usd exactly equal to the
  generation usage cost and estimate_usd above zero, with
  model and usage present, and no run cost added. See
  DECISIONS.md section 27.

### Tests, v0.5.6 fix pass

- 315 unit tests pass, 0 failed, locally. New: 10 tests, 7
  redact (bare JWT, Bearer single count, assigned JWT
  single count, short and fragment JWTs untouched, bare hex
  and base64 untouched, Bearer-assigned double count fixed
  to 1, already-redacted skip is exact not substring), 2
  verify (NV-1 skipped result shows the generation cost,
  bool flags accept truthy values), 1 store (verified is
  operator-set without a reproduced verification, confirmed
  still refused).
- $0.00 GMI spend for the gap fixes and audit: MockLLM and
  deterministic PoC only, no live model call. Live re-test
  in the release pass, Muse MCP, gemini-3.5-flash-lite:
  triage SQLi real, $0.0003325, generated SSRF PoC
  reproduced and confirmed, $0.0007213, pass total
  $0.0010538 of the $1.00 cap. See SPEND.md v0.5.6.

## [0.5.5] - 2026-11-11

### Fixed

- SSRF PoC generation root cause, second half: the v0.5.4 fix
  named the harness module but not the functions inside it,
  so a live Gemini generation invented
  ssrf_harness.fetch(url), which does not exist, and built
  its own http.server collector instead of using the harness
  Collector, and the oracle could not reproduce, 2/2 Gemini
  generations in the Hermes 15-tool test. verify_impl now
  puts the exact harness function names and a minimal usage
  snippet into the prompt, for all five oracle categories,
  taken from the real harness files, never invented:
  sqli make_db and vulnerable_query, xss render_page, ssrf
  Collector and vulnerable_fetch with collector.url +
  "?nonce=" + nonce, path traversal vulnerable_read, host
  key start_test_server and connect_no_verify. The prompt
  says use only those exact names, do not invent, shorten,
  or rename a function, and do not build your own collector,
  server, database, or renderer. The fixed-form functions
  (safe_query, render_page_safe, safe_read, connect_strict)
  are deliberately not listed. The SSRF evidence contract
  no longer tells the model to start its own collector.
  See DECISIONS.md section 26.
- PoC runner proxy root cause, found in the v0.5.5 live
  re-test: the Hermes MCP spawn sets HTTP(S)_PROXY without
  NO_PROXY, so urllib in the PoC child routed the 127.0.0.1
  collector fetch through the egress proxy, which dropped
  it, and a correct generated SSRF PoC exited 1 with no
  evidence, 3/3 Qwen attempts. The same PoC reproduced from
  a shell with NO_PROXY set, and reproduced through the
  server's own run_poc path once the fix landed.
  _scrubbed_env now merges 127.0.0.1 and localhost into
  NO_PROXY and no_proxy for the PoC child, keeping any
  existing entries. PoCs may only talk to 127.0.0.1, so
  this only exempts loopback from proxying. See
  DECISIONS.md section 26.
- .gitignore now covers hermes-test-*.md and
  cursor-test-*.md, which the v0.5.4 Hermes test log noted
  as uncovered.

### Deferred, not implemented

- Server-side retry of PoC generation with the oracle
  failure fed back, capped at 1 retry, only on
  not_reproduced or error from a generated PoC. Deferred
  because it complicates the NV-1 confirm gate: a retried
  PoC is still generated code needing review, and a second
  generation inside the same call would either run
  unreviewed code or return a second unreviewed PoC, plus
  a second spend inside one call. The caller can already
  retry by re-calling verify_finding with the oracle
  failure in the finding note. See DECISIONS.md section 26.

### Tests, v0.5.5 fix pass

- 305 unit tests pass, 0 failed, locally. New: 13 tests,
  harness function names exist in the real harness source
  for all five categories, generation prompt names the
  functions and snippet per category, SSRF snippet shows
  the Collector context, no harness functions offered when
  no module is found, MockLLM generated SSRF PoC uses the
  harness functions and reproduces, same check for all
  five categories, plus 3 proxy tests: the PoC child env
  forces 127.0.0.1 and localhost past the proxy, keeps
  existing NO_PROXY entries without duplicating, and the
  SSRF PoC reproduces through run_poc with proxy vars set
  and NO_PROXY absent.
- Live re-test, this pass, $1.00 cap: Muse round 1
  reproduced first try, gemini-3.5-flash-lite, $0.0007041.
  Hermes Qwen attempts 1 to 3 errored, exit 1, no evidence,
  $0.00427853 + $0.0014261 + $0.00189469, which exposed the
  PoC runner proxy defect, fixed in this version, 3 new
  tests, suite 302 to 305. Muse round 2 after the fix
  reproduced in the hostile env, NO_PROXY removed, proxy
  vars present, $0.0006891. Hermes Qwen attempt 4 after the
  fix still errored, $0.00242203, because the gateway's MCP
  server process predated the fix and Hermes reuses it;
  the stale server was stopped and a fresh one spawned.
  Hermes Qwen attempt 5 reproduced, confirmed true,
  $0.00124139. Tool total $0.01265594, Hermes agent turns
  about $0.01179, pass total about $0.02445 of the $1.00
  cap. Internal re-audit: clean, 0 confirmed, see
  AUDIT-2026-11-11-v055.md, workspace only.
- Follow-up to the v0.5.4 Tests line: the v0.5.4 live
  iterative test of all 15 tools and internal re-audit
  happened in the v0.5.4 pass itself, not in v0.5.5. All
  15 tools pass with no error, pass total $0.009559 of
  the $1.00 cap (rounds $0.006992 + $0.001883 +
  $0.000684), see live-behaviour-test-v054-2026-11-11.md.
  Internal re-audit clean, 126 candidates reviewed, 0
  confirmed, see AUDIT-2026-11-11-v054.md. The test also
  exposed the SSRF second-half defect fixed in this
  version, see DECISIONS.md section 26.

## [0.5.4] - 2026-11-11

### Fixed

- SSRF PoC generation root cause: the generation prompt told
  the model to import local harness modules by name but never
  gave it a name, so live generations invented "harness" and
  crashed, 3/3 in the v0.5.3 live test. verify_impl now
  infers the harness module from the repo and names it
  exactly in the prompt, for all five oracle categories
  (sqli, xss, ssrf, path traversal, host key), with an
  optional harness_module argument to override it. When no
  harness module is found, the prompt says so and forbids
  importing one. See DECISIONS.md section 25.
- Bearer token redaction: redact() returned 0 hits for
  "Authorization: Bearer <token>" before this fix. Bearer
  tokens of 10 or more characters are now replaced with
  [REDACTED]. Deterministic proof, no live call needed.
- PoC generation prompt now bans literal braces inside
  f-strings: the v0.5.4 live test showed 2/2 XSS generations
  writing a payload f-string with a lone `}`, a Python syntax
  error, so the PoC exited 1 with no evidence. Payload
  strings must use plain concatenation. See DECISIONS.md
  section 25.

### Tests, v0.5.4 fix pass

- 292 unit tests pass, 0 failed, locally. New: harness module
  inference for all five categories, generation prompt names
  ssrf_harness exactly, generation prompt says no harness
  module when none is found, generation prompt bans literal
  braces in f-strings, Bearer redaction, short Bearer
  values untouched.
- Live iterative test of all 15 tools and an internal
  re-audit to follow in this pass, $1.00 cap.

## [0.5.3] - 2026-11-11

### Fixed

- NV-1, from the internal audit of v0.5.2: `verify_finding`
  no longer runs a model-generated PoC on the host in the
  same call that generated it unless the caller confirms it.
  New flag `confirm_generated_poc` (default false). With
  `run_poc` true and no confirmation, a generated PoC is
  returned for review with status `skipped` and nothing
  runs. Re-call with the reviewed PoC supplied as `poc`, or
  with `confirm_generated_poc` true, to run it. A
  caller-supplied PoC runs with `run_poc` true and no extra
  flag. No Docker is needed: the gate works on any coding
  agent or workflow, with only the Python runtime the server
  already needs. See DECISIONS.md section 24.

### Tests, v0.5.3 fix pass

- 285 unit tests pass, 3 new: generated PoC without
  confirmation is skipped and not run, generated PoC with
  confirmation reproduces, generated PoC reviewed and
  supplied in a later call runs with no extra flag, plus a
  generated PoC with confirmation that fails the oracle is
  `not_reproduced`, not confirmed.
- Internal audit, same method as the v0.5.2 audit, report
  workspace-only, AUDIT-2026-11-11-nv1.md, never
  pushed: no High, Medium, or Low open. $0.00 GMI spend,
  no live model call.

## [0.5.2] - 2026-11-10

### Fixed

- `count_field_occurrences` and `read_snippet` now refuse
  paths that escape the repo being scanned (absolute paths,
  or `..` climbing out), returning None instead of reading
  outside the repo. The paths come from semgrep output, and
  the only effect before was a count or a snippet, but the
  read is now bounded to the repo. Closes internal audit
  finding A7 from the post-v0.5.0 audit.
- `verify_finding` now accepts `docker_available`, and the
  Docker-unavailable refusal test forces it to False instead
  of relying on auto-detection. The test failed on a machine
  with Docker installed because auto-detection found the
  binary and tried to run a container. The refusal
  behaviour is unchanged; only the test's determinism and
  the plumbing changed. Auto-detection is covered by a new
  test that forces both branches with a mocked `shutil.which`.
- Triage prompt gains one narrow presence-flaw clause: a
  finding is also real when the code shown itself contains
  the flaw by presence, a hardcoded credential or live
  secret assigned in source, or a password or private key
  written to a log or returned to a client, with no masking,
  placeholder, test-only value, or safe source in the code
  shown. Placeholders, test-only values, environment-loaded
  values, usernames, and public keys stay false_positive.
  See DECISIONS.md section 23.

### Live results, v0.5.2 fix pass

- Live run, v0.5.2 fix pass: one live run on real local
  fixtures, $0.0151149. The presence clause did not move
  Gemini 3.5 Flash Lite on redacted hardcoded-secret
  examples, and broke nothing: all false positives still
  pass. Recorded honestly in DECISIONS.md section 23:
  the remaining gap is model judgement on redacted values,
  not a prompt wording gap that a further tweak can fix
  without risking the false positives. No live repo_scan
  re-run was made for the prompt clause: one live run per
  fix, and the fixture run was the prompt fix's run.
- Deterministic fixed-response stub floors, $0.00:
  host-key triaged real.
- Models re-checked live 2026-11-10: 73 models, 73 unique,
  no removals, no additions, pricing unchanged, Ripple
  still the only unpriced model.
- 282 unit tests pass.

## [0.5.1] - 2026-11-10

### Fixed

- Triage now catches missing-verification flaws. The
  ssh-mcp-server host-key finding (line 1710, custom rule)
  triaged false_positive at 0.9 in v0.5.0 while the oracle
  reproduced it. TRIAGE_PROMPT gains one narrow clause for
  a complete configuration that omits a required
  verification, and repo_scan now attaches a file-wide count
  of the rule's absent verification fields as checked
  evidence for triage. Live repo_scan now triages the
  host-key finding real at 0.95, and verify with the fixture
  PoC reproduces it with measured fingerprints, so the
  finding is verified in the store. See DECISIONS.md
  section 22.
- Host-key oracle now enforces the same-format fingerprint
  check its contract described: both fingerprints must
  classify to the same kind (colon-hex, hex, or base64) and
  length. A colon-hex fingerprint against a base64 string
  no longer counts as a measured mismatch.
- `explain_cve` no longer crashes the MCP call when the
  OSV API returns an incomplete read. The fetch converts
  transport and parse failures to a clean found-false
  result with an error string.
- Scope entries with a port (`example.com:443`) are now
  refused plainly, without the misleading IPv6 message.
- Generated PoCs no longer receive the absolute repo path
  in the generation prompt; the prompt requires relative
  paths only.
- `_tool_json` guard now has a unit test (new
  tests/test_mcp_test.py).

### Live results, v0.5.1 fix pass

- Live run, v0.5.1 fix pass: one live run on real local
  fixtures, $0.0136399, plus a scored-corpus run, $0.015404,
  whose score was removed in v0.5.7 and is not claimed.
- Repo_scan on ssh-mcp-server: 14 findings, 1 real
  (host-key), 13 false_positive, $0.005954.
- Muse agent-side test, all 15 tools over MCP stdio:
  15/15 passed, $0.001867.
- Fix-pass live total about $0.0494; cumulative with
  v0.5.0 about $0.0769 of the $5.00 cap.
- 278 unit tests pass.

## [0.5.0] - 2026-11-10

### Added

- `verify_finding`: verify one finding with a deterministic
  oracle and a runnable PoC. A model verdict alone never sets
  confirmation. Oracles for SQL injection, XSS, SSRF, path
  traversal, and missing SSH host key verification. Other
  categories return `skipped`.
- Findings store: `list_findings`, `get_finding`,
  `update_finding`, `mark_fp`, `mark_confirmed`, backed by a
  per-user SQLite database at `~/.gmi-security-mcp/findings.db`.
  Schema in `migrations/001_init.sql`.
- Custom semgrep rules pack in `rules/`: 8 rules
  (missing SSH host key verification, missing auth, missing
  crypto verification, hardcoded secret, SSRF, path traversal,
  SQL injection, XSS), each with vulnerable and fixed
  fixtures. `repo_scan` runs the pack alongside the default
  config and tags its findings `source: custom-rule`.
- `list_rules`: list the custom rules pack, with an optional
  category filter. No GMI call.
- Scope plugin: `scope_enable` and `scope_disable`,
  `--require-scope` (or `GMI_REQUIRE_SCOPE=1`), and an
  `--allow-apply` double gate for file-writing tool calls.
  Engagement profiles standard (5 rps) and conservative
  (1 rps) with full jitter.
- `rules/README.md` with per-rule hit counts measured on the
  test repos.

### Changed

- `repo_scan` now also runs the custom rules pack. The default
  semgrep config is unchanged.
- `draft_private_disclosure` with a finding id refuses a
  finding that is not confirmed or not triaged real with
  confidence at or above 0.8.
- `verify_finding` with a fix candidate, `repo_scan` with a
  write report, and `draft_private_disclosure` with a write
  path now refuse without `--allow-apply`.
- `pyproject.toml` uses the SPDX license form (`license =
  "MIT"`) instead of the deprecated table form.
- `models-80.json` re-checked live: 73 models, 73 unique, down
  from 80. Pricing unchanged on all 73 shared models.
  `gmicloud/Ripple-65B-Preview` is still unpriced. The filename
  is kept; the count in the name is not a guarantee.
- Server version 0.5.0 in `pyproject.toml`,
  `src/gmi_security_mcp/__init__.py`, and `server.json`
  (re-validated with `mcp-publisher validate` 1.8.8).

### Fixed

- Reproduced-verification validation required every oracle
  assertion to pass; the SQLi oracle reproduces on 2 of 3
  signals, so a real reproduced result failed validation.
  The rule is now non-empty assertions with at least one
  passing assertion.
- A custom-rules directory given explicitly (or by
  environment) that does not contain the pack no longer falls
  back silently to another checkout; it reports the pack as
  not found.
- `find_rules_dir` and the merged repo_scan finding list now
  dedup custom findings the default run already reported, so
  one finding is never triaged twice.

### Known issues

- Live triage missed missing-verification flaws in v0.5.0:
  the ssh-mcp-server host-key finding triaged false_positive
  at confidence 0.9 while the host-key oracle reproduced it.
  Fixed in 0.5.1: the prompt clause plus the absence
  evidence now triage it real at 0.95, and verify confirms
  it. See DECISIONS.md section 22.
- `src/utils/ssh-config-parser.ts` line 222
  (non-literal-regexp) returned no valid JSON verdict from
  either stage in the v0.5.0 live scan. Recorded as an error,
  not clean.
- Registry publish is not done: blocked on a user PyPI
  credential and the GitHub device-flow login. See
  DECISIONS.md section 17.

### Live results, v0.5.0

- Phase A1: 5 oracle PoC generations, 3 of 5 reproduced on
  the first run, 0 unparsed, $0.004749.
- Phase A2: 12 examples 8/12, $0.0153807. The store did
  not change triage behaviour on the examples.
- Phase A3: repo_scan on classfang/ssh-mcp-server with the
  custom pack, 14 findings triaged, 0 real, 13 false
  positive, 1 no verdict, $0.005798. The custom rule found
  the host-key flaw at line 1710; triage missed it, the
  oracle reproduced it. Verify total $0.001627.
- Total v0.5.0 live $0.0275547 of the $5.00 hard stop.
  257 unit tests pass.

## [0.4.0] - 2026-11-10

### Added

- `server.json` for the official MCP Registry (name
  `io.github.Jayanng/gmi-security-mcp`, PyPI package
  `gmi-security-mcp` 0.4.0), `mcp-name` ownership marker in
  the README, `__version__` fixed to 0.4.0.
- Product README in audit-tool order, one-command pip and
  pipx install, `mcp-test` console command, `install/`
  config snippets for Claude Code, Codex, and Cursor,
  `TUTORIAL.md` with real commands and output,
  `scripts/call-tool.py` helper.
- Disclosure drafting, hardening and privacy fixes,
  redaction note to the model.
- `repo_scan` with two-stage triage, `check_osv_advisory`,
  `explain_cve`, live repo tests.

### Changed

- Pricing re-checked live at 80 models (`models-80.json`,
  replaces `models-82.json`).
- Test scripts now report a non-JSON tool result instead of
  crashing on it.

### Live results, v0.4.0

- 12 examples: Phase 6 run 8 of 12, 0 unparsed, $0.003546.
- Scored-corpus run: spend $0.0117599, score removed in
  v0.5.7 and not claimed.
- Total v0.4.0 live $0.0506687 of the $5.00 budget.
- 121 unit tests pass.
- Claude Code 2.1.322 and Codex 0.164.0 tested for
  registration and tools/list. Cursor not tested.

### Known issues

- Registry publish not done yet: the PyPI release is a
  precondition and no PyPI credential was available to this
  build. See DECISIONS.md section 17.

## [0.3.0] - 2026-11-10

### Added

- Phases 4 and 5: disclosure drafting, hardening and privacy
  fixes, redaction note to the model, 12 examples re-run at 9
  and 10 of 12.

## [0.2.0] - 2026-11-10

### Added

- Phases 2 and 3: repo_scan with two-stage triage,
  check_osv_advisory, explain_cve, live repo tests.

## [0.1.0] - 2026-11-10

### Added

- Phase 1: core server, triage_semgrep_finding,
  estimate_cost, 12 examples live at 9 of 12.

## [0.0.1] - 2026-11-10

### Added

- Phase 0: repo, SDK 2.3.0 verified, decisions recorded,
  pricing copied from the audit tool.
