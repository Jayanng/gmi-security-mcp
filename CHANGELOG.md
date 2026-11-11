# Changelog

All notable changes to gmi-security-mcp are documented here.
The format is based on Keep a Changelog, and the project
adheres to Semantic Versioning. Entries from 0.4.0 onward are
recorded here; earlier history is in the README changelog
section.

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

- Dataset-50 live: 47/50, accuracy 0.940, precision 1.000,
  recall 0.880, 0 unparsed, $0.0151149. Failures are the
  same three as v0.5.1: S10, S11, S24, all real triaged
  false_positive. The presence clause did not move Gemini
  3.5 Flash Lite on these three, and broke nothing: all 25
  false positives still pass, including F10, F11, F17, F24,
  and F25. Recorded honestly in DECISIONS.md section 23:
  the remaining gap is model judgement on redacted values,
  not a prompt wording gap that a further tweak can fix
  without risking the false positives. No live repo_scan
  re-run was made for the prompt clause: one live run per
  fix, and the dataset run was the prompt fix's run.
- MockLLM floors, $0.00: dataset-50 51/51, dataset-v2
  57/57, host-key triaged real.
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

- Dataset-50 live: 47/50, accuracy 0.940, precision 1.000,
  recall 0.880, 0 unparsed, $0.0136399. Failures S10, S11,
  S24, all real triaged false_positive.
- Dataset-v2 live, first scored run: 53/56, accuracy
  0.946, precision 1.000, recall 0.893, 0 unparsed,
  $0.015404. Same three failures; all 6 new v2 items pass.
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
- `rules/README.md` with per-rule precision measured on the
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
- Phase A2: 12 examples 8/12, 50-finding dataset 48/50,
  accuracy 0.960, precision 1.000, recall 0.920, 0 unparsed,
  $0.0153807. The store did not change triage accuracy.
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
- 50-finding dataset: 48 of 50, accuracy 0.960, precision
  1.000, recall 0.920, 0 unparsed, $0.0117599.
- Total v0.4.0 live $0.0506687 of the $5.00 budget.
- 121 unit tests pass.
- Claude Code 2.1.322 and Codex 0.164.0 tested for
  registration and tools/list. Cursor not tested.

### Known issues

- Registry publish not done yet: the PyPI release is a
  precondition and no PyPI credential was available to this
  build. See DECISIONS.md section 17.
