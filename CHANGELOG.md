# Changelog

All notable changes to gmi-security-mcp are documented here.
The format is based on Keep a Changelog, and the project
adheres to Semantic Versioning. Entries from 0.4.0 onward are
recorded here; earlier history is in the README changelog
section.

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

- Live triage misses missing-verification flaws: the
  ssh-mcp-server host-key finding triaged false_positive at
  confidence 0.9 in the v0.5.0 live run, while the host-key
  oracle reproduced it under a regression check. The triage
  prompt frames real as untrusted input reaching a dangerous
  sink, and a missing-verification flaw is not a tainted
  flow. A follow-up decision is needed before any prompt
  change. See DECISIONS.md section 20 and
  AUDIT-2026-11-10-phaseA3.md finding 1.
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
