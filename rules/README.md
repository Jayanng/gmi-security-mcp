# Custom semgrep rules pack

Eight rules the default semgrep packs do not cover, or cover only
as patterns without the missing-logic check. Each rule has one YAML
file in `src/gmi_security_mcp/rules/` (v0.5.8: the pack used to
live in this directory, which the wheel never shipped, so a pure
PyPI install found 0 rules; the YAML files moved into the package
and ship as package data), a vulnerable fixture and a fixed fixture in
`fixtures/` in this directory, and a test in `tests/test_rules.py` that runs the real
semgrep binary against both fixtures.

Run the whole pack with a separate `--config` flag per config, never
a comma list:

```
semgrep scan --config src/gmi_security_mcp/rules/ --json <repo>
```

A single `--config` with a comma list 404s and silently returns 0
findings. The server always passes the rules directory as its own
`--config` value, in addition to the default configs.

## How the rules are built

Standard semgrep custom-rule practice, from the semgrep docs and
the rule-writing guides in DECISIONS.md section 20:

- `patterns` is AND, `pattern-either` is OR, `pattern-not` and
  `pattern-not-regex` exclude the safe cases, `pattern-not-inside`
  excludes a match inside a surrounding safe construct.
- Taint mode (`mode: taint`) tracks user input from sources to
  sinks across statements, with sanitizers that clean the value.
  Multi-argument sinks use `focus-metavariable` so only taint
  reaching the dangerous argument counts: a parameterised query
  with tainted parameters is safe, a concatenated query is not.
- A rule that lists several languages must only use patterns that
  parse in every listed language. A pattern that does not parse in
  one listed language silently stops matching in the others too.
  That was found by testing, not by reading the docs: a Python
  keyword-argument pattern (`options={...}`) killed the whole
  crypto rule for Python until it was rewritten with
  `pattern-regex`, which is language neutral. Every rule is
  tested in every language it claims.
- A rule file that does not parse as YAML, or a pattern that does
  not parse, fails the whole config silently: semgrep returns 0
  findings with the error buried in its JSON output. The server
  treats a custom-rules run with config errors as an error, never
  as a clean scan, and `tests/test_rules.py` asserts every rule
  file parses and every run reports no errors.
- `metavariable-regex` matches the whole metavariable text, not a
  substring. Secret-shape regexes are wrapped in `.*...*`.

## Rules

| Rule | Category | Severity | Enabled by default |
|---|---|---|---|
| `custom.ssh-missing-host-key-verification` | Authentication and session flaws | WARNING | yes |
| `custom.missing-auth` | Authentication and session flaws | WARNING | yes |
| `custom.missing-crypto-verification` | Weak cryptography | ERROR | yes |
| `custom.hardcoded-secret` | Hardcoded secrets | WARNING | yes |
| `custom.ssrf-user-input-to-fetch` | Server-side request forgery (SSRF) | ERROR | yes |
| `custom.path-traversal-user-input-to-file` | Path traversal | ERROR | yes |
| `custom.sqli-user-input-to-query` | SQL injection | ERROR | yes |
| `custom.xss-user-input-to-html-sink` | Cross-site scripting (XSS) | ERROR | yes |

Category is one of the 7 known checks. The host-key rule maps to
Authentication and session flaws; the finding it returns carries
the check string "Missing SSH host key verification", which is the
wording the host-key oracle in `verify_finding` matches on.

## Hit counts, measured 2026-11-10, semgrep 1.184.0

Test repos: classfang/ssh-mcp-server at v1.11.0 (vulnerable) and
at the fix branch `fix/ssh-host-key-verification` commit a993f2d
(fixed), and the gmi-benchmark checkout in the build scratch dir.
Counts are raw rule hits, before triage. Triage still runs on
every hit: a rule hit is a candidate, not a verdict.

| Rule | ssh-mcp-server src, vulnerable | ssh-mcp-server src, fixed | gmi-benchmark | Fixtures |
|---|---|---|---|---|
| ssh-missing-host-key-verification | 1 hit, 1 true positive, 0 false positives | 0 hits | 0 hits | fires on vulnerable, silent on fixed, both TS and Python |
| missing-auth | 0 hits | 0 hits | 0 hits | fires on 2 admin routes, silent on protected routes; 1 known false positive on the public /health route, by design |
| missing-crypto-verification | 0 hits | 0 hits | 0 hits | fires on vulnerable, silent on fixed, both JS and Python |
| hardcoded-secret | 0 hits | 0 hits | 0 hits | fires on vulnerable, silent on fixed, both Python and JS; the documented AWS example key is excluded as an example by design |
| ssrf-user-input-to-fetch | 0 hits | 0 hits | 0 hits | fires on vulnerable, silent on fixed, both JS and Python |
| path-traversal-user-input-to-file | 0 hits | 0 hits | 0 hits | fires on vulnerable, silent on fixed, both Python and JS |
| sqli-user-input-to-query | 0 hits | 0 hits | 0 hits | fires on vulnerable, silent on fixed, both Python and JS |
| xss-user-input-to-html-sink | 0 hits | 0 hits | 0 hits | fires on vulnerable, silent on fixed |

No rule is over the 50 percent false-positive bar on the test
repos, so all 8 are enabled by default in `repo_scan`.

## Known limits, read before trusting a hit

- ssh-missing-host-key-verification: the rule reads the ssh2
  config object literal. It fires only when the literal carries
  `readyTimeout`, which is how the real ssh-mcp-server config is
  written, so it does not fire on app-level SSH config objects
  that only carry host, username, and a key. A minimal ssh2
  config literal with no `readyTimeout` and no inline connect
  call is missed. Verification assigned after the literal, as in
  the real fix (`sshConfig.hostVerifier = ...`), is recognised
  through the `pattern-not-inside` exclusion, as is a
  `hostVerifier` inside the literal. The inline connect form and
  the Python `AutoAddPolicy` form are covered.
- missing-auth: the rule only sees the route registration call.
  It cannot tell a public route from an unprotected admin route,
  and it cannot see auth enforced inside a named handler. Every
  hit needs triage: a public route is a false positive, a
  missing check on an admin route is real. The
  `fixtures/auth-public.js` file records the public-route false
  positive with a test.
- hardcoded-secret: a hint, not a verdict. Example keys,
  placeholders, and test values match the same shapes, so the
  rule excludes the common placeholder words and triage must
  still run. A real secret that does not match the listed shapes
  is missed.
- ssrf, path-traversal, sqli, xss: taint rules only see flow
  inside one file and only through the listed sources, sinks,
  and sanitizers. A check in another file, a custom wrapper the
  rule does not list, or an allowlist the rule does not recognise
  will be missed or flagged. A hit still needs triage and, for
  confirmation, a `verify_finding` oracle run.
- The fixtures in `fixtures/` are intentionally vulnerable code.
  Do not treat a scan of this repo as a finding on the product:
  the fixtures exist so the rules can be tested. They contain
  example-shaped secret values, not real secrets.
