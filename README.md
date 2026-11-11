# gmi-security-mcp

<!-- mcp-name: io.github.Jayanng/gmi-security-mcp -->

A security MCP server for coding agents, backed by GMI Inference. Your agent triages semgrep findings, scans repos, checks lockfiles against OSV, and verifies findings with a runnable PoC, all inside the editor, with the cost shown before every run.

PyPI: https://pypi.org/project/gmi-security-mcp/ — MCP Registry: https://registry.modelcontextprotocol.io/v0/servers?search=gmi-security-mcp — Repo: https://github.com/Jayanng/gmi-security-mcp

## Install

Requires Python 3.13 or later and a GMI Inference API key. No GitHub token is needed for local repos.

```bash
pip install gmi-security-mcp
export GMI_API_KEY="your-gmi-key"
gmi-security-mcp --list-tools
```

That prints the 15 tool names. Run the server as a stdio MCP server with `gmi-security-mcp`, or run the 12 built-in examples with `mcp-test`, which spends under $0.02 with the default model. `pipx install gmi-security-mcp` works the same way, in an isolated venv.

## Quick start

Add the server to Claude Code with `claude mcp add gmi-security-mcp -e GMI_API_KEY="your-gmi-key" -- gmi-security-mcp`, or drop this in `.mcp.json`:

```json
{
  "mcpServers": {
    "gmi-security-mcp": {
      "command": "gmi-security-mcp",
      "env": { "GMI_API_KEY": "your-gmi-key" }
    }
  }
}
```

Config copies for Claude Code, Codex, and Cursor are in `install/`. Editor test status: Claude Code and Codex are tested for registration and tools/list only, Cursor is not tested end-to-end. See TUTORIAL.md section 2.

## Tools

| Tool | What it does |
|---|---|
| `triage_semgrep_finding` | Triage one finding. One validated verdict: real or false positive, severity, confidence, reason, fix. |
| `repo_scan` | Scan a repo with semgrep and osv-scanner, then two-stage triage of each finding. Returns a JSON report. |
| `check_osv_advisory` | Check one lockfile against OSV. No GMI call. |
| `explain_cve` | Explain a CVE, GHSA, or OSV id from its advisory, with citations. |
| `draft_private_disclosure` | Draft a private disclosure from a confirmed real finding. Drafts only, never sent. |
| `estimate_cost` | Estimate a run before it spends anything. No GMI call, no spend. |
| `verify_finding` | Prove a finding with a deterministic oracle and a runnable PoC. |
| `list_findings` | List stored findings, summaries only, no code. |
| `get_finding` | One stored finding in full: code, evidence, verdict history, verification results. |
| `update_finding` | Update a stored finding. A reason is required. |
| `mark_fp` | Mark a finding false positive, with a reason. |
| `mark_confirmed` | Mark a finding confirmed, with a reason. Only with a reproduced verification. |
| `list_rules` | List the custom semgrep rules pack: 8 rules, all enabled by default. |
| `scope_enable` | Enable a scope policy for one repo from a scope file. |
| `scope_disable` | Disable the scope policy for one repo. |

## Cost and safety

Estimate before every run. The default cap is $1.00 per tool call and cannot go above $5.00. A single finding typically costs $0.0001 to $0.001 with Gemini 3.5 Flash Lite. A model verdict alone never confirms a finding: only a deterministic oracle reproducing it does, and a generated PoC never runs on your host until you review and confirm it. Secrets are redacted before anything is sent to GMI, and the key comes from `GMI_API_KEY` only, never from a file. Drafts are never sent, opened as a PR, forked, pushed, or emailed by this server.

## Docs

- [TUTORIAL.md](TUTORIAL.md): full worked tutorial, every command with real output, plus the reference appendix with tool details, cost records, limitations, and repo structure.
- [CHANGELOG.md](CHANGELOG.md): version history, including what is new in 0.5.8.
- [DECISIONS.md](DECISIONS.md): design decisions and the audit record behind them.
- [DATA_SOURCES.md](DATA_SOURCES.md): where the model pricing comes from and when it was last re-checked live.

## Development

```bash
python3 -m venv .venv
.venv/bin/pip install -e ".[dev]"
python3 -m pytest tests/ -q
```

Unit tests need no key and no network. 317 tests pass. Live tests are separate and capped: $1.00 per full run, $5.00 total for the whole build.

## License

MIT. See LICENSE.
