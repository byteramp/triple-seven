# t7 — Triple Seven agent

Threat model, **verified fixes** and **proof** for every change. Runs on the
developer's machine and in your CI. **Your source code never leaves your
environment**: Byteramp only receives an abstract architecture model and
finding metadata (title, file:line, fix/proof results as hashes and pass/fail).

## Install

```bash
pipx install t7-agent                  # stdlib only, no third-party dependencies
export T7_TOKEN=t7_...                 # from the portal: Triple Seven → Repositories
t7 doctor
t7 scan                                # review your current branch + uncommitted work
t7 fix SEC-REQ-SHOP-004                # apply a verified fix and its regression test
```

## In your editor / AI assistant (MCP)

`t7 mcp` is a Model Context Protocol server. Your assistant can then review the
change you're working on, explain findings and apply verified fixes — before a
pull request exists. Tools: `t7_scan`, `t7_findings`, `t7_explain`,
`t7_show_fix`, `t7_apply_fix`, `t7_doctor`.

```bash
# Claude Code (local scope — token stays out of the repo)
claude mcp add triple-seven -e T7_TOKEN=t7_... -e T7_API_URL=https://api.byteramp.se/api -- t7 mcp
```

Cursor / Windsurf (`~/.cursor/mcp.json`, `~/.codeium/windsurf/mcp_config.json`):
```json
{ "mcpServers": { "triple-seven": { "command": "t7", "args": ["mcp"],
  "env": { "T7_TOKEN": "t7_...", "T7_API_URL": "https://api.byteramp.se/api" } } } }
```

VS Code (`.vscode/mcp.json`, safe to commit — each developer is prompted for their token):
```json
{ "inputs": [{ "type": "promptString", "id": "t7-token", "description": "Triple Seven token", "password": true }],
  "servers": { "triple-seven": { "type": "stdio", "command": "t7", "args": ["mcp"],
    "env": { "T7_TOKEN": "${input:t7-token}", "T7_API_URL": "https://api.byteramp.se/api" } } } }
```

Codex (`~/.codex/config.toml`):
```toml
[mcp_servers.triple-seven]
command = "t7"
args = ["mcp"]
env = { T7_TOKEN = "t7_...", T7_API_URL = "https://api.byteramp.se/api" }
tool_timeout_sec = 900
```

Give each developer a personal token (portal → Repositories → *Install for your
team*) so runs are attributed and one person can be revoked on their own.

## GitHub Actions

```yaml
# .github/workflows/triple-seven.yml
name: Triple Seven
on: pull_request
permissions:
  contents: read
  pull-requests: write
jobs:
  t7:
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: byteramp/triple-seven@v0
        with:
          token: ${{ secrets.T7_TOKEN }}
```

The PR comment and one-click suggested changes are posted with the runner's own
`GITHUB_TOKEN`. Byteramp needs no access to your repository.

## Models

| `T7_LLM`    | Where code goes                                   |
|-------------|---------------------------------------------------|
| `byteramp`  | Byteramp's own EU VPS models — requires opt-in in the portal; never forwarded to a cloud provider, never logged |
| `azure`     | Your Azure OpenAI deployment                      |
| `openai`    | Any OpenAI-compatible endpoint you choose         |
| `anthropic` | Your Anthropic account                            |
| `ollama`    | A model next to the agent (laptop / runner)       |

## How a review runs

`planner` picks the chain for this diff → `mapper` builds the abstract
architecture delta → Byteramp's threat model returns hypotheses →
specialist `analyst`s run in parallel (authz, injection, LLM, IaC,
secrets/crypto, logic) → `triage` checks each hypothesis against the
code → an adversarial `critic` tries to refute high/critical findings →
`fixer` ⇄ `verifier` loop (isolated git worktree: applies, lint, types,
independent re-check, test suite) → `prover` writes a regression test that
must fail before and pass after the fix (L2) → noise budget → report.
Every step streams to the portal timeline.

## Verifying a release

Every release is Sigstore-signed with a CycloneDX SBOM and SLSA provenance —
see [RELEASING.md](RELEASING.md#how-customers-verify). Source is public so you can read
exactly what runs on your code; what is sent to Byteramp is documented in [SECURITY.md](SECURITY.md).
