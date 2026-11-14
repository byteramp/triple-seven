# t7 — Triple Seven agent

Threat model, **verified fixes** and **proof** for every change. Runs on the
developer's machine and in your CI. **Your source code never leaves your
environment**: Byteramp only receives an abstract architecture model and
finding metadata (title, file:line, fix/proof results as hashes and pass/fail).

## Get started (developer machine)

```bash
cd path/to/your-repository
curl -fsSL https://raw.githubusercontent.com/byteramp/triple-seven/main/install.sh | sh
```

or, if you prefer to install it yourself:

```bash
pipx install t7-agent                  # stdlib only, no third-party dependencies
cd path/to/your-repository
t7 setup
```

`t7 setup` does everything once:

1. **Signs you in through the browser.** It shows a code and opens the portal;
   approve it there (portal login), or enter the code on the invitation e-mail
   your team sent you. No token to copy.
2. **Stores a personal token for this repository** in
   `~/.config/t7/credentials.json` (mode 0600). It is valid for 90 days and
   **renews itself** while your organization's subscription is active.
3. **Adds Triple Seven to your editors / AI assistants** — VS Code (GitHub
   Copilot agent mode), Cursor, Windsurf, Claude Code, Codex — user-wide, so it
   works in every repository. No token is written into any editor config.

Then:

```bash
t7 scan                                # review your current branch + uncommitted work
t7 fix SEC-REQ-SHOP-004                # apply a verified fix and its regression test
```

…or ask your assistant: *"review my change with Triple Seven"*.

Every other repository: `cd` into it and run `t7 setup` again (one click in the
browser). An active Triple Seven subscription is required for every review — in
the terminal, the IDE and CI.

| Command | |
|---|---|
| `t7` | welcome and next step |
| `t7 setup` | connect this repository (browser sign-in) and your editors; `--token` to paste a token instead |
| `t7 editors` | add Triple Seven to the editors on this machine; `--show` prints the configs |
| `t7 status` | repositories connected on this machine and token lifetime |
| `t7 doctor` | check access, model, tests, editors |
| `t7 scan [--all]` | review the change (or the whole repository) |
| `t7 list` / `t7 fix ID` | fixes from the last scan / apply one |
| `t7 logout` | remove the stored token for this repository |

## In your editor / AI assistant (MCP)

`t7 setup` registers `t7 mcp` (a Model Context Protocol server) for you. Tools:
`t7_scan`, `t7_findings`, `t7_explain`, `t7_show_fix`, `t7_apply_fix`,
`t7_doctor`. The server finds the open workspace itself (or the assistant
passes `repo_path`).

- **VS Code + GitHub Copilot:** Copilot Chat → **Agent** mode → ask. The
  analysis runs on *your Copilot model* via MCP sampling (VS Code asks once to
  allow it). Set `T7_LLM` to use another model.
- **Claude Code / Cursor / Windsurf / Codex:** ask in chat. These clients do not
  offer sampling: the analysis uses Byteramp models (after your administrator's
  opt-in) or the provider you set with `T7_LLM`.

Manual configuration (if you skipped it): `t7 editors --show`.

## Token lifetime

| Token | Lifetime | Renewal |
|---|---|---|
| Developer (`t7 setup`) | 90 days | automatic, by `t7`, while the subscription is active |
| CI (`T7_TOKEN` secret) | 1 year | portal → Repositories → Renew; the portal warns 30 days ahead |

An expired or revoked developer token: run `t7 setup` again.

## GitHub Actions

```yaml
# .github/workflows/triple-seven.yml
name: Triple Seven
on:
  pull_request:
  push:
    branches: [main]          # review coverage: which merges were reviewed
  issue_comment:
    types: [created]          # /t7 accept-risk | false-positive | not-applicable | reopen
permissions:
  contents: read
  pull-requests: write
  statuses: write             # the "Triple Seven" commit status carries the merge gate
jobs:
  t7:
    if: github.event_name != 'issue_comment' || startsWith(github.event.comment.body, '/t7')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: { fetch-depth: 0 }
      - uses: byteramp/triple-seven@v0
        with:
          token: ${{ secrets.T7_TOKEN }}
```

Protect the branch on the **Triple Seven** commit status (not the job). A
collaborator can clear a blocking finding from the PR with
`/t7 accept-risk SEC-REQ-… <reason>` — the decision is recorded with an audit
trail and the status flips to success. Each finding in the PR comment also has
a ready prompt for Claude Code, Cursor, Codex or Copilot.

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

## GitLab

Copy [`templates/gitlab-ci.yml`](templates/gitlab-ci.yml) into your `.gitlab-ci.yml`
and add two masked CI/CD variables: `T7_TOKEN` (from the portal) and
`T7_GITLAB_TOKEN` (a project access token, scope `api`, role Reporter, so t7 can
comment on the merge request with one-click suggestions). Works with
self-managed GitLab — `CI_API_V4_URL` is picked up automatically.

## Any other CI (Bitbucket, Azure DevOps, Jenkins …)

See [`templates/generic-ci.sh`](templates/generic-ci.sh): `t7 scan --ci` exits
non-zero when an enforced merge gate blocks, and writes `t7-report.md`.

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
