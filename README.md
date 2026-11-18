# t7 — Triple Seven agent

Threat model, **verified fixes** and **proof** for every change. Runs on the
developer's machine and in your CI.

Your organisation selects where code is analysed. Byteramp mode sends relevant
code excerpts to Byteramp EU models. Own-provider and AI-assistant modes send
excerpts to that provider under your account. Ollama runs model analysis locally.
Byteramp retains review metadata (architecture, findings, file locations, proof/check
results and step summaries). Model prompts and completions are not stored by T7.
Metadata is redacted on the agent and server to reduce accidental code and secret
inclusion; this is a best-effort safeguard, not a complete secret detector.

Security analysis failures make the review incomplete and prevent PASS.
Large reviews are split into bounded analysis batches. The result reports specialist
file coverage and explicitly lists excluded files.

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

`t7 setup` does everything once per machine:

1. **Connects you to your organisation.** Developers choose *"I have a setup code"*
   and enter their work e-mail and the code their organisation e-mailed them (valid
   4 hours, once — *"send me a new setup code"* if it expired). No Triple Seven
   account needed. Administrators can instead sign in with their portal account
   in the browser.
2. **Stores one personal token for this machine** in
   `~/.config/t7/credentials.json` (mode 0600). It works in **every repository of
   the organisation** — the repository of each review is recognised from its git
   remote (only the URL, credentials stripped). Valid for 90 days and **renews
   itself** while you are on the organisation's roster and the subscription is
   active.
3. **Adds Triple Seven to your editors / AI assistants** — VS Code (GitHub
   Copilot agent mode), Cursor, Windsurf, Claude Code, Codex — user-wide. No token
   is written into any editor config. In a new project folder without git it
   offers `git init`.

Then:

```bash
t7 scan                                # review your current branch + uncommitted work
t7 fix SEC-REQ-SHOP-004                # apply a verified fix and its regression test
```

…or ask your assistant: *"review my change with Triple Seven"*.

A repository your organisation has not set up yet still works: it appears as
*discovered* for your administrator. An active subscription is required for
every review — in the terminal, the IDE and CI.

### For administrators

Add your developers' e-mail addresses in the portal (Triple Seven → Developers,
one or two thousand, paste or CSV). Each gets a personal setup code by e-mail.
Removing someone revokes their tokens immediately. Connect CI per repository
(Repositories → Connect); CI runs also teach Triple Seven each repository's
canonical remote.

| Command | |
|---|---|
| `t7` | welcome and next step |
| `t7 setup` | connect this machine (setup code, or `--browser` for administrators) and your editors; `--code --email you@co.se` non-interactive; `--token` to paste a repository token |
| `t7 editors` | add Triple Seven to the editors on this machine; `--show` prints the configs |
| `t7 status` | what this machine is connected to and token lifetime |
| `t7 doctor` | check access, model, tests, editors |
| `t7 scan [--all]` | review the change (or the whole repository) |
| `t7 list` / `t7 fix ID` | fixes from the last scan / apply one |
| `t7 check` / `t7 hooks install` | seconds-fast checkpoint without a model; pre-commit + Claude Code hook |
| `t7 update` | update to the latest release (t7 reminds you once a day) |
| `t7 logout` | remove the stored token for this repository |

## First baseline and later changes

`t7 scan --all --no-fix` checks repository source files locally and applies AI verification to risk paths identified by the supported rules. It does not send every source line to AI. Python checks recognize request/tool arguments and model/network outputs within functions; pattern checks cover other supported languages and configuration. Custom cross-function flows and unmatched semantic risks are outside the baseline's complete coverage.

Confirmed findings still face an independent critic. Unverified paths remain visible and make the baseline warn. Local source inventory nodes do not assert runtime network flows or trust boundaries.

Use `t7 scan` for later changes: contextual specialist reviews remain in place. `--all` with fix preparation enabled also runs the fix and project-check stages, whose time depends on the project. Proposed changes are prepared separately; the working copy stays untouched until a fix is applied.

## In your editor / AI assistant (MCP)

`t7 setup` registers `t7 mcp` (a Model Context Protocol server) for you. Tools:
`t7_scan`, `t7_findings`, `t7_explain`, `t7_show_fix`, `t7_apply_fix`,
`t7_doctor`. The server finds the open workspace itself (or the assistant
passes `repo_path`).

**Which model analyses the code** is decided by your organisation's *model policy*
(portal → Repositories): Byteramp EU models, your organisation's own model (endpoint in
the policy, API key in your environment as `T7_LLM_API_KEY`), a local Ollama model, or
the editor's model via MCP sampling in compatible clients (only if the policy
allows it) — or the developer's own signed-in AI CLI (Claude Code, Codex, Gemini CLI,
Copilot CLI) under their subscription, **no API key**. t7 applies the policy before any model call; it overrides `T7_LLM` and
never falls back to another model. Every result states what analysed it. Without a
policy, t7 uses Byteramp models (after opt-in) or what you set with `T7_LLM`.

Ask in your assistant's chat (VS Code: Copilot Chat in **Agent** mode). The assistant
only starts `t7_scan`; the review itself is t7's own pipeline with the model above.

For a whole-repository review, paste this into Copilot Chat in **Agent** mode:

```text
Call Triple Seven's t7_scan MCP tool with all=true and fix=true for this workspace. Show the T7 result when it finishes.
```

This is equivalent to `t7 scan --all`: proposed fixes are prepared and verified; applying
one is a separate action. For a first baseline without fix preparation, use `fix=false`
(equivalent to `t7 scan --all --no-fix`). For later changes, use `all=false`.

**Copilot in VS Code and the terminal use the official Copilot runtime for T7.**
Install it once and sign in with your existing Copilot account:

```sh
npm install -g @github/copilot
t7 copilot login
t7 editors
```

Reload VS Code, then use the chat prompt above. For a terminal review, run
`T7_ASSISTANT=copilot t7 scan --all --no-fix`. An existing supported `gh auth login`
can also supply the Copilot account login. No separate model API key is needed.
Your Copilot plan's model access and usage limits still apply.

T7 uses **Auto routing**, rather than forcing the resolved ID of the model selected
in chat. Some models work through Auto but reject direct MCP sampling requests.
The result records the actual model used. The organisation must allow **Copilot**;
an editor-sampling-only policy does not permit this route. T7 never changes providers
to work around a policy or access error.

Each model call runs in an isolated T7 profile, with tools disabled. The outer
assistant starts T7; it does not replace the scan with its own review.

## Scan duration and progress

`t7 check` is the fast, model-free check. `t7 scan` reviews the current change;
`t7 scan --all` reviews the entire repository. With fix preparation enabled,
T7 also verifies proposed patches and runs available checks. A full baseline can
take substantially longer than a change review, especially with CPU-hosted models.

Byteramp model inputs are split into smaller batches with complete source coverage.
The editor and portal show each batch starting and finishing. A model timeout stops
that request instead of automatically repeating the same oversized input. A failed
or interrupted run is not a completed security review.

## Token lifetime

| Token | Lifetime | Renewal |
|---|---|---|
| Developer (`t7 setup`) | 90 days | automatic, by `t7`, while you are on the roster and the subscription is active |
| CI (`T7_TOKEN` secret) | 1 year | portal → Repositories → Renew; the portal warns 30 days ahead |

An expired or revoked developer token: run `t7 setup` → *send me a new setup code*.

## Checkpoint in the agent loop

```bash
t7 hooks install      # git pre-commit + Claude Code Stop hook (in .claude/settings.json)
```

Every commit — and every turn of Claude Code — gets a seconds-fast check without a model
(`t7 check`): secrets, shell/deserialization sinks, tenant IDs from the request, and the
repository's agent/MCP configuration. Blocking items stop the commit (or are handed back
to the agent to fix); `t7 scan` remains the full review.

## Whole organisation (administrators)

Create an **organisation CI token** in the portal (Triple Seven → CI / CD) — one secret for
every repository; each run is matched to its repository by its git remote. Then:

```bash
gh auth login                         # organisation owner
t7 rollout your-org --dry-run         # see what would happen
t7 rollout your-org --require-check   # secret + a PR per repository + merge rule
```

GitLab: set `T7_TOKEN` as a group CI/CD variable and `include:` the template below in
each project (or in a pipeline execution policy). Details per platform: portal → CI / CD.

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

## Trusted connection settings

Set T7_API_URL and T7_LLM_BASE_URL in your environment for custom endpoints.
Repository .t7.json files cannot override connection endpoints or authentication state.
Keep T7_TOKEN and T7_LLM_API_KEY in your local secret store or CI secrets.
