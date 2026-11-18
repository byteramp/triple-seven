# Changelog

## 0.7.4

- Bound Byteramp architecture and specialist inputs to smaller batches while preserving source coverage.
- Reduce Byteramp planner input size and retain the sampled file index.
- Publish step starts and per-batch progress immediately to the portal and MCP client.
- Honour server retryability instructions so expensive model timeouts are not repeated unchanged.
- Explain the difference between fast local checks, change reviews and full baseline reviews.

## 0.7.3

- Report rejected, cancelled and failed editor model requests with setup instructions instead of misleading JSON-repair errors.
- Stop immediately when the editor cannot provide a completion; preserve provider policy without fallback.
- Reject truncated model responses and combine multiple text blocks correctly.
- Document exact Copilot Chat prompts, full-scan options and the separate terminal CLI requirement.

## 0.7.2

- Stop incomplete security reviews from passing after specialist, triage or critic failures.
- Reject malformed model JSON and invalid fix-verification responses.
- Prevent repository settings from redirecting connection endpoints or authentication state.
- Refuse cross-origin HTTP redirects for model and agent requests.
- Constrain fix and proof file paths to the workspace, including symlink targets.
- Batch all relevant files and changed code regions. Report reviewed and excluded files.
- Include removed controls in analysis and redact metadata before upload.
- Clarify which model provider processes code excerpts and which metadata is retained.
- Custom API/model endpoints now require environment settings rather than .t7.json.


Update with `t7 update`. t7 reminds you (at most once a day) when a new version is out.

## 0.7.1
- `t7 scan --all` now reviews the full repository against the empty tree, including committed files on the main branch.
- Empty source files skip architecture model calls. Changes containing only removed lines map the remaining source.
- An editor-only model policy requires MCP model access and correctly blocks terminal CLI selection.
- Missing Copilot CLI reports how to use VS Code Copilot or install the terminal CLI. Model and API failures exit with a concise error.
- Permanent request errors and missing Copilot CLI fail immediately without repeated attempts.

## 0.7.0
- **Living threat model.** Full scans and merged changes keep your repository's architecture
  threat model current in the portal (map, threats, version timeline, auditor document).
  The mapper now reuses the names of the existing model, so it stays coherent.
- **Agent-built software & MCP.** New specialists for multi-tenant isolation and for agentic
  code (confused deputy, unbounded tool/MCP permissions, prompt injection through tools,
  agent-introduced data flows). Agent/MCP configuration (.mcp.json, .cursor, .vscode,
  .claude, Gemini, Kiro, Codex) is reviewed when it changes: whole-file-system servers,
  secrets in plain text, permission bypass, wildcard tools, plain-HTTP and unpinned servers.
- **Checkpoint in the agent loop.** `t7 check` (seconds, no model) and `t7 hooks install`:
  a git pre-commit hook plus a Claude Code Stop hook that tells the agent what to fix
  before it finishes. `t7 scan` stays the full review.

## 0.6.1
- **Separate model policy for CI.** CI runs (`t7 scan --ci`) follow the organisation's CI
  policy (e.g. Byteramp or your own model), developer machines follow the developers'
  policy (e.g. their own signed-in assistant). CI tokens always count as CI.
- `t7 rollout --dry-run` says how many pull requests would be opened.

## 0.6.0
- **`t7 rollout ORG`** (administrators): switches Triple Seven on for a whole GitHub
  organisation with your own `gh` login — sets the organisation secret `T7_TOKEN`, opens a
  pull request with the workflow in each repository you choose, and with `--require-check`
  adds a ruleset requiring the "Triple Seven" status. Byteramp gets no access. `--dry-run`,
  `--repos a,b`, `--all`.
- Works with the new **organisation CI token**: one secret for every repository; each run
  is matched to its repository by the git remote.
- CI templates install the newest 0.x agent instead of a pinned old version.

## 0.5.0
- **Use the AI you are already signed in to — no API key.** t7 can run your signed-in
  Claude Code, Codex, Gemini CLI or GitHub Copilot CLI for its analysis (in an empty
  folder, tools off / read-only), under your own subscription. Your organisation's
  policy "Developer's own AI assistant" uses the editor's model when you review from
  the editor, otherwise the signed-in CLI. `T7_LLM=claude-cli` (or codex-cli, …) when no
  policy is set. `t7 doctor` lists the assistants it found.
- More editors and assistants registered by `t7 setup` / `t7 editors`: Claude Desktop,
  Gemini CLI, Antigravity, Kiro, Zed, Cline. Perplexity (Mac): see `t7 editors --show`.

## 0.4.0
- **Model policy from your organisation.** Your administrator decides which model analyses
  code (Byteramp EU models, your organisation's own model, a local model, or the editor's
  model). t7 applies it before any model call — it overrides `T7_LLM` and never falls back
  to another model. If this machine cannot satisfy it (e.g. no API key), t7 tells you exactly
  what is missing.
- **The editor's model is no longer used automatically.** VS Code + Copilot (MCP sampling)
  is used only when your organisation's policy says so (or you set `T7_LLM=client` while no
  policy is set).
- Every review states what analysed it: terminal, editor answer, pull-request comment, portal.
- **`t7 update`** and a daily update reminder. Agents below the supported minimum are told to update.
- `t7 doctor` shows the model policy and available updates.

## 0.3.1
- Clear warning when a `T7_TOKEN` in your shell overrides your `t7 setup` sign-in.
- Clearer message when Byteramp models are not enabled for a repository.

## 0.3.0
- **Setup code from your organisation**: no Triple Seven account needed. One setup per
  machine works in every repository of the organisation (matched by git remote).
- `t7 setup` → "send me a new setup code"; `--code --email` for non-interactive use.

## 0.2.1
- `t7 setup` in a new project folder offers `git init`; the installer continues into setup.

## 0.2.0
- Installer (`install.sh`), browser sign-in, editors registered once (VS Code, Cursor,
  Windsurf, Claude Code, Codex), self-renewing 90-day tokens, `t7 editors`, `t7 status`.

## 0.1.5
- `t7 setup`, welcome screen, a valid token is required for every review.
