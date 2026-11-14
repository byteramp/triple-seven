# Changelog

Update with `t7 update`. t7 reminds you (at most once a day) when a new version is out.

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
