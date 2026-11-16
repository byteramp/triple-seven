"""The developer's own, logged-in AI assistant as t7's model — no API key.

Many developers are already signed in to Claude Code, Codex, Gemini CLI or GitHub
Copilot CLI with their subscription. t7 can run that CLI non-interactively for each
analysis step, so the review uses the same model and the same account, without a key.

Safety: the CLI is started in an empty temporary directory, with its tools disabled
or a read-only sandbox where the CLI supports it — it only answers the prompt t7
gives it; it does not browse or change the repository by itself. The prompt is the
same text t7 would send to any model (the code excerpts needed for the step).
"""
import json
import os
import shutil
import subprocess
import tempfile

# Order = preference when several are installed (overridable with T7_ASSISTANT).
ASSISTANTS = {
    'claude': {'bin': 'claude', 'label': 'Claude Code', 'login': 'claude  (then /login)'},
    'codex': {'bin': 'codex', 'label': 'Codex', 'login': 'codex login'},
    'gemini': {'bin': 'gemini', 'label': 'Gemini CLI', 'login': 'gemini  (sign in with Google)'},
    'copilot': {'bin': 'copilot', 'label': 'GitHub Copilot CLI', 'login': 'copilot  (then /login)'},
}


class AssistantError(RuntimeError):
    pass


def installed():
    return [k for k, v in ASSISTANTS.items() if shutil.which(v['bin'])]


def pick(allowed=None):
    """The assistant to use: T7_ASSISTANT if set and allowed, else the first installed one
    that is allowed. None if there is none."""
    allowed = [a for a in (allowed or ASSISTANTS) if a in ASSISTANTS]
    wanted = os.environ.get('T7_ASSISTANT', '').strip().lower()
    have = installed()
    if wanted:
        return wanted if wanted in have and wanted in allowed else None
    return next((a for a in have if a in allowed), None)


def label(key):
    return ASSISTANTS.get(key, {}).get('label', key)


def _run(cmd, stdin_text, timeout, cwd):
    try:
        p = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd, env={**os.environ, 'NO_COLOR': '1'})
    except subprocess.TimeoutExpired:
        raise AssistantError(f'{cmd[0]} did not answer within {timeout}s') from None
    except OSError as e:
        raise AssistantError(f'{cmd[0]} could not start: {e}') from None
    return p


def _fail(key, p):
    err = (p.stderr or p.stdout or '').strip()[-400:]
    if key == 'copilot' and p.returncode == 127:
        error = AssistantError('GitHub Copilot CLI is unavailable. For Copilot in VS Code, '
                               'run the Triple Seven MCP tool from Copilot Chat (Agent mode) '
                               'with editor model access enabled and allowed by your model policy. '
                               'For terminal scans, install and sign in to Copilot CLI, '
                               'or choose Byteramp models in the portal.')
        error.retryable = False
        raise error
    hint = ''
    if any(w in err.lower() for w in ('login', 'log in', 'auth', 'unauthor', 'credential', 'sign in',
                                      'setupuser', 'code_assist')):
        hint = f' — are you signed in? Run: {ASSISTANTS[key]["login"]}'
    raise AssistantError(f'{label(key)} failed (exit {p.returncode}){hint}: {err}')


def complete(key, system, prompt, timeout=600):
    """(text, model) from the assistant CLI. Raises AssistantError."""
    # A fake "SYSTEM" header inside the prompt reads like prompt injection to these assistants
    # (Claude Code refuses it). Claude gets the system text through --system-prompt; the
    # others get it as plain role text at the top.
    full = (f'{system}\n\n---\n\n' if system else '') + prompt
    with tempfile.TemporaryDirectory(prefix='t7-assistant-') as cwd:
        if key == 'claude':
            # --setting-sources local: the developer's own hooks/plugins/output styles do not
            # reshape t7's answers (cwd is an empty temp dir, so 'local' is empty). Not --bare:
            # that disables the subscription login.
            base = ['claude', '-p', '--output-format', 'json', '--no-session-persistence',
                    '--setting-sources', 'local', '--system-prompt', system or 'Respond precisely.']
            p = _run(base + ['--tools', ''], prompt, timeout, cwd)
            if p.returncode != 0 and 'unknown option' in (p.stderr or '').lower():
                p = _run(base + ['--disallowedTools', 'Bash,Edit,Write,WebFetch,WebSearch'], prompt, timeout, cwd)
            if p.returncode != 0:
                _fail(key, p)
            try:
                data = json.loads(p.stdout)
            except ValueError:
                return p.stdout.strip(), 'claude-code'
            if data.get('is_error'):
                raise AssistantError(f'Claude Code: {str(data.get("result"))[:300]}')
            model = next(iter((data.get('modelUsage') or {}).keys()), '') or 'claude-code'
            return str(data.get('result') or ''), model
        if key == 'codex':
            out = os.path.join(cwd, 'answer.txt')
            p = _run(['codex', 'exec', '-', '--skip-git-repo-check', '--sandbox', 'read-only',
                      '--output-last-message', out], full, timeout, cwd)
            if p.returncode != 0:
                _fail(key, p)
            try:
                with open(out) as fh:
                    return fh.read(), 'codex'
            except OSError:
                return p.stdout.strip(), 'codex'
        if key == 'gemini':
            # Read-only plan mode: no tool may change anything.
            p = _run(['gemini', '--approval-mode', 'plan', '-p', full], None, timeout, cwd)
            if p.returncode != 0:
                _fail(key, p)
            return p.stdout.strip(), 'gemini-cli'
        if key == 'copilot':
            # No --allow-all-tools: any tool call fails instead of running.
            p = _run(['copilot', '-p', full, '-s'], None, timeout, cwd)
            if p.returncode != 0 and 'unknown option' in (p.stderr or '').lower():
                p = _run(['copilot', '-p', full], None, timeout, cwd)
            if p.returncode != 0:
                _fail(key, p)
            return p.stdout.strip(), 'copilot-cli'
    raise AssistantError(f'Unknown assistant {key}')
