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
    'copilot': {'bin': 'copilot', 'label': 'GitHub Copilot CLI', 'login': 't7 copilot login'},
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


def _run(cmd, stdin_text, timeout, cwd, env=None):
    try:
        p = subprocess.run(cmd, input=stdin_text, capture_output=True, text=True, timeout=timeout,
                           cwd=cwd, env={**(env if env is not None else os.environ), 'NO_COLOR': '1'})
    except subprocess.TimeoutExpired:
        raise AssistantError(f'{cmd[0]} did not answer within {timeout}s') from None
    except OSError as e:
        raise AssistantError(f'{cmd[0]} could not start: {e}') from None
    return p


def _fail(key, p):
    err = (p.stderr or p.stdout or '').strip()[-400:]
    if key == 'copilot' and p.returncode == 127:
        error = AssistantError('GitHub Copilot runtime is unavailable. Install it with '
                               'npm install -g @github/copilot, then run t7 copilot login. '
                               'Use it from Copilot Chat in VS Code or the terminal. Your Copilot plan and '
                               'usage limits apply; no separate model API key is needed.')
        error.retryable = False
        raise error
    if key == 'copilot':
        error = AssistantError('Copilot runtime request failed. Update Copilot CLI, then run '
                               't7 copilot login (or gh auth login with your Copilot account). '
                               'T7 uses Auto routing within your existing plan; no API key is required.')
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
            # Auto is the account's supported router. Passing its resolved model id
            # directly can be rejected even when the same model works through Auto.
            # Empty --available-tools exposes ALL tools in affected official CLI
            # versions (github/copilot-cli#5306). A non-matching name selects none;
            # explicit permission denials add protection if CLI filtering regresses.
            env = _copilot_env(cwd)
            try:
                p = _run(['copilot', '--model', 'auto', '--available-tools=__t7_model_only__',
                          '--deny-tool=shell', '--deny-tool=read', '--deny-tool=write',
                          '--deny-tool=url', '--deny-tool=memory',
                          '--disable-builtin-mcps', '--no-custom-instructions', '--no-ask-user',
                          '--trust-folder', '--sync-session=off', '--output-format', 'json',
                          '-p', full], None, timeout, cwd, env=env)
            except AssistantError as error:
                error.retryable = False
                raise
            if p.returncode != 0:
                _fail(key, p)
            return _copilot_result(p.stdout)
    raise AssistantError(f'Unknown assistant {key}')


def _copilot_env(cwd):
    """Isolated T7 profile; use explicit auth or the officially supported gh OAuth login."""
    from .credentials import path
    env = {k: v for k, v in os.environ.items() if not k.startswith(('COPILOT_PROVIDER_', 'T7_'))}
    # The runtime must not load a developer's plugins, MCP servers or repository hooks.
    profile = path().parent / 'copilot'
    profile.mkdir(parents=True, exist_ok=True)
    os.chmod(profile, 0o700)
    env['COPILOT_HOME'] = str(profile)
    if not any(env.get(k) for k in ('COPILOT_GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN')):
        gh = shutil.which('gh')
        if gh:
            try:
                token = subprocess.run([gh, 'auth', 'token'], capture_output=True, text=True, timeout=10)
                if token.returncode == 0 and token.stdout.strip():
                    env['COPILOT_GITHUB_TOKEN'] = token.stdout.strip()
            except (OSError, subprocess.SubprocessError):
                pass
    return env


def _copilot_result(text):
    answer, model, completed = '', '', False
    for line in text.splitlines():
        try:
            event = json.loads(line)
        except ValueError:
            continue
        if not isinstance(event, dict):
            continue
        kind, data = event.get('type'), event.get('data') or {}
        if not isinstance(data, dict):
            continue
        if kind == 'tool.execution_start':
            error = AssistantError('Copilot attempted a tool call in a model-only review request.')
            error.retryable = False
            raise error
        if kind == 'assistant.message' and not data.get('parentToolCallId'):
            answer, model = str(data.get('content') or ''), str(data.get('model') or '')
        if kind == 'result':
            completed = event.get('exitCode') == 0
    if not completed or not answer.strip():
        error = AssistantError('Copilot did not return a completed model response. Run t7 copilot login '
                               'or update the official Copilot CLI, then retry.')
        error.retryable = False
        raise error
    return answer, 'auto/' + (model or 'copilot')


def copilot_login():
    """Use the official OAuth flow in the isolated T7 runtime profile."""
    import pathlib
    env = _copilot_env(str(pathlib.Path.cwd()))
    # Login should establish its own credential rather than inherit a token override.
    for key in ('COPILOT_GITHUB_TOKEN', 'GH_TOKEN', 'GITHUB_TOKEN'):
        env.pop(key, None)
    return subprocess.call(['copilot', 'login'], env=env)
