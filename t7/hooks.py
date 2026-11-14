"""`t7 check` and `t7 hooks install` — a security checkpoint inside the agent loop
(plan → generate → CHECK → commit), in seconds and without a model.

`t7 check` runs the deterministic layer of t7 on what is about to be committed (or what an
AI agent just changed): code signals on added lines + the repository's agent/MCP
configuration when it changed. It blocks only on high-confidence, high-impact patterns
(secrets, shell/deserialization sinks, agent permission bypasses, whole-file-system MCP
servers); everything else is a warning pointing to `t7 scan` for the full review.

Hooks:
  git          .git/hooks/pre-commit → `t7 check --staged`
  claude       .claude/settings.json Stop hook → `t7 check --agent` (exit 2 tells Claude
               Code what to fix before it finishes)
"""
import json
import os
import stat
import sys
from pathlib import Path

from . import agent_config, gitops
from .signals import scan

BLOCKING = {'secret_literal', 'shell_exec', 'deserialization', 'agent_bypass_permissions',
            'mcp_unbounded_fs', 'mcp_plaintext_secret'}
LABEL = {
    'secret_literal': 'secret in code', 'shell_exec': 'shell command built from input',
    'deserialization': 'untrusted deserialization', 'sql_construct': 'SQL built from input',
    'ssrf_sink': 'request to a user-controlled URL', 'idor': 'object fetched by ID without an ownership check',
    'auth_bypass_risk': 'authentication/CSRF relaxed', 'tenant_from_request': 'tenant ID taken from the request',
    'llm_output_exec': 'model output executed', 'llm_prompt_untrusted': 'untrusted input in a prompt',
    'mcp_tool_exec': 'MCP tool with side effects', 'agent_bypass_permissions': 'agent permission checks disabled',
    'mcp_unbounded_fs': 'MCP server with whole-file-system access', 'mcp_plaintext_secret': 'secret in MCP/agent config',
    'agent_wildcard_tools': 'wildcard agent tool permissions', 'mcp_insecure_transport': 'MCP server over plain HTTP',
    'mcp_unpinned_server': 'unpinned MCP server package', 'crypto_weak': 'weak cryptography',
    'pii_logging': 'sensitive data in logs', 'iac_public_exposure': 'resource exposed publicly',
}
MARK = '# triple-seven'


def check(staged=False, agent=False):
    root = gitops.repo_root()
    base = '--cached' if staged else 'HEAD'
    if not gitops.has_commits(root):
        base = '--cached' if staged else gitops.EMPTY_TREE
    from .config import Config
    cfg = Config.load(root)
    changed = gitops.changed_files(root, base, include_worktree=not staged, ignore=cfg.ignore_paths)
    signals, _ = scan(changed)
    if agent_config.touched(root, 'HEAD' if gitops.has_commits(root) else gitops.EMPTY_TREE):
        signals += agent_config.scan_repo(root)[0]
    blocking = [s for s in signals if s['kind'] in BLOCKING]
    warn = [s for s in signals if s['kind'] not in BLOCKING]
    out = sys.stderr if agent else sys.stdout
    if not signals:
        if not agent:
            print('t7 check: nothing risky in this change. ✓  (full review: t7 scan)')
        return 0
    print(f't7 check: {len(blocking)} blocking, {len(warn)} to review', file=out)
    for s in blocking + warn:
        tag = 'BLOCK' if s['kind'] in BLOCKING else 'check'
        print(f"  [{tag}] {s['file']}:{s['line']}  {LABEL.get(s['kind'], s['kind'])}", file=out)
    if blocking:
        if agent:
            print('Fix the BLOCK items above before finishing (move secrets to environment variables, '
                  'avoid shell/unsafe deserialization, scope agent/MCP permissions). Then run `t7 scan` '
                  'for the full security review.', file=out)
            return 2          # Claude Code: exit 2 feeds this back to the agent
        print('Commit blocked by Triple Seven. Fix the BLOCK items, or commit with --no-verify if this is a '
              'false positive. Full review: t7 scan', file=out)
        return 1
    print('Run `t7 scan` for the full review of the items to check.', file=out)
    return 0


def _install_git(root):
    hooks = Path(gitops.git(root, 'rev-parse', '--git-path', 'hooks').strip())
    if not hooks.is_absolute():
        hooks = Path(root) / hooks
    hooks.mkdir(parents=True, exist_ok=True)
    p = hooks / 'pre-commit'
    line = f'{MARK}\nt7 check --staged || exit $?\n'
    if p.exists():
        text = p.read_text()
        if MARK in text:
            return 'git pre-commit: already installed'
        p.write_text(text.rstrip('\n') + '\n\n' + line)
    else:
        p.write_text('#!/bin/sh\n' + line)
    p.chmod(p.stat().st_mode | stat.S_IEXEC | stat.S_IXGRP | stat.S_IXOTH)
    return f'git pre-commit: {p}'


def _install_claude(root):
    p = Path(root) / '.claude' / 'settings.json'
    try:
        data = json.loads(p.read_text()) if p.exists() else {}
    except ValueError:
        return f'Claude Code: {p} is not plain JSON — add a Stop hook running `t7 check --agent` by hand'
    hooks = data.setdefault('hooks', {})
    stop = hooks.setdefault('Stop', [])
    if any('t7 check' in h.get('command', '') for entry in stop for h in entry.get('hooks', [])):
        return 'Claude Code: already installed'
    stop.append({'hooks': [{'type': 'command', 'command': 't7 check --agent', 'timeout': 60}]})
    p.parent.mkdir(parents=True, exist_ok=True)
    p.write_text(json.dumps(data, indent=2) + '\n')
    return f'Claude Code Stop hook: {p} (commit it to share with the team)'


def install(git=True, claude=True):
    root = gitops.repo_root()
    done = []
    if git:
        done.append(_install_git(root))
    if claude:
        done.append(_install_claude(root))
    return done


def uninstall():
    root = gitops.repo_root()
    hooks = Path(gitops.git(root, 'rev-parse', '--git-path', 'hooks').strip())
    p = (hooks if hooks.is_absolute() else Path(root) / hooks) / 'pre-commit'
    if p.exists() and MARK in p.read_text():
        text = p.read_text().replace(f'{MARK}\nt7 check --staged || exit $?\n', '')
        if text.strip() in ('', '#!/bin/sh'):
            os.remove(p)
        else:
            p.write_text(text)
    s = Path(root) / '.claude' / 'settings.json'
    if s.exists():
        try:
            data = json.loads(s.read_text())
            stop = data.get('hooks', {}).get('Stop', [])
            data['hooks']['Stop'] = [e for e in stop if not any('t7 check' in h.get('command', '')
                                                                 for h in e.get('hooks', []))]
            s.write_text(json.dumps(data, indent=2) + '\n')
        except (ValueError, KeyError, TypeError):
            pass
