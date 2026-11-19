"""Deterministic review of AI-agent / MCP configuration in the repository.

Agent-built software ships configuration that scanners never look at: which MCP servers
an agent may start, with which file-system scope, secrets and permission modes. These
files live in folders t7 otherwise skips (.vscode/, .cursor/, .claude/), so they are read
here directly. Findings go to the threat model as signals (kind + file:line, no content).
"""
import json
import re
from pathlib import Path

FILES = ['.mcp.json', '.cursor/mcp.json', '.vscode/mcp.json', '.claude/settings.json',
         '.claude/settings.local.json', '.gemini/settings.json', '.kiro/settings/mcp.json',
         'claude_desktop_config.json', '.codex/config.toml', 'mcp.json']

SECRET_KEY = re.compile(r'(?i)(token|secret|password|api[_-]?key|private[_-]?key|auth)')
ENV_REF = re.compile(r'^\$\{?[A-Za-z_][A-Za-z0-9_]*\}?$|^\$\{input:')
UNPINNED = re.compile(r'^(@?[\w.-]+/)?[\w.-]+$')          # npx pkg / uvx pkg without @version


def _line_of(text, needle):
    i = text.find(needle)
    return text.count('\n', 0, i) + 1 if i >= 0 else 1


def _servers(data):
    for key in ('mcpServers', 'servers', 'context_servers'):
        v = data.get(key)
        if isinstance(v, dict):
            yield from v.items()


def check_json(path, text):
    out = []
    try:
        data = json.loads(text)
    except ValueError:
        return out
    if not isinstance(data, dict):
        return out

    def sig(kind, needle, detail):
        out.append({'kind': kind, 'file': path, 'line': _line_of(text, needle), 'detail': detail})

    for name, srv in _servers(data):
        if not isinstance(srv, dict):
            continue
        args = [str(a) for a in srv.get('args') or []]
        if any(a in ('/', '~', '~/', '/Users', '/home', 'C:\\\\') for a in args):
            sig('mcp_unbounded_fs', f'"{name}"', f'MCP server "{name}" is given the whole file system')
        for k, v in (srv.get('env') or {}).items():
            if SECRET_KEY.search(k) and isinstance(v, str) and v and not ENV_REF.match(v.strip()):
                sig('mcp_plaintext_secret', k, f'MCP server "{name}": {k} is a literal value')
        url = str(srv.get('url') or srv.get('serverUrl') or srv.get('httpUrl') or '')
        if url.startswith('http://') and not re.match(r'http://(localhost|127\.0\.0\.1)', url):
            sig('mcp_insecure_transport', url, f'MCP server "{name}" uses plain HTTP')
        cmd = str(srv.get('command') or '')
        if cmd.rsplit('/', 1)[-1] in ('npx', 'uvx', 'bunx', 'pnpx'):
            pkg = next((a for a in args if not a.startswith('-')), '')
            if pkg and UNPINNED.match(pkg) and '@' not in pkg.lstrip('@'):
                sig('mcp_unpinned_server', pkg, f'MCP server "{name}" runs {pkg} without a pinned version')
    perms = data.get('permissions') if isinstance(data.get('permissions'), dict) else {}
    if str(perms.get('defaultMode', '')).lower() in ('bypasspermissions',) or data.get('dangerouslySkipPermissions') \
            or str(data.get('approvalMode', data.get('approval_mode', ''))).lower() == 'yolo':
        sig('agent_bypass_permissions', 'Mode', 'agent permission checks are bypassed')
    allow = perms.get('allow') or []
    if any(str(a).strip() in ('*', 'Bash', 'Bash(*)', 'Bash(*:*)', 'mcp__*') for a in allow):
        sig('agent_wildcard_tools', 'allow', 'wildcard tool / shell permission')
    return out


def check_toml(path, text):
    out = []
    for i, line in enumerate(text.splitlines(), 1):
        if re.search(r'(?i)^\s*(approval_policy|ask_for_approval)\s*=\s*"never"', line) and \
                re.search(r'(?i)sandbox_mode\s*=\s*"danger-full-access"', text):
            out.append({'kind': 'agent_bypass_permissions', 'file': path, 'line': i,
                        'detail': 'Codex runs without approval and without a sandbox'})
        m = re.match(r'\s*(\w*(?:TOKEN|SECRET|KEY|PASSWORD)\w*)\s*=\s*"([^"$]{8,})"', line, re.I)
        if m:
            out.append({'kind': 'mcp_plaintext_secret', 'file': path, 'line': i,
                        'detail': f'{m.group(1)} is a literal value'})
    return out


def scan_repo(root):
    """Signals + areas for agent configuration files present in the repository."""
    root = Path(root)
    signals = []
    for rel in FILES:
        p = root / rel
        if not p.is_file() or p.is_symlink() or not p.resolve().is_relative_to(root.resolve()):
            continue
        try:
            text = p.read_text(errors='replace')[:200000]
        except OSError:
            continue
        signals += check_toml(rel, text) if rel.endswith('.toml') else check_json(rel, text)
    return signals, ({'agentic'} if signals else set())


def touched(root, base_sha, include_worktree=True):
    """Was any agent configuration file changed? (These folders are skipped by the normal
    diff, so ask git directly.)"""
    import subprocess
    names = set()
    try:
        names |= set(subprocess.run(['git', 'diff', '--name-only', base_sha] + ([] if include_worktree else ['HEAD']),
                                    cwd=root, capture_output=True, text=True, timeout=30).stdout.split())
        if include_worktree:
            names |= set(subprocess.run(['git', 'ls-files', '--others', '--exclude-standard'], cwd=root,
                                        capture_output=True, text=True, timeout=30).stdout.split())
    except (OSError, subprocess.SubprocessError):
        return False
    return any(n in FILES or n.endswith(('/mcp.json', '/.mcp.json')) for n in names)
