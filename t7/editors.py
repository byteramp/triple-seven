"""Register `t7 mcp` once, user-wide, in the editors / AI assistants on this machine.

One registration serves every repository: the server finds the open workspace
itself (MCP roots, the editor's working directory, or a repo_path argument) and
uses the token `t7 setup` stored for that repository. No token is ever written
into an editor config.

Supported: VS Code (+ Insiders, GitHub Copilot agent mode), Cursor, Windsurf,
Claude Code, Codex, Claude Desktop, Gemini CLI, Antigravity, Kiro, Zed, Cline.
Perplexity (Mac) adds local MCP servers in its own UI — see `t7 editors --show`. Existing configs are merged, never overwritten; a config we
cannot parse safely (e.g. JSON with comments) is left alone and the manual
snippet is shown instead.
"""
import json
import os
import platform
import re
import shutil
import subprocess
import sys
from pathlib import Path

NAME = 'triple-seven'


def t7_command():
    """Absolute path of the t7 launcher, so editors started from the Dock (without the
    shell's PATH) still find it. pipx's ~/.local/bin/t7 survives upgrades."""
    found = shutil.which('t7')
    if found:
        return found
    argv0 = Path(sys.argv[0])
    if argv0.name == 't7' and argv0.exists():
        return str(argv0.absolute())
    return 't7'


def _home():
    return Path.home()


def _vscode_user_dirs():
    system = platform.system()
    if system == 'Darwin':
        base = _home() / 'Library' / 'Application Support'
    elif system == 'Windows':
        base = Path(os.environ.get('APPDATA') or _home() / 'AppData' / 'Roaming')
    else:
        base = Path(os.environ.get('XDG_CONFIG_HOME') or _home() / '.config')
    return [('VS Code', base / 'Code' / 'User'), ('VS Code Insiders', base / 'Code - Insiders' / 'User')]


def _read_json(path):
    """dict, {} for a missing/empty file, or None if it cannot be parsed safely."""
    try:
        text = path.read_text()
    except FileNotFoundError:
        return {}
    except OSError:
        return None
    if not text.strip():
        return {}
    try:
        data = json.loads(text)
    except ValueError:
        return None          # JSONC with comments / trailing commas: do not risk rewriting it
    return data if isinstance(data, dict) else None


def _write_json(path, data):
    path.parent.mkdir(parents=True, exist_ok=True)
    tmp = path.with_suffix(path.suffix + '.t7tmp')
    tmp.write_text(json.dumps(data, indent=2) + '\n')
    os.replace(tmp, path)


def _json_target(label, path, section, entry):
    data = _read_json(path)
    if data is None:
        return label, 'manual', f'{path} could not be read safely (comments?). Add it by hand: t7 editors --show'
    servers = data.setdefault(section, {})
    if not isinstance(servers, dict):
        return label, 'manual', f'unexpected "{section}" in {path}'
    if servers.get(NAME) == entry:
        return label, 'ok', 'already set up'
    servers[NAME] = entry
    _write_json(path, data)
    return label, 'added', str(path)


def _vscode_target(label, user_dir, entry):
    result = _json_target(label, user_dir / 'mcp.json', 'servers', entry)
    if result[1] != 'manual':
        return result
    executable = shutil.which('code-insiders' if 'Insiders' in label else 'code')
    if not executable and platform.system() == 'Darwin':
        app = 'Visual Studio Code - Insiders' if 'Insiders' in label else 'Visual Studio Code'
        candidate = Path('/Applications') / (app + '.app') / 'Contents/Resources/app/bin/code'
        if candidate.is_file():
            executable = str(candidate)
    if not executable:
        return result
    try:
        completed = subprocess.run(
            [executable, '--user-data-dir', str(user_dir.parent), '--add-mcp',
             json.dumps({'name': NAME, **entry})],
            capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError):
        return result
    if completed.returncode:
        return result
    return label, 'added', 'Registered through VS Code; existing comments preserved'


def detect():
    """[(label, register_fn)] for the editors that are installed."""
    cmd = t7_command()
    found = []
    for label, user_dir in _vscode_user_dirs():
        if user_dir.exists():
            entry = {'type': 'stdio', 'command': cmd, 'args': ['mcp', '--assistant', 'copilot']}
            found.append((label, lambda l=label, d=user_dir, e=entry: _vscode_target(l, d, e)))
    if shutil.which('copilot'):
        entry = {'type': 'stdio', 'command': cmd, 'args': ['mcp', '--assistant', 'copilot']}
        found.append(('Copilot', lambda e=entry: _json_target('Copilot', _home() / '.copilot' / 'mcp-config.json',
                                                           'mcpServers', e)))
    if (_home() / '.cursor').exists():
        entry = {'command': cmd, 'args': ['mcp']}
        found.append(('Cursor', lambda e=entry: _json_target('Cursor', _home() / '.cursor' / 'mcp.json',
                                                            'mcpServers', e)))
    ws = _home() / '.codeium' / 'windsurf'
    if ws.exists():
        entry = {'command': cmd, 'args': ['mcp']}
        found.append(('Windsurf', lambda e=entry: _json_target('Windsurf', ws / 'mcp_config.json',
                                                              'mcpServers', e)))
    if shutil.which('claude'):
        found.append(('Claude Code', lambda: _claude_code(cmd)))
    std = {'command': cmd, 'args': ['mcp']}
    cd = _claude_desktop_dir()
    if cd.exists():
        found.append(('Claude Desktop', lambda: _json_target('Claude Desktop', cd / 'claude_desktop_config.json',
                                                            'mcpServers', std)))
    gem = _home() / '.gemini'
    if (gem / 'settings.json').exists() or shutil.which('gemini'):
        # Gemini CLI: long reviews → generous tool timeout (ms).
        found.append(('Gemini CLI', lambda: _json_target('Gemini CLI', gem / 'settings.json', 'mcpServers',
                                                        {**std, 'timeout': 900000})))
    if (gem / 'config').exists() or (gem / 'antigravity').exists() or Path('/Applications/Antigravity.app').exists():
        ag = gem / 'config' / 'mcp_config.json'
        if not ag.exists() and (gem / 'antigravity' / 'mcp_config.json').exists():
            ag = gem / 'antigravity' / 'mcp_config.json'          # older Antigravity versions
        found.append(('Antigravity', lambda p=ag: _json_target('Antigravity', p, 'mcpServers', {**std, 'timeoutSeconds': 900})))
    kiro = _home() / '.kiro'
    if kiro.exists():
        found.append(('Kiro', lambda: _json_target('Kiro', kiro / 'settings' / 'mcp.json', 'mcpServers', std)))
    zed = _home() / '.config' / 'zed'
    if zed.exists():
        found.append(('Zed', lambda: _json_target('Zed', zed / 'settings.json', 'context_servers',
                                                 {**std, 'env': {}})))
    for label, user_dir in _vscode_user_dirs():
        cline = user_dir / 'globalStorage' / 'saoudrizwan.claude-dev' / 'settings'
        if cline.exists():
            found.append((f'Cline ({label})', lambda p=cline / 'cline_mcp_settings.json', l=label:
                          _json_target(f'Cline ({l})', p, 'mcpServers', std)))
    if (_home() / '.codex').exists() or shutil.which('codex'):
        found.append(('Codex', lambda: _codex(cmd)))
    return found


def _claude_desktop_dir():
    system = platform.system()
    if system == 'Darwin':
        return _home() / 'Library' / 'Application Support' / 'Claude'
    if system == 'Windows':
        return Path(os.environ.get('APPDATA') or _home() / 'AppData' / 'Roaming') / 'Claude'
    return _home() / '.config' / 'Claude'


def _claude_code(cmd):
    claude = shutil.which('claude')
    try:
        if subprocess.run([claude, 'mcp', 'get', NAME], capture_output=True, timeout=30).returncode == 0:
            return 'Claude Code', 'ok', 'already set up'
        p = subprocess.run([claude, 'mcp', 'add', '--scope', 'user', NAME, '--', cmd, 'mcp'],
                           capture_output=True, text=True, timeout=60)
    except (OSError, subprocess.SubprocessError) as e:
        return 'Claude Code', 'manual', f'claude mcp add failed ({e})'
    if p.returncode != 0:
        return 'Claude Code', 'manual', (p.stderr or p.stdout).strip()[:200]
    return 'Claude Code', 'added', 'user scope (all projects)'


def _codex(cmd):
    path = _home() / '.codex' / 'config.toml'
    try:
        text = path.read_text() if path.exists() else ''
    except OSError as e:
        return 'Codex', 'manual', str(e)
    if re.search(r'^\[mcp_servers\.["\']?triple-seven["\']?\]', text, re.M):
        return 'Codex', 'ok', 'already set up'
    block = (f'\n[mcp_servers.{NAME}]\ncommand = {json.dumps(cmd)}\nargs = ["mcp"]\n'
             '# Fix + proof runs can take minutes on large changes\ntool_timeout_sec = 900\n')
    path.parent.mkdir(parents=True, exist_ok=True)
    with open(path, 'a') as fh:
        fh.write(('\n' if text and not text.endswith('\n') else '') + block)
    return 'Codex', 'added', str(path)


def register(only=None):
    out = []
    for label, fn in detect():
        if only and label.lower() not in only:
            continue
        try:
            out.append(fn())
        except Exception as e:  # noqa: BLE001 — one editor must not stop the others
            out.append((label, 'manual', f'{type(e).__name__}: {e}'))
    return out


def manual_snippets():
    cmd = t7_command()
    j = {'command': cmd, 'args': ['mcp']}
    return [
        ('VS Code — user mcp.json (Command Palette → "MCP: Open User Configuration")',
         json.dumps({'servers': {NAME: {'type': 'stdio', **j, 'args': ['mcp', '--assistant', 'copilot']}}}, indent=2)),
        ('Copilot — ~/.copilot/mcp-config.json',
         json.dumps({'mcpServers': {NAME: {**j, 'args': ['mcp', '--assistant', 'copilot']}}}, indent=2)),
        ('Cursor — ~/.cursor/mcp.json', json.dumps({'mcpServers': {NAME: j}}, indent=2)),
        ('Windsurf — ~/.codeium/windsurf/mcp_config.json', json.dumps({'mcpServers': {NAME: j}}, indent=2)),
        ('Claude Code — terminal', f'claude mcp add --scope user {NAME} -- {cmd} mcp'),
        ('Claude Desktop — Settings → Developer → Edit Config (claude_desktop_config.json)',
         json.dumps({'mcpServers': {NAME: j}}, indent=2) + '\n# Desktop apps see no workspace: ask "review <absolute path> with Triple Seven".'),
        ('Gemini CLI — ~/.gemini/settings.json', json.dumps({'mcpServers': {NAME: {**j, 'timeout': 900000}}}, indent=2)),
        ('Antigravity — ~/.gemini/config/mcp_config.json (Agent panel → MCP Servers → View raw config)',
         json.dumps({'mcpServers': {NAME: j}}, indent=2)),
        ('Kiro — ~/.kiro/settings/mcp.json', json.dumps({'mcpServers': {NAME: j}}, indent=2)),
        ('Zed — settings.json (Command Palette → "zed: open settings")',
         json.dumps({'context_servers': {NAME: {**j, 'env': {}}}}, indent=2)),
        ('Perplexity (Mac) — Settings → Connectors → install the helper → Add Connector → Advanced',
         json.dumps({'mcpServers': {NAME: j}}, indent=2) + '\n# Ask: "review <absolute path to the repository> with Triple Seven".'),
        ('Codex — ~/.codex/config.toml',
         f'[mcp_servers.{NAME}]\ncommand = {json.dumps(cmd)}\nargs = ["mcp"]\ntool_timeout_sec = 900'),
    ]
