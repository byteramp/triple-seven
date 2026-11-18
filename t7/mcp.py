"""`t7 mcp` — Model Context Protocol server (stdio, JSON-RPC 2.0, stdlib only).

Lets a developer's AI assistant (Claude Code, Cursor, VS Code Copilot, Codex,
Windsurf, Zed …) run Triple Seven on the open repository:

    t7_scan        review the current change (threat model → triage → verified fixes → proof)
    t7_findings    list findings + fixes from the last scan
    t7_explain     full detail for one finding (attack, trace, proof, fix checks)
    t7_show_fix    the verified patch for one finding (unified diff)
    t7_apply_fix   apply a verified fix (and its regression test) to the working tree
    t7_doctor      check token, model provider and test tooling

The server runs on the developer's machine. Code excerpts are sent to the selected
model provider. Byteramp retains review metadata and processes opt-in model prompts
transiently. Metadata redaction is best effort.
Stdout carries ONLY protocol messages; all logging goes to stderr.
"""
import contextlib
import io
import json
import os
import sys
import threading
import traceback

from . import __version__, gitops
from .access import AccessError

PROTOCOL_VERSION = '2025-06-18'
SUPPORTED_VERSIONS = {'2024-11-05', '2025-03-26', '2025-06-18'}

TOOLS = [
    {
        'name': 't7_scan',
        'title': 'Triple Seven: review my change',
        'description': (
            'Security-review the current branch and uncommitted work in this repository: '
            'threat model the change, confirm findings against the code, generate fixes that '
            'are verified in an isolated worktree (lint, types, tests, independent re-check) '
            'and prove them with a regression test when possible. Can take several minutes.'),
        'inputSchema': {
            'type': 'object',
            'properties': {
                'base': {'type': 'string', 'description': 'Base ref (default: merge-base with origin/main)'},
                'all': {'type': 'boolean', 'description': 'Review the whole repository instead of the change'},
                'fix': {'type': 'boolean', 'description': 'Generate and verify fixes (default true)'},
                'repo_path': {'type': 'string', 'description': 'Absolute path of the repository / workspace root. Pass it when the server may not see your workspace.'},
            },
        },
        'annotations': {'readOnlyHint': True, 'openWorldHint': True},
    },
    {
        'name': 't7_findings',
        'title': 'Triple Seven: findings from the last scan',
        'description': 'List the findings, proof levels and fix status from the most recent t7 scan.',
        'inputSchema': {'type': 'object', 'properties': {'repo_path': {'type': 'string'}}},
        'annotations': {'readOnlyHint': True},
    },
    {
        'name': 't7_explain',
        'title': 'Triple Seven: explain a finding',
        'description': 'Explain one finding: why it matters, the attack, the code trace, proof and fix checks.',
        'inputSchema': {'type': 'object', 'required': ['id'],
                        'properties': {'id': {'type': 'string', 'description': 'SEC-REQ id or fingerprint prefix'},
                                       'repo_path': {'type': 'string'}}},
        'annotations': {'readOnlyHint': True},
    },
    {
        'name': 't7_show_fix',
        'title': 'Triple Seven: show the verified fix',
        'description': 'Return the verified patch (unified diff, incl. regression test) for a finding.',
        'inputSchema': {'type': 'object', 'required': ['id'],
                        'properties': {'id': {'type': 'string'}, 'repo_path': {'type': 'string'}}},
        'annotations': {'readOnlyHint': True},
    },
    {
        'name': 't7_apply_fix',
        'title': 'Triple Seven: apply a verified fix',
        'description': 'Apply the verified fix (and its regression test) to the working tree. '
                       'Does not commit. Review with git diff afterwards.',
        'inputSchema': {'type': 'object', 'required': ['id'],
                        'properties': {'id': {'type': 'string'}, 'repo_path': {'type': 'string'}}},
        'annotations': {'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': False},
    },
    {
        'name': 't7_doctor',
        'title': 'Triple Seven: check setup',
        'description': 'Check access, model provider, detected stack and test tooling.',
        'inputSchema': {'type': 'object', 'properties': {'repo_path': {'type': 'string'}}},
        'annotations': {'readOnlyHint': True},
    },
]


class _Session:
    """The live stdio channel. Kept separately because tool calls redirect sys.stdout."""
    stdin = None
    stdout = None
    client_caps = {}
    client_info = {}
    progress_token = None
    repo_path = ''
    progress = 0
    seq = 0
    lock = threading.Lock()


SESSION = _Session()


def _write(obj):
    with SESSION.lock:
        SESSION.stdout.write(json.dumps(obj) + '\n')
        SESSION.stdout.flush()


def client_can_sample():
    return 'sampling' in (SESSION.client_caps or {})


_SAMPLE_LOCK = threading.Lock()


def _request(method, params):
    """Send a request to the MCP client and wait for its response (answering pings meanwhile)."""
    with _SAMPLE_LOCK:
        SESSION.seq += 1
        rid = f't7-req-{SESSION.seq}'
        _write({'jsonrpc': '2.0', 'id': rid, 'method': method, 'params': params})
        while True:
            line = SESSION.stdin.readline()
            if not line:
                raise RuntimeError('MCP client closed the connection')
            line = line.strip()
            if not line:
                continue
            try:
                msg = json.loads(line)
            except ValueError:
                continue
            if msg.get('id') == rid and 'method' not in msg:
                if 'error' in msg:
                    raise RuntimeError(f"{method} refused: {msg['error'].get('message', msg['error'])}")
                return msg.get('result') or {}
            if 'method' in msg and msg.get('id') is not None:
                if msg['method'] == 'ping':
                    _write({'jsonrpc': '2.0', 'id': msg['id'], 'result': {}})
                else:
                    _write({'jsonrpc': '2.0', 'id': msg['id'],
                            'error': {'code': -32000, 'message': 'Triple Seven is busy with a scan'}})


class SamplingError(RuntimeError):
    """A rejected editor request must not be retried or treated as model output."""
    retryable = False


_MODEL_ACCESS_HELP = (
    'No review completed. In Copilot Chat, choose an available model and approve '
    'Triple Seven model access; sign in to your AI service if required. '
    'If it still fails, check the editor model request log for the provider error '
    '(for example model_not_supported). For editor-managed connections, also check '
    'MCP: List Servers > triple-seven > Configure Model Access. '
    'Chat model availability does not guarantee MCP model access. '
    'T7 has not switched to another provider.'
)


def sample(system, prompt, max_tokens=2000, temperature=0.1):
    """MCP sampling: ask the editor (VS Code Copilot, …) to run the completion with the model
    the developer already uses."""
    try:
        res = _request('sampling/createMessage', {
            'messages': [{'role': 'user', 'content': {'type': 'text', 'text': prompt}}],
            'systemPrompt': system or '', 'maxTokens': int(max_tokens), 'temperature': temperature,
            'includeContext': 'none',
            'modelPreferences': {'intelligencePriority': 0.8, 'speedPriority': 0.4, 'costPriority': 0.3},
        })
    except RuntimeError as error:
        # Do not persist arbitrary provider error bodies: they can include source text.
        code = ' (model_not_supported)' if 'model_not_supported' in str(error) else ''
        raise SamplingError(f'Editor model request failed{code}. {_MODEL_ACCESS_HELP}') from None
    if not isinstance(res, dict):
        raise SamplingError(f'Editor returned an invalid model response. {_MODEL_ACCESS_HELP}')
    reason = res.get('stopReason', '')
    if reason in ('cancelled', 'canceled', 'refusal', 'error') or res.get('role') != 'assistant':
        # Copilot can return a user-role cancellation after an upstream model failure.
        # Its text is a status message, not a completion to feed to JSON repair.
        raise SamplingError(f'Editor model request was cancelled, rejected or failed. {_MODEL_ACCESS_HELP}')
    if reason == 'maxTokens':
        raise SamplingError('Editor model response reached its output limit. No review completed. '
                            'Choose a model with enough output capacity, then rerun T7.')
    content = res.get('content') or {}
    blocks = content if isinstance(content, list) else [content]
    text = '\n'.join(block['text'] for block in blocks
                     if isinstance(block, dict) and block.get('type') == 'text'
                     and isinstance(block.get('text'), str))
    if not text.strip():
        raise SamplingError(f'Editor returned no model text. {_MODEL_ACCESS_HELP}')
    return text, res.get('model', '')


def _ensure_repo_cwd():
    """Run inside the developer's repository: T7_REPO, else the cwd if it is a git repo,
    else the workspace root the editor reports (MCP roots)."""
    from urllib.parse import unquote, urlparse
    target = SESSION.repo_path or os.environ.get('T7_REPO')
    if not target and gitops.run(['git', 'rev-parse', '--show-toplevel'], '.').returncode != 0 \
            and 'roots' in (SESSION.client_caps or {}):
        try:
            roots = _request('roots/list', {}).get('roots') or []
            uri = next((r.get('uri', '') for r in roots if r.get('uri', '').startswith('file://')), '')
            target = unquote(urlparse(uri).path) if uri else ''
        except Exception as e:  # noqa: BLE001
            _log('roots/list failed:', e)
    if target and os.path.isdir(target):
        os.chdir(target)


def on_step(node):
    """Tracer hook: forward finished steps as MCP progress so the developer sees what happens."""
    if SESSION.progress_token is None or node.get('status') not in ('done', 'failed', 'skipped'):
        return
    SESSION.progress += 1
    _write({'jsonrpc': '2.0', 'method': 'notifications/progress', 'params': {
        'progressToken': SESSION.progress_token, 'progress': SESSION.progress,
        'message': f"{node.get('agent')}: {node.get('title')}"[:200]}})


def _log(*a):
    print('[t7-mcp]', *a, file=sys.stderr, flush=True)


def _root():
    _ensure_repo_cwd()
    return gitops.repo_root('.')


def _last(root):
    try:
        return json.loads((root / '.t7' / 'last_scan.json').read_text())
    except (OSError, ValueError):
        return None


def _find(root, ident):
    last = _last(root) or {}
    ident = (ident or '').strip()
    for f in last.get('findings', []):
        if ident and (ident == f.get('sec_req_id') or f.get('fingerprint', '').startswith(ident)):
            return f
    return None


def _text(s):
    return {'content': [{'type': 'text', 'text': s}]}


def _fmt_findings(last):
    if not last:
        return 'No scan yet. Run t7_scan first.'
    lines = [f"Gate: {last.get('gate', {}).get('verdict', 'pass').upper()} · "
             f"{len(last.get('findings', []))} finding(s) · {last.get('seconds')}s"]
    for f in last.get('findings', []):
        loc = f"{f.get('file_path')}:{f.get('line_start')}" if f.get('file_path') else f.get('component', '')
        fx = (f.get('fix') or {}).get('status', 'none')
        lines.append(f"- {f.get('sec_req_id') or f['fingerprint'][:12]} [{f['severity']}] {f['title']} "
                     f"({loc}) · proof {f['proof_level']} · fix {fx}")
    if last.get('resolved'):
        lines.append(f"Resolved by this change: {len(last['resolved'])}")
    if last.get('unconfirmed'):
        lines.append(f"{last['unconfirmed']} plausible but unconfirmed hypothesis(es) kept for review in the "
                     "portal (status: needs validation) — not findings, not part of the gate.")
    return '\n'.join(lines)


LOCAL_ONLY = '\n\n⚠ Local-only run (T7_ALLOW_OFFLINE): not recorded in the Triple Seven portal.'


def tool_scan(args):
    from . import trace
    from .orchestrator import scan_repo
    # The editor's model (MCP sampling) is used only when the organisation's model policy says
    # so — never automatically (plan §0c). t7 applies the policy inside scan_repo.
    trace.ON_STEP = on_step
    _ensure_repo_cwd()
    if gitops.run(['git', 'rev-parse', '--show-toplevel'], '.').returncode != 0:
        return _text(f'No git repository found (working directory: {os.getcwd()}). Call t7_scan again '
                     'with repo_path set to the absolute path of the workspace / repository root.'), True
    buf = io.StringIO()
    # Never let anything reach stdout (it is the protocol channel).
    with contextlib.redirect_stdout(buf):
        res = scan_repo(base=gitops.EMPTY_TREE if args.get('all') else args.get('base'),
                        fix=args.get('fix', True), quiet=True, client='mcp',
                        can_sample=client_can_sample())
    if res.get('no_changes'):
        return _text('Nothing changed compared with the base branch. Call t7_scan with all=true to '
                     'review the whole repository.' + ('' if res.get('run_id') else LOCAL_ONLY))
    root = _root()
    head = f"Analysed with: {res.get('analysed_with')}\n"
    if res.get('update_notice'):
        head += f"Note for the developer: {res['update_notice']}\n"
    note = (f"\nPortal run: {res.get('run_id')}" if res.get('run_id') else
            LOCAL_ONLY)
    coverage = res.get('coverage') or {}
    if coverage:
        head += (f"Coverage: {coverage['reviewed_files']}/{coverage['changed_files']} changed files "
                 f"reviewed; {len(coverage['excluded_files'])} excluded.\n")
        if coverage['excluded_files']:
            head += "Excluded: " + ', '.join(coverage['excluded_files']) + "\n"
    return _text(head + _fmt_findings(_last(root)) + note)


def tool_findings(args):
    return _text(_fmt_findings(_last(_root())))


def tool_explain(args):
    f = _find(_root(), args.get('id'))
    if not f:
        return _text(f"No finding {args.get('id')!r} in the last scan."), True
    fix = f.get('fix') or {}
    parts = [
        f"{f.get('sec_req_id') or f['fingerprint'][:12]} — {f['title']} [{f['severity']}]",
        f"Location: {f.get('file_path')}:{f.get('line_start')}" if f.get('file_path') else f"Component: {f.get('component')}",
        f"Classification: {', '.join(x for x in (f.get('cwe'), f.get('owasp'), f.get('llm_code'), f.get('stride')) if x)}",
        f"Confidence: {f['confidence']} · proof {f['proof_level']}",
        '', f"Why: {f.get('description', '')}", f"Attack: {f.get('attack_scenario', '')}",
        f"Requirement: {f.get('recommendation', '')}",
    ]
    if f.get('trace'):
        parts += ['', 'Trace:'] + [f"  {i + 1}. {t.get('file')}:{t.get('line')} — {t.get('label')}"
                                   for i, t in enumerate(f['trace'])]
    if fix:
        parts += ['', f"Fix: {fix.get('status')} after {fix.get('attempts')} attempt(s) — "
                      + ', '.join(f'{k} {v}' for k, v in (fix.get('checks') or {}).items()),
                  fix.get('explanation', '')]
    return _text('\n'.join(p for p in parts if p is not None))


def _patch_path(root, f):
    sid = f.get('sec_req_id') or f['fingerprint'][:12]
    return root / '.t7' / 'fixes' / f'{sid}.patch'


def tool_show_fix(args):
    root = _root()
    f = _find(root, args.get('id'))
    if not f or not _patch_path(root, f).exists():
        return _text(f"No verified fix for {args.get('id')!r}."), True
    return _text(_patch_path(root, f).read_text())


def tool_apply_fix(args):
    root = _root()
    f = _find(root, args.get('id'))
    if not f or not _patch_path(root, f).exists():
        return _text(f"No verified fix for {args.get('id')!r}."), True
    patch = _patch_path(root, f).read_text()
    ok, err = gitops.apply_patch(root, patch, check_only=True)
    if not ok:
        return _text(f'The fix no longer applies cleanly (code changed since the scan):\n{err}'), True
    gitops.apply_patch(root, patch)
    return _text(f"Applied {f.get('sec_req_id') or f['fingerprint'][:12]}. Not committed — review with git diff.")


def tool_doctor(args):
    from .cli import cmd_doctor
    _ensure_repo_cwd()
    buf = io.StringIO()
    with contextlib.redirect_stdout(buf):
        try:
            cmd_doctor(None)
        except SystemExit:
            pass
    return _text(buf.getvalue())


HANDLERS = {'t7_scan': tool_scan, 't7_findings': tool_findings, 't7_explain': tool_explain,
            't7_show_fix': tool_show_fix, 't7_apply_fix': tool_apply_fix, 't7_doctor': tool_doctor}


def handle(msg):
    """Return a response dict, or None for notifications."""
    mid, method, params = msg.get('id'), msg.get('method'), msg.get('params') or {}
    if mid is None:                                   # notification
        return None

    def ok(result):
        return {'jsonrpc': '2.0', 'id': mid, 'result': result}

    def err(code, message):
        return {'jsonrpc': '2.0', 'id': mid, 'error': {'code': code, 'message': message}}

    if method == 'initialize':
        SESSION.client_caps = params.get('capabilities') or {}
        SESSION.client_info = params.get('clientInfo') or {}
        v = params.get('protocolVersion')
        return ok({
            'protocolVersion': v if v in SUPPORTED_VERSIONS else PROTOCOL_VERSION,
            'capabilities': {'tools': {'listChanged': False}},
            'serverInfo': {'name': 'triple-seven', 'title': 'Triple Seven by Byteramp',
                           'version': __version__},
            'instructions': ('Use t7_scan to security-review the developer\'s current change before '
                             'they open or merge a pull request. Prefer applying fixes marked '
                             '"verified". Never invent findings; report what t7 returns.'),
        })
    if method == 'ping':
        return ok({})
    if method == 'tools/list':
        return ok({'tools': TOOLS})
    if method == 'tools/call':
        SESSION.progress_token = (params.get('_meta') or {}).get('progressToken')
        SESSION.repo_path = str((params.get('arguments') or {}).get('repo_path') or '')
        SESSION.progress = 0
        name = params.get('name')
        fn = HANDLERS.get(name)
        if not fn:
            return err(-32602, f'Unknown tool: {name}')
        try:
            out = fn(params.get('arguments') or {})
            result, is_error = (out if isinstance(out, tuple) else (out, False))
            return ok({**result, 'isError': bool(is_error)})
        except AccessError as e:
            where = os.getcwd()
            return ok({**_text(f'Triple Seven: no access for {where}.\n{e}\n\n'
                               f'Ask the developer to run this in a terminal and enter the setup code from '
                               f'their e-mail (or sign in as an administrator), then retry:\n  t7 setup\n'
                               'Do not attempt the security review yourself.'), 'isError': True})
        except SystemExit as e:
            return ok({**_text(f't7 stopped: exit {e.code}. Run t7_doctor.'), 'isError': True})
        except Exception as e:  # noqa: BLE001 — tool errors are results, not protocol errors
            _log(traceback.format_exc())
            return ok({**_text(f'{type(e).__name__}: {e}'), 'isError': True})
    return err(-32601, f'Method not found: {method}')


def serve(stdin=None, stdout=None):
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    SESSION.stdin, SESSION.stdout = stdin, stdout
    _log(f'triple-seven {__version__} ready')
    while True:
        line = stdin.readline()
        if not line:
            break
        line = line.strip()
        if not line:
            continue
        try:
            msg = json.loads(line)
        except ValueError:
            stdout.write(json.dumps({'jsonrpc': '2.0', 'id': None,
                                     'error': {'code': -32700, 'message': 'Parse error'}}) + '\n')
            stdout.flush()
            continue
        batch = msg if isinstance(msg, list) else [msg]
        replies = [r for r in (handle(m) for m in batch if isinstance(m, dict)) if r]
        if replies:
            with SESSION.lock:
                stdout.write(json.dumps(replies if isinstance(msg, list) else replies[0]) + '\n')
                stdout.flush()
