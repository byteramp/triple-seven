"""`t7 mcp` — Model Context Protocol server (stdio, JSON-RPC 2.0, stdlib only).

Lets a developer's AI assistant (Claude Code, Cursor, VS Code Copilot, Codex,
Windsurf, Zed …) run Triple Seven on the open repository:

    t7_scan        review the current change (threat model → triage → verified fixes → proof)
    t7_findings    list findings + fixes from the last scan
    t7_explain     full detail for one finding (attack, trace, proof, fix checks)
    t7_show_fix    the verified patch for one finding (unified diff)
    t7_apply_fix   apply a verified fix (and its regression test) to the working tree
    t7_doctor      check token, model provider and test tooling

The server runs on the developer's machine, in the repository. Everything the
agent sends to Byteramp is the same metadata as in CI — never source code
(unless the repository opted in to Byteramp models).
Stdout carries ONLY protocol messages; all logging goes to stderr.
"""
import contextlib
import io
import json
import os
import sys
import traceback

from . import __version__, gitops

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
                'fix': {'type': 'boolean', 'description': 'Generate and verify fixes (default true)'},
            },
        },
        'annotations': {'readOnlyHint': True, 'openWorldHint': True},
    },
    {
        'name': 't7_findings',
        'title': 'Triple Seven: findings from the last scan',
        'description': 'List the findings, proof levels and fix status from the most recent t7 scan.',
        'inputSchema': {'type': 'object', 'properties': {}},
        'annotations': {'readOnlyHint': True},
    },
    {
        'name': 't7_explain',
        'title': 'Triple Seven: explain a finding',
        'description': 'Explain one finding: why it matters, the attack, the code trace, proof and fix checks.',
        'inputSchema': {'type': 'object', 'required': ['id'],
                        'properties': {'id': {'type': 'string', 'description': 'SEC-REQ id or fingerprint prefix'}}},
        'annotations': {'readOnlyHint': True},
    },
    {
        'name': 't7_show_fix',
        'title': 'Triple Seven: show the verified fix',
        'description': 'Return the verified patch (unified diff, incl. regression test) for a finding.',
        'inputSchema': {'type': 'object', 'required': ['id'],
                        'properties': {'id': {'type': 'string'}}},
        'annotations': {'readOnlyHint': True},
    },
    {
        'name': 't7_apply_fix',
        'title': 'Triple Seven: apply a verified fix',
        'description': 'Apply the verified fix (and its regression test) to the working tree. '
                       'Does not commit. Review with git diff afterwards.',
        'inputSchema': {'type': 'object', 'required': ['id'],
                        'properties': {'id': {'type': 'string'}}},
        'annotations': {'readOnlyHint': False, 'destructiveHint': False, 'idempotentHint': False},
    },
    {
        'name': 't7_doctor',
        'title': 'Triple Seven: check setup',
        'description': 'Check token, model provider, detected stack and test tooling.',
        'inputSchema': {'type': 'object', 'properties': {}},
        'annotations': {'readOnlyHint': True},
    },
]


def _log(*a):
    print('[t7-mcp]', *a, file=sys.stderr, flush=True)


def _root():
    return gitops.repo_root(os.environ.get('T7_REPO') or '.')


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
    return '\n'.join(lines)


def tool_scan(args):
    from .orchestrator import scan_repo
    buf = io.StringIO()
    # Never let anything reach stdout (it is the protocol channel).
    with contextlib.redirect_stdout(buf):
        res = scan_repo(base=args.get('base'), fix=args.get('fix', True), quiet=True, client='mcp')
    root = _root()
    return _text(_fmt_findings(_last(root)) + (
        f"\nPortal run: {res.get('run_id')}" if res.get('run_id') else ''))


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
        name = params.get('name')
        fn = HANDLERS.get(name)
        if not fn:
            return err(-32602, f'Unknown tool: {name}')
        try:
            out = fn(params.get('arguments') or {})
            result, is_error = (out if isinstance(out, tuple) else (out, False))
            return ok({**result, 'isError': bool(is_error)})
        except SystemExit as e:
            return ok({**_text(f't7 stopped: exit {e.code}. Run t7_doctor.'), 'isError': True})
        except Exception as e:  # noqa: BLE001 — tool errors are results, not protocol errors
            _log(traceback.format_exc())
            return ok({**_text(f'{type(e).__name__}: {e}'), 'isError': True})
    return err(-32601, f'Method not found: {method}')


def serve(stdin=None, stdout=None):
    stdin, stdout = stdin or sys.stdin, stdout or sys.stdout
    _log(f'triple-seven {__version__} ready')
    for line in stdin:
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
            stdout.write(json.dumps(replies if isinstance(msg, list) else replies[0]) + '\n')
            stdout.flush()
