"""t7 — Triple Seven command line.

  t7 setup                      connect this repository (browser sign-in) + your editors
  t7 editors                    add Triple Seven to your editors / AI assistants (once)
  t7 status                     repositories connected on this machine
  t7 scan [--base REF] [--no-fix] [--ci] [--json] [--quiet]
  t7 fix  <SEC-REQ-ID>          apply a verified fix (and its regression test) locally
  t7 list                       fixes available from the last local scan
  t7 doctor                     check access, model provider and test tooling
  t7 logout                     remove the token stored by `t7 setup` for this repository
  t7 command                    apply /t7 decisions typed in a PR comment (CI)
  t7 mcp                        MCP server for Claude Code, Cursor, VS Code, Codex …
"""
import argparse
import getpass
import json
import os
import sys

from . import __version__, credentials, gitops
from .access import WELCOME, AccessError
from .config import Config
from .context import detect

SEV_ICON = {'critical': '🟥', 'high': '🟧', 'medium': '🟨', 'low': '🟦', 'info': '⬜'}


def _print_human(res):
    surfaced = res.get('surfaced') or []
    verdict = (res.get('gate') or {}).get('verdict', 'pass')
    print(f"\nTriple Seven · gate {verdict.upper()} · {res.get('seconds')}s")
    if not surfaced:
        print('No confirmed security issues in this change. ✓')
    for h in surfaced:
        sid = res['sec_ids'].get(h.fingerprint, h.fingerprint[:12])
        fix = (h.fix or {}).get('status', '—')
        loc = f'{h.file_path}:{h.line_start}' if h.file_path else h.component
        print(f"{SEV_ICON.get(h.severity, '')} {sid}  {h.title}\n    {loc}  · proof {h.proof_level}"
              f"  · fix {fix}" + (f"  → t7 fix {sid}" if fix in ('verified', 'partial') else ''))
    if res.get('resolved'):
        print(f"\n✓ {len(res['resolved'])} earlier SEC-REQ(s) resolved by this change.")
    if res.get('run_id'):
        print(f"\nDetails: portal → Triple Seven → Runs ({res['run_id']})")
    else:
        print('\n⚠ Local-only run (T7_ALLOW_OFFLINE): not recorded in the portal.')


def cmd_scan(a):
    from .orchestrator import scan_repo
    from . import gitops
    res = scan_repo(base=gitops.EMPTY_TREE if a.all else a.base, fix=not a.no_fix, ci=a.ci,
                    quiet=a.quiet or a.json)
    if res.get('no_changes') and not a.json:
        print('Nothing changed compared with the base branch. Review the whole repository with:\n'
              '  t7 scan --all')
        return 0
    if a.json:
        print(json.dumps({
            'gate': res.get('gate'), 'run_id': res.get('run_id'), 'seconds': res.get('seconds'),
            'findings': [{'sec_req_id': res['sec_ids'].get(h.fingerprint), **h.to_api(True)}
                         for h in res.get('surfaced') or []],
            'resolved': res.get('resolved', []),
        }, indent=2, default=str))
    else:
        _print_human(res)
    verdict = (res.get('gate') or {}).get('verdict', 'pass')
    if res.get('status_posted'):
        return 0   # the "Triple Seven" commit status carries the gate (can be cleared by /t7 decisions)
    return 1 if verdict == 'block' else 0


def _index(root):
    try:
        return json.loads((root / '.t7' / 'fixes' / 'index.json').read_text())
    except (OSError, ValueError):
        return {}


def cmd_list(a):
    root = gitops.repo_root()
    idx = _index(root)
    if not idx:
        print('No fixes yet. Run `t7 scan` first.')
    for sid, m in idx.items():
        print(f"{sid}  [{m.get('status')}]  {m.get('title')}  ({m.get('file')})")
    return 0


def cmd_fix(a):
    root = gitops.repo_root()
    patch_file = root / '.t7' / 'fixes' / f'{a.id}.patch'
    if not patch_file.exists():
        print(f'No fix found for {a.id}. Run `t7 list`.', file=sys.stderr)
        return 1
    patch = patch_file.read_text()
    ok, err = gitops.apply_patch(root, patch, check_only=True)
    if not ok:
        print(f'Fix does not apply cleanly any more (code changed?):\n{err}', file=sys.stderr)
        return 1
    gitops.apply_patch(root, patch)
    print(f'Applied {a.id}. Review with `git diff`, then commit.')
    return 0


def _root_or_none():
    try:
        return gitops.repo_root()
    except (RuntimeError, OSError):
        return None


def _expiry(cfg_or_entry_expires):
    from .access import days_left
    left = days_left(cfg_or_entry_expires)
    if left is None:
        return ''
    if left <= 0:
        return 'expired'
    return f'valid {round(left)} more days (renews automatically)' if left > 1 else 'expires today'


def cmd_doctor(a):
    root = _root_or_none()
    cfg = Config.load(root)
    print(f't7 {__version__}')
    src = {'env': 'T7_TOKEN', 'setup': 't7 setup'}.get(cfg.token_source, '')
    print(f"token        {'set (' + src + ')' if cfg.token else 'not connected — run `t7 setup`'}")
    print(f'api          {cfg.api_url}')
    print(f"model        {cfg.llm}{' / ' + cfg.llm_model if cfg.llm_model else ''}")
    if root is None:
        print('git          not inside a git repository — cd into the repository you want to review')
    else:
        prof = detect(root, cfg)
        print(f"git          {'ok' if gitops.has_commits(root) else 'no commits yet — fixes need a first commit'}")
        print(f"stack        {', '.join(prof.stack) or 'unknown'}")
        print(f"tests        {prof.test_cmd or '—'}  (L2 proofs {'on' if prof.can_prove else 'off'})")
        print(f"lint/types   {prof.lint_cmd or '—'} / {prof.type_cmd or '—'}")
    from . import editors
    eds = [label for label, _ in editors.detect()]
    print(f"editors      {', '.join(eds) if eds else 'none detected'}  (t7 editors to add Triple Seven)")
    if not cfg.token:
        print('\nRun `t7 setup` in the repository to connect. An active Triple Seven subscription is required.')
        return 1
    from .api import APIError, Byteramp
    try:
        pol = Byteramp(cfg).config()
    except APIError as e:
        print(f'access       FAILED: {e.detail or e.status}')
        return 1
    llm, tok = pol['llm'], pol.get('token') or {}
    print(f"repository   {pol['repository']['full_name']}")
    print(f"access       active · {tok.get('kind', '?')} token, {_expiry(tok.get('expires_at')) or 'no expiry'}")
    print(f"byteramp LLM {'enabled (opt-in recorded)' if llm['byteramp_allowed'] else 'not enabled'}")
    if cfg.llm == 'byteramp' and not llm['byteramp_allowed']:
        print('  → opt in under Triple Seven → Repositories, or set T7_LLM to your own provider.')
    return 0


def _read_token():
    if not sys.stdin.isatty():                       # piped: printf %s "$TOKEN" | t7 setup --token
        return sys.stdin.readline().strip()
    return getpass.getpass('Paste your token (input hidden): ').strip()


def _repo_hint(root):
    if not root:
        return ''
    p = gitops.run(['git', 'remote', 'get-url', 'origin'], root)
    return p.stdout.strip() if p.returncode == 0 and p.stdout.strip() else root.name


def _browser_sign_in(api_url, root):
    """Device authorization: show a code, the developer approves it in the browser."""
    import platform
    import time
    import webbrowser
    from .api import APIError, Byteramp
    try:
        d = Byteramp.public(api_url, 'device/', {'hostname': platform.node()[:120],
                                                 'repo_hint': _repo_hint(root), 'agent_version': __version__})
    except APIError as e:
        print(f'Cannot reach {api_url} ({e.detail or e.status}).', file=sys.stderr)
        return None
    url = d['verification_uri_complete']
    print('Approve this sign-in in your browser:\n')
    print(f'    {url}\n')
    print(f"    Code: {d['user_code']}   (check that the browser shows the same code)\n")
    print('No portal login? Open your invitation e-mail and enter the code there.')
    try:
        if sys.stdout.isatty() and not os.environ.get('T7_NO_BROWSER'):
            webbrowser.open(url)
    except Exception:  # noqa: BLE001 — headless machines: the printed link is enough
        pass
    deadline = time.time() + int(d.get('expires_in') or 900)
    print('Waiting for approval … (Ctrl+C to cancel)', flush=True)
    try:
        while time.time() < deadline:
            time.sleep(int(d.get('interval') or 3))
            try:
                r = Byteramp.public(api_url, 'device/poll/', {'device_code': d['device_code']})
            except APIError as e:
                if e.status == 0:
                    continue                               # transient network error
                print(f'Sign-in failed ({e.detail or e.status}).', file=sys.stderr)
                return None
            st = r.get('status')
            if st == 'approved':
                return r
            if st in ('denied', 'expired', 'done', 'invalid'):
                print(r.get('detail') or f'Sign-in {st}. Run `t7 setup` again.', file=sys.stderr)
                return None
    except KeyboardInterrupt:
        print('\nCancelled.', file=sys.stderr)
        return None
    print('The code expired. Run `t7 setup` again.', file=sys.stderr)
    return None


def _paste_token(cfg):
    from .api import APIError, Byteramp
    token = _read_token()
    if not token.startswith('t7_'):
        print('That does not look like a Triple Seven token (it starts with t7_).', file=sys.stderr)
        return None
    cfg.token, cfg.offline = token, False
    try:
        pol = Byteramp(cfg).config()
    except APIError as e:
        if e.status in (401, 402, 403):
            print(f'Token not accepted ({e.detail or e.status}). Nothing was saved.', file=sys.stderr)
        else:
            print(f'Cannot reach {cfg.api_url} ({e.detail or e.status}). Nothing was saved.', file=sys.stderr)
        return None
    tok = pol.get('token') or {}
    return {'token': token, 'api_url': cfg.api_url, 'repository': pol['repository']['full_name'],
            'expires_at': tok.get('expires_at'), 'kind': tok.get('kind') or 'developer', 'email': ''}


def _yes(question, default=True):
    if not sys.stdin.isatty():
        return default
    ans = input(f"{question} [{'Y/n' if default else 'y/N'}] ").strip().lower()
    return default if not ans else ans in ('y', 'yes', 'j', 'ja')


def _register_editors(assume_yes=False):
    from . import editors
    found = editors.detect()
    if not found:
        print('\nNo supported editor found (VS Code, Cursor, Windsurf, Claude Code, Codex).')
        print('Add Triple Seven by hand later: t7 editors --show')
        return
    print(f"\nEditors on this machine: {', '.join(label for label, _ in found)}")
    if not (assume_yes or _yes('Add Triple Seven to them? (once, for all your repositories)')):
        print('Skipped. Run `t7 editors` any time.')
        return
    icon = {'added': '✓', 'ok': '✓', 'manual': '!'}
    for label, state, detail in editors.register():
        print(f"  {icon.get(state, '·')} {label:<16} {'already set up' if state == 'ok' else detail}")
    print('  Restart open editors (or reload the window) to pick it up.')


def _offer_git_init(assume_yes=False):
    """New project folder (vibe-coding): Triple Seven reviews what git tracks, so offer to
    start a repository here. Never in the home directory or the filesystem root."""
    from pathlib import Path
    here = Path.cwd().resolve()
    if here in (Path.home().resolve(), Path(here.anchor)):
        print('Run t7 setup inside your project folder, not in your home directory:')
        print('  cd path/to/your-project && t7 setup\n')
        return None
    print(f'{here.name} is not a git repository yet. Triple Seven reviews the changes git tracks')
    print('(nothing needs to be committed or pushed).')
    if not (assume_yes or _yes(f'Create a git repository in {here}?')):
        print('Skipped. Run `git init` here (or cd into a repository), then `t7 setup`.\n')
        return None
    p = gitops.run(['git', 'init', '-q'], str(here))
    if p.returncode != 0:
        print(f'git init failed: {p.stderr.strip()}', file=sys.stderr)
        return None
    print('✓ git repository created\n')
    return gitops.repo_root(str(here))


def cmd_setup(a):
    from . import access
    root = None if a.default else _root_or_none()
    print(access.WELCOME.split('\n')[0] + ' — setup\n')
    if root is None and not a.default:
        root = _offer_git_init(a.yes)
        if root is None:
            _register_editors(a.yes)
            return 1
    cfg = Config.load(root)
    if a.api_url:
        cfg.api_url = a.api_url.rstrip('/')
    print(f'Repository: {root}\n' if root else 'Storing a default token for all repositories.\n')
    got = _paste_token(cfg) if a.token else _browser_sign_in(cfg.api_url, root)
    if not got:
        return 1
    # Store the URL this sign-in actually used (it worked), not the server's public hint.
    credentials.store(got['token'], cfg.api_url, got['repository'], root,
                      expires_at=got.get('expires_at'), kind=got.get('kind') or 'developer',
                      email=got.get('email') or '')
    print(f"\n✓ Connected to {got['repository']}" + (f" as {got['email']}" if got.get('email') else ''))
    exp = _expiry(got.get('expires_at'))
    print(f'  Token stored in {credentials.path()} (only readable by you){" · " + exp if exp else ""}.')
    if os.environ.get('T7_TOKEN'):
        print('  Note: T7_TOKEN is set in this shell and takes precedence over the stored token.')
    if not a.no_editors:
        _register_editors(a.yes)
    print('\nYou are set. Next:')
    print('  t7 scan                review your current change (branch + uncommitted work)')
    print('  t7 scan --all          review the whole repository')
    print('  In your editor\'s AI chat: "review my change with Triple Seven"')
    return 0


def cmd_editors(a):
    from . import editors
    if a.show:
        for title, code in editors.manual_snippets():
            print(f'# {title}\n{code}\n')
        return 0
    _register_editors(assume_yes=True)
    return 0


def cmd_status(a):
    rows = credentials.entries()
    if not rows:
        print('No repositories connected on this machine. Run `t7 setup` inside a repository.')
        return 0
    for key, e in rows:
        print(f"{e.get('repository', '?'):<40} {key}\n    {_expiry(e.get('expires_at')) or 'expiry unknown'}")
    return 0


def cmd_logout(a):
    root = None if a.default else _root_or_none()
    credentials.remove(root)
    print('Stored token removed' + (f' for {root}.' if root else ' (default).'))
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog='t7', description='Triple Seven by Byteramp')
    p.add_argument('--version', action='version', version=f't7 {__version__}')
    sub = p.add_subparsers(dest='cmd')
    su = sub.add_parser('setup', help='connect this repository (browser sign-in) and your editors')
    su.add_argument('--token', action='store_true', help='paste a token instead of signing in in the browser')
    su.add_argument('--default', action='store_true', help='store as default for all repositories')
    su.add_argument('--no-editors', action='store_true', help='do not offer to register editors')
    su.add_argument('--yes', '-y', action='store_true', help='register editors without asking')
    su.add_argument('--api-url', help='API base URL (default https://t7.byteramp.se/api)')
    su.set_defaults(fn=cmd_setup)
    ed = sub.add_parser('editors', help='add Triple Seven to VS Code, Cursor, Windsurf, Claude Code, Codex')
    ed.add_argument('--show', action='store_true', help='print the configs instead of writing them')
    ed.set_defaults(fn=cmd_editors)
    sub.add_parser('status', help='repositories connected on this machine').set_defaults(fn=cmd_status)
    lo = sub.add_parser('logout', help='remove the stored token for this repository')
    lo.add_argument('--default', action='store_true')
    lo.set_defaults(fn=cmd_logout)
    s = sub.add_parser('scan', help='review the current change')
    s.add_argument('--base', help='base ref (default: merge-base with origin/main)')
    s.add_argument('--all', action='store_true', help='review the whole repository, not just the change')
    s.add_argument('--no-fix', action='store_true', help='skip fix generation')
    s.add_argument('--ci', action='store_true', help='CI mode (PR comment, committed diff only)')
    s.add_argument('--json', action='store_true')
    s.add_argument('--quiet', action='store_true')
    s.set_defaults(fn=cmd_scan)
    f = sub.add_parser('fix', help='apply a verified fix')
    f.add_argument('id')
    f.set_defaults(fn=cmd_fix)
    sub.add_parser('list', help='list fixes from the last scan').set_defaults(fn=cmd_list)
    sub.add_parser('doctor', help='check setup').set_defaults(fn=cmd_doctor)
    sub.add_parser('command', help='apply /t7 decisions from a PR comment (GitHub Actions)').set_defaults(
        fn=lambda a: __import__('t7.commands', fromlist=['run_command']).run_command())
    sub.add_parser('mcp', help='run as an MCP server (stdio) for IDE assistants').set_defaults(
        fn=lambda a: __import__('t7.mcp', fromlist=['serve']).serve() or 0)
    a = p.parse_args(argv)
    if not getattr(a, 'fn', None):
        print(WELCOME)
        sys.exit(0)
    try:
        sys.exit(a.fn(a))
    except AccessError as e:
        print(f't7: {e}', file=sys.stderr)
        sys.exit(2)


if __name__ == '__main__':
    main()
