"""t7 — Triple Seven command line.

  t7 scan [--base REF] [--no-fix] [--ci] [--json] [--quiet]
  t7 fix  <SEC-REQ-ID>          apply a verified fix (and its regression test) locally
  t7 list                       fixes available from the last local scan
  t7 doctor                     check token, model provider and test tooling
  t7 command                    apply /t7 decisions typed in a PR comment (CI)
  t7 mcp                        MCP server for Claude Code, Cursor, VS Code, Codex …
"""
import argparse
import json
import sys

from . import __version__, gitops
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


def cmd_scan(a):
    from .orchestrator import scan_repo
    res = scan_repo(base=a.base, fix=not a.no_fix, ci=a.ci, quiet=a.quiet or a.json)
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


def cmd_doctor(a):
    root = gitops.repo_root()
    cfg = Config.load(root)
    prof = detect(root, cfg)
    print(f't7 {__version__}')
    print(f"token        {'set' if cfg.token else 'MISSING (T7_TOKEN) — offline mode'}")
    print(f'api          {cfg.api_url}')
    print(f"model        {cfg.llm}{' / ' + cfg.llm_model if cfg.llm_model else ''}")
    print(f"stack        {', '.join(prof.stack) or 'unknown'}")
    print(f"tests        {prof.test_cmd or '—'}  (L2 proofs {'on' if prof.can_prove else 'off'})")
    print(f"lint/types   {prof.lint_cmd or '—'} / {prof.type_cmd or '—'}")
    if cfg.token:
        from .api import APIError, Byteramp
        try:
            pol = Byteramp(cfg).config()
            llm = pol['llm']
            print(f"repository   {pol['repository']['full_name']}")
            print(f"byteramp LLM {'enabled (opt-in recorded)' if llm['byteramp_allowed'] else 'not enabled'}")
            if cfg.llm == 'byteramp' and not llm['byteramp_allowed']:
                print('  → opt in under Triple Seven → Repositories, or set T7_LLM to your own provider.')
        except APIError as e:
            print(f'api check    FAILED: {e}')
            return 1
    return 0


def main(argv=None):
    p = argparse.ArgumentParser(prog='t7', description='Triple Seven by Byteramp')
    p.add_argument('--version', action='version', version=f't7 {__version__}')
    sub = p.add_subparsers(dest='cmd', required=True)
    s = sub.add_parser('scan', help='review the current change')
    s.add_argument('--base', help='base ref (default: merge-base with origin/main)')
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
    sys.exit(a.fn(a))


if __name__ == '__main__':
    main()
