"""`t7 command` — decisions typed as PR comments.

    /t7 accept-risk SEC-REQ-SHOP-004 Only reachable from the VPN; WAF rule 941100 in front.
    /t7 false-positive SEC-REQ-SHOP-005 The value is an enum, never user input.
    /t7 not-applicable SEC-REQ-SHOP-006 Feature flag is off in every environment.
    /t7 reopen SEC-REQ-SHOP-004

Runs in the customer's GitHub Actions on `issue_comment`. Only repository
collaborators (OWNER / MEMBER / COLLABORATOR) may decide. The decision is
recorded in Triple Seven (audit trail), the gate is re-evaluated, the summary
comment and the "Triple Seven" commit status are updated.
"""
import json
import os
import re
import sys
import urllib.request
from pathlib import Path

from .agents.reporter import MARKER, _gh
from .api import APIError, Byteramp
from .ci import set_github_status
from .config import Config

ACTIONS = {'accept-risk': 'accept_risk', 'false-positive': 'false_positive',
           'not-applicable': 'not_applicable', 'reopen': 'reopen'}
CMD = re.compile(r'^/t7\s+(accept-risk|false-positive|not-applicable|reopen)\s+(SEC-REQ-[A-Z0-9_-]+)\s*(.*)$',
                 re.I | re.M)
TRUSTED = {'OWNER', 'MEMBER', 'COLLABORATOR'}


def parse(body):
    return [(ACTIONS[m.group(1).lower()], m.group(2).upper(), m.group(3).strip()) for m in CMD.finditer(body or '')]


def run_command():
    env = os.environ
    event_path = env.get('GITHUB_EVENT_PATH')
    if env.get('GITHUB_EVENT_NAME') != 'issue_comment' or not event_path:
        print('t7 command: not an issue_comment event — nothing to do', file=sys.stderr)
        return 0
    ev = json.loads(Path(event_path).read_text())
    issue, comment = ev.get('issue') or {}, ev.get('comment') or {}
    cmds = parse(comment.get('body', ''))
    if not cmds or 'pull_request' not in issue:
        return 0
    ctx = {'token': env.get('GITHUB_TOKEN', ''), 'repo': env.get('GITHUB_REPOSITORY', ''),
           'api': env.get('GITHUB_API_URL', 'https://api.github.com'), 'number': issue['number']}
    base = f"{ctx['api']}/repos/{ctx['repo']}"
    who = (comment.get('user') or {}).get('login', 'unknown')

    def reply(text):
        _gh('POST', f"{base}/issues/{ctx['number']}/comments", ctx['token'], {'body': text})

    def react(content):
        try:
            req = urllib.request.Request(f"{base}/issues/comments/{comment['id']}/reactions",
                                         data=json.dumps({'content': content}).encode(), method='POST',
                                         headers={'Authorization': f"Bearer {ctx['token']}",
                                                  'Accept': 'application/vnd.github+json'})
            urllib.request.urlopen(req, timeout=15)
        except Exception:  # noqa: BLE001
            pass

    if comment.get('author_association') not in TRUSTED:
        reply(f'@{who} only repository collaborators can record Triple Seven decisions.')
        react('confused')
        return 0

    api = Byteramp(Config.load(Path('.')))
    results, last = [], None
    for action, sec_id, reason in cmds:
        try:
            last = api.decision(sec_req_id=sec_id, action=action, reason=reason, actor=who,
                                source='github', pr_number=ctx['number'],
                                url=comment.get('html_url', ''))
            results.append(f'✅ `{sec_id}` → **{last["status"]}**')
        except APIError as e:
            results.append(f'❌ `{sec_id}`: {e.detail}')
    if last and last.get('summary_markdown'):
        comments = _gh('GET', f"{base}/issues/{ctx['number']}/comments?per_page=100", ctx['token'])
        mine = next((c for c in comments if MARKER in (c.get('body') or '')), None)
        body = f"{MARKER}\n{last['summary_markdown']}"
        if mine:
            _gh('PATCH', f"{base}/issues/comments/{mine['id']}", ctx['token'], {'body': body})
        if last.get('head_sha'):
            try:
                set_github_status({**ctx, 'head_sha': last['head_sha']}, last['gate']['verdict'])
            except Exception as e:  # noqa: BLE001
                results.append(f'(could not update the commit status: {e})')
    reply(f'Triple Seven — decision{"s" if len(results) > 1 else ""} recorded by @{who}:\n\n' + '\n'.join(results)
          + (f"\n\nGate is now **{last['gate']['verdict'].upper()}**." if last and last.get('gate') else ''))
    react('+1' if all(r.startswith('✅') for r in results) else 'confused')
    return 0
