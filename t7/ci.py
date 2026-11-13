"""CI events beyond pull requests: pushes to the default branch (review coverage)
and the commit status that carries the merge gate."""
import json
import os
import re
import urllib.request
from pathlib import Path

from . import gitops

ZERO = '0' * 40
PR_PATTERNS = [
    re.compile(r'Merge pull request #(\d+)'),          # GitHub merge commit
    re.compile(r'\(#(\d+)\)\s*$', re.M),               # GitHub squash / rebase
    re.compile(r'See merge request [^!\s]*!(\d+)'),    # GitLab merge commit body
]


def push_context():
    """{'before': sha, 'branch': name} for a push to a branch, else None."""
    env = os.environ
    if env.get('GITHUB_EVENT_NAME') == 'push' and env.get('GITHUB_EVENT_PATH'):
        try:
            ev = json.loads(Path(env['GITHUB_EVENT_PATH']).read_text())
        except (OSError, ValueError):
            return None
        return {'before': ev.get('before') or '', 'branch': env.get('GITHUB_REF_NAME', '')}
    if env.get('GITLAB_CI') and env.get('CI_PIPELINE_SOURCE') == 'push':
        return {'before': env.get('CI_COMMIT_BEFORE_SHA', ''), 'branch': env.get('CI_COMMIT_BRANCH', '')}
    if env.get('BITBUCKET_COMMIT') and not env.get('BITBUCKET_PR_ID'):
        return {'before': '', 'branch': env.get('BITBUCKET_BRANCH', '')}
    return None


def merges(root, base):
    """First-parent commits base..HEAD with the PR/MR number they came from."""
    rng = f'{base}..HEAD' if base and base != ZERO else 'HEAD~20..HEAD'
    p = gitops.run(['git', 'log', '--first-parent', '--format=%H%x1f%an%x1f%cI%x1f%s%x1f%b%x1e', rng], root)
    out = []
    for rec in p.stdout.split('\x1e'):
        parts = rec.strip('\n').split('\x1f')
        if len(parts) < 5 or not parts[0]:
            continue
        sha, author, date, subject, body = parts[:5]
        pr = None
        for rx in PR_PATTERNS:
            m = rx.search(subject) or rx.search(body)
            if m:
                pr = int(m.group(1))
                break
        out.append({'commit_sha': sha, 'pr_number': pr, 'title': subject[:300], 'author': author[:120],
                    'merged_at': date})
    return out[:200]


def set_github_status(ctx, verdict, target_url='', description=''):
    """Commit status 'Triple Seven' on the PR head. Protect the branch on this status: unlike a
    job result it flips to success when a /t7 decision clears the gate."""
    state = {'pass': 'success', 'warn': 'success', 'block': 'failure'}.get(verdict, 'error')
    body = {'state': state, 'context': 'Triple Seven',
            'description': (description or {'pass': 'No blocking SEC-REQs', 'warn': 'Open SEC-REQs (advisory)',
                                             'block': 'Blocking SEC-REQs — fix or decide'}[verdict])[:140]}
    if target_url:
        body['target_url'] = target_url
    req = urllib.request.Request(f"{ctx['api']}/repos/{ctx['repo']}/statuses/{ctx['head_sha']}",
                                 data=json.dumps(body).encode(), method='POST',
                                 headers={'Authorization': f"Bearer {ctx['token']}",
                                          'Accept': 'application/vnd.github+json'})
    with urllib.request.urlopen(req, timeout=20):
        return True
