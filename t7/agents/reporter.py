"""Reporter — noise budget, local fix bundle, and (in GitHub Actions) the PR
comment + one-click suggested changes. Uses the customer's own GITHUB_TOKEN
inside their runner: Byteramp needs no access to the repository."""
import json
import os
import urllib.request
from pathlib import Path

from . import SEV_RANK


def select_for_pr(confirmed, budget):
    """Noise budget: proven + fixable + severe first; the rest go to the dashboard only."""
    def score(h):
        return (SEV_RANK.get(h.severity, 0) * 10
                + {'L3': 4, 'L2': 3, 'L1': 2, 'L0': 0}[h.proof_level]
                + (3 if h.fix and h.fix.get('status') == 'verified' else 0))
    ranked = sorted(confirmed, key=score, reverse=True)
    return ranked[:budget], ranked[budget:]


def write_bundle(root, findings, sec_ids):
    """Save each verified patch locally under .t7/fixes/ (for `t7 fix <id>`)."""
    out = root / '.t7' / 'fixes'
    out.mkdir(parents=True, exist_ok=True)
    gi = root / '.t7' / '.gitignore'
    if not gi.exists():
        gi.write_text('*\n')
    index_path = out / 'index.json'
    try:
        index = json.loads(index_path.read_text())
    except (OSError, ValueError):
        index = {}
    for h in findings:
        if not h.patch:
            continue
        sid = sec_ids.get(h.fingerprint, h.fingerprint[:12])
        patch = h.patch + (h.test_patch or '')
        (out / f'{sid}.patch').write_text(patch)
        index[sid] = {'fingerprint': h.fingerprint, 'title': h.title, 'file': h.file_path,
                      'status': h.fix.get('status') if h.fix else '', 'patch_sha256':
                      h.fix.get('patch_sha256') if h.fix else '', 'fix_only': h.patch}
    index_path.write_text(json.dumps(index, indent=2))
    return out


def write_last_scan(root, findings, sec_ids, gate, seconds, resolved):
    """Local record of the last scan (for `t7 mcp` / IDE tools). Never uploaded."""
    out = root / '.t7'
    out.mkdir(parents=True, exist_ok=True)
    rows = []
    for h in sorted(findings, key=lambda x: -x.rank):
        row = h.to_api(True)
        row.update({'sec_req_id': sec_ids.get(h.fingerprint, ''), 'trace': h.trace,
                    'reasoning': h.reasoning})
        rows.append(row)
    (out / 'last_scan.json').write_text(json.dumps(
        {'gate': gate, 'seconds': seconds, 'findings': rows, 'resolved': resolved}, indent=2,
        default=str))


def _gh(method, url, token, body=None):
    req = urllib.request.Request(url, method=method, data=json.dumps(body).encode() if body else None,
                                 headers={'Authorization': f'Bearer {token}',
                                          'Accept': 'application/vnd.github+json',
                                          'X-GitHub-Api-Version': '2022-11-28'})
    with urllib.request.urlopen(req, timeout=30) as r:
        raw = r.read()
        return json.loads(raw) if raw else {}


def github_context():
    token, repo = os.environ.get('GITHUB_TOKEN'), os.environ.get('GITHUB_REPOSITORY')
    event_path = os.environ.get('GITHUB_EVENT_PATH')
    if not (token and repo and event_path and Path(event_path).exists()):
        return None
    event = json.loads(Path(event_path).read_text())
    pr = event.get('pull_request')
    if not pr:
        return None
    return {'token': token, 'repo': repo, 'number': pr['number'], 'head_sha': pr['head']['sha'],
            'title': pr.get('title', ''), 'url': pr.get('html_url', ''),
            'author': (pr.get('user') or {}).get('login', ''),
            'api': os.environ.get('GITHUB_API_URL', 'https://api.github.com')}


MARKER = '<!-- triple-seven -->'


def post_pr(ctx, summary_md, surfaced, sec_ids, tracer):
    with tracer.step('reporter', 'Publish PR summary and suggested changes') as s:
        base = f"{ctx['api']}/repos/{ctx['repo']}"
        body = f'{MARKER}\n{summary_md}'
        comments = _gh('GET', f"{base}/issues/{ctx['number']}/comments?per_page=100", ctx['token'])
        mine = next((c for c in comments if MARKER in (c.get('body') or '')), None)
        if mine:
            _gh('PATCH', f"{base}/issues/comments/{mine['id']}", ctx['token'], {'body': body})
        else:
            _gh('POST', f"{base}/issues/{ctx['number']}/comments", ctx['token'], {'body': body})

        review_comments = []
        for h in surfaced:
            if not (h.fix and h.fix.get('status') in ('verified', 'partial') and h.edits):
                continue
            sid = sec_ids.get(h.fingerprint, '')
            for e in h.edits[:3]:
                line_range = _locate(ctx, e)
                if not line_range:
                    continue
                start, end = line_range
                badge = '✅ verified fix' if h.fix['status'] == 'verified' else '⚠️ partially verified'
                proof = ' · 🧪 regression test proves it' if h.proof_level == 'L2' else ''
                c = {'path': e['file'], 'line': end, 'side': 'RIGHT',
                     'body': f"**{sid} · {h.title}** — {badge}{proof}\n\n{h.fix.get('explanation', '')}"
                             f"\n\n```suggestion\n{e['replace']}\n```"}
                if end > start:
                    c.update({'start_line': start, 'start_side': 'RIGHT'})
                review_comments.append(c)
        if review_comments:
            try:
                _gh('POST', f"{base}/pulls/{ctx['number']}/reviews", ctx['token'],
                    {'commit_id': ctx['head_sha'], 'event': 'COMMENT', 'comments': review_comments,
                     'body': 'Triple Seven — verified fixes, one click to commit.'})
            except Exception as ex:  # noqa: BLE001 — lines outside the diff are rejected by GitHub
                s.summary(f'summary posted; suggestions rejected by GitHub ({str(ex)[:80]})')
                return
        s.summary(f'summary posted, {len(review_comments)} suggested change(s)')


def _locate(ctx, edit):
    """Line range of `find` in the PR head (workspace = head checkout in Actions)."""
    p = Path(os.environ.get('GITHUB_WORKSPACE', '.')) / edit['file']
    try:
        text = p.read_text()
    except OSError:
        return None
    i = text.find(edit['find'])
    if i < 0:
        return None
    start = text.count('\n', 0, i) + 1
    return start, start + edit['find'].count('\n')
