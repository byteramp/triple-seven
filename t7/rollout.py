"""`t7 rollout` — switch Triple Seven on for a whole GitHub organisation, with the
administrator's own GitHub CLI login (`gh`). Byteramp never gets access to the code.

  1. sets the organisation secret T7_TOKEN (an organisation CI token from the portal)
  2. opens a pull request with .github/workflows/triple-seven.yml in each chosen repository
  3. optionally (--require-check) adds an organisation ruleset that requires the
     "Triple Seven" status before merging into the default branch

Re-running is safe: repositories that already have the workflow are skipped.
"""
import base64
import getpass
import json
import shutil
import subprocess
import sys

WORKFLOW_PATH = '.github/workflows/triple-seven.yml'
BRANCH = 't7/rollout'


def workflow(default_branch='main', api_url=''):
    api = f'\n          api-url: {api_url}' if api_url and api_url != 'https://t7.byteramp.se/api' else ''
    return f"""name: Triple Seven
on:
  pull_request:
  push:
    branches: [{default_branch}]   # review coverage
  issue_comment:
    types: [created]                 # /t7 decisions from the PR
permissions:
  contents: read
  pull-requests: write
  statuses: write
jobs:
  t7:
    if: github.event_name != 'issue_comment' || startsWith(github.event.comment.body, '/t7')
    runs-on: ubuntu-latest
    steps:
      - uses: actions/checkout@v4
        with: {{ fetch-depth: 0 }}
      - uses: byteramp/triple-seven@v0
        with:
          token: ${{{{ secrets.T7_TOKEN }}}}{api}
"""


PR_BODY = """Adds Triple Seven security review to pull requests: threat model of the change, confirmed
findings, fixes verified against this repository's tests, and a "Triple Seven" status.

- Runs in this repository's GitHub Actions. Byteramp gets no access to the repository; results
  are reported as metadata (title, file:line, fix/proof status).
- Uses the organisation secret `T7_TOKEN`.
- Decide from any PR with `/t7 accept-risk SEC-REQ-… <reason>`.

Opened by `t7 rollout`."""


class RolloutError(RuntimeError):
    pass


def gh(*args, input_text=None, check=True):
    p = subprocess.run(['gh', *args], input=input_text, capture_output=True, text=True, timeout=120)
    if check and p.returncode != 0:
        raise RolloutError((p.stderr or p.stdout).strip()[:500])
    return p


def _ask(q):
    try:
        return input(q).strip()
    except EOFError:
        return ''


def repos_of(org):
    out = gh('repo', 'list', org, '--limit', '1000', '--no-archived', '--json',
             'name,defaultBranchRef,isFork,isEmpty').stdout
    rows = json.loads(out or '[]')
    return [{'name': r['name'], 'default': (r.get('defaultBranchRef') or {}).get('name') or 'main'}
            for r in rows if not r.get('isFork') and not r.get('isEmpty')]


def has_workflow(org, repo):
    return gh('api', f'repos/{org}/{repo}/contents/{WORKFLOW_PATH}', check=False).returncode == 0


def open_pr(org, repo, default, api_url=''):
    ref = json.loads(gh('api', f'repos/{org}/{repo}/git/ref/heads/{default}').stdout)
    sha = ref['object']['sha']
    created = gh('api', '-X', 'POST', f'repos/{org}/{repo}/git/refs', '-f', f'ref=refs/heads/{BRANCH}',
                 '-f', f'sha={sha}', check=False)
    if created.returncode != 0 and 'already exists' not in (created.stderr + created.stdout):
        raise RolloutError((created.stderr or created.stdout).strip()[:300])
    content = base64.b64encode(workflow(default, api_url).encode()).decode()
    put = gh('api', '-X', 'PUT', f'repos/{org}/{repo}/contents/{WORKFLOW_PATH}',
             '-f', 'message=Add Triple Seven security review', '-f', f'content={content}',
             '-f', f'branch={BRANCH}', check=False)
    if put.returncode != 0:
        err = (put.stderr or put.stdout).strip()
        if 'workflow' in err.lower() and 'scope' in err.lower():
            raise RolloutError('your gh login may not change workflows. Run: gh auth refresh -s workflow')
        raise RolloutError(err[:300])
    pr = gh('pr', 'create', '-R', f'{org}/{repo}', '--head', BRANCH, '--base', default,
            '--title', 'Add Triple Seven security review', '--body', PR_BODY, check=False)
    if pr.returncode != 0 and 'already exists' not in (pr.stderr + pr.stdout):
        raise RolloutError((pr.stderr or pr.stdout).strip()[:300])
    return pr.stdout.strip().splitlines()[-1] if pr.stdout.strip() else 'pull request already open'


def require_check(org):
    body = json.dumps({
        'name': 'Triple Seven', 'target': 'branch', 'enforcement': 'active',
        'conditions': {'ref_name': {'include': ['~DEFAULT_BRANCH'], 'exclude': []},
                       'repository_name': {'include': ['~ALL'], 'exclude': []}},
        'rules': [{'type': 'required_status_checks', 'parameters': {
            'strict_required_status_checks_policy': False,
            'required_status_checks': [{'context': 'Triple Seven'}]}}],
    })
    gh('api', '-X', 'POST', f'orgs/{org}/rulesets', '--input', '-', input_text=body)


def run(a):
    org = a.org
    if not shutil.which('gh'):
        print('GitHub CLI (gh) is required: https://cli.github.com — then `gh auth login`.', file=sys.stderr)
        return 1
    if gh('auth', 'status', check=False).returncode != 0:
        print('Sign in to GitHub first: gh auth login  (an organisation owner/admin)', file=sys.stderr)
        return 1
    print(f'Triple Seven rollout · GitHub organisation {org}\n')

    # 1 · organisation secret
    if not a.skip_secret:
        if a.dry_run:
            print('· would set organisation secret T7_TOKEN (all repositories)')
        else:
            print('Organisation CI token from the portal (Triple Seven → CI / CD → Organisation CI token).')
            token = sys.stdin.readline().strip() if not sys.stdin.isatty() else getpass.getpass('Token (hidden): ').strip()
            if not token.startswith('t7_'):
                print('That does not look like a Triple Seven token (t7_…).', file=sys.stderr)
                return 1
            gh('secret', 'set', 'T7_TOKEN', '--org', org, '--visibility', 'all', input_text=token)
            print('✓ organisation secret T7_TOKEN set (visible to all repositories)')

    # 2 · repositories
    try:
        repos = repos_of(org)
    except RolloutError as e:
        print(f'Cannot list repositories of {org}: {e}', file=sys.stderr)
        return 1
    if a.repos:
        wanted = {r.strip() for r in a.repos.split(',') if r.strip()}
        repos = [r for r in repos if r['name'] in wanted]
    elif not a.all:
        print(f'\n{len(repos)} repositories: ' + ', '.join(r['name'] for r in repos[:30]) + (' …' if len(repos) > 30 else ''))
        if (_ask('Open a pull request in all of them? [y/N] ') or 'n').lower() not in ('y', 'yes', 'j', 'ja'):
            print('Stopped. Choose with --repos a,b,c or use --all.')
            return 0
    opened, skipped, failed = 0, 0, []
    for r in repos:
        name = r['name']
        if has_workflow(org, name):
            skipped += 1
            print(f'  = {name}: already set up')
            continue
        if a.dry_run:
            print(f'  · {name}: would open a pull request')
            opened += 1
            continue
        try:
            url = open_pr(org, name, r['default'], a.api_url or '')
            opened += 1
            print(f'  ✓ {name}: {url}')
        except RolloutError as e:
            failed.append(name)
            print(f'  ✗ {name}: {e}', file=sys.stderr)

    # 3 · merge gate
    if a.require_check and not a.dry_run:
        print('\nThis requires the "Triple Seven" status before merging into the default branch of EVERY '
              f'repository in {org}.')
        if (_ask('Create the organisation ruleset now? [y/N] ') or 'n').lower() in ('y', 'yes', 'j', 'ja'):
            try:
                require_check(org)
                print('✓ ruleset "Triple Seven" created (Settings → Rules → Rulesets)')
            except RolloutError as e:
                print(f'✗ ruleset: {e}  (organisation rulesets need GitHub Team or Enterprise)', file=sys.stderr)

    verb = 'would be opened (dry run — nothing changed)' if a.dry_run else 'opened'
    print(f'\nDone: {opened} pull request(s) {verb}, {skipped} already set up'
          + (f', {len(failed)} failed ({", ".join(failed)})' if failed else '') + '.')
    if not a.require_check:
        print(f'Merge gate: https://github.com/organizations/{org}/settings/rules — require the status '
              '"Triple Seven" on the default branch (or rerun with --require-check).')
    return 1 if failed else 0
