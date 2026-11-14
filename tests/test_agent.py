"""Offline tests for the t7 agent: real git, real worktrees, real pytest, scripted LLM.

Run: python -m pytest tripleseven_agent/tests -q
"""
import io
import json
import os
import subprocess
import sys

import pytest

from t7 import llm as llm_mod

_ORIG_DISPATCH = llm_mod.LLM._dispatch

VULN = """    rows = c.execute(f"select id, name from users where name = '{name}'").fetchall()"""
FIXED = """    rows = c.execute("select id, name from users where name = ?", (name,)).fetchall()"""
TEST = '''from app.users import find_user


def test_sqli_payload_does_not_dump_table():
    assert find_user("x' or '1'='1") == []


def test_normal_lookup_still_works():
    assert find_user("alice") == [(1, "alice")]
'''


def fake_dispatch(self, purpose, system, prompt, json_mode, max_tokens, temperature):
    if purpose == 'plan':
        return json.dumps({'add': [], 'focus_files': ['app/users.py'], 'risk': 'high'})
    if purpose == 'map':
        return json.dumps({'components': [
            {'id': 'user', 'name': 'User', 'kind': 'client', 'trust_zone': 'internet'},
            {'id': 'svc', 'name': 'Users service', 'kind': 'service', 'trust_zone': 'internal'}],
            'flows': [{'id': 'a', 'source': 'user', 'target': 'svc', 'authenticated': True}]})
    if purpose == 'analyze':
        if VULN.strip() not in prompt:
            return json.dumps({'findings': []})
        return json.dumps({'findings': [{
            'title': 'SQL injection in find_user', 'severity': 'high', 'cwe': 'CWE-89',
            'file': 'app/users.py', 'line': 6, 'description': 'name interpolated into SQL',
            'attack_scenario': "x' or '1'='1", 'recommendation': 'parameterise'}]})
    if purpose == 'triage':
        if 'HYPOTHESIS: SQL' not in prompt:
            return json.dumps({'verdict': 'rejected'})
        return json.dumps({'verdict': 'confirmed', 'severity': 'high', 'file': 'app/users.py',
                           'line_start': 6, 'line_end': 6, 'reasoning': 'f-string into execute',
                           'trace': [{'file': 'app/users.py', 'line': 6, 'label': 'sink'}]})
    if purpose == 'critic':
        if 'INDEPENDENT VERIFIER' in system:
            return json.dumps({'still_vulnerable': VULN.strip() in prompt, 'breaks_behaviour': False})
        return json.dumps({'refuted': False})
    if purpose == 'fix':
        return json.dumps({'edits': [{'file': 'app/users.py', 'find': VULN, 'replace': FIXED}],
                           'explanation': 'Bind the parameter.'})
    if purpose == 'prove':
        return json.dumps({'path': 'tests/test_t7_sqli.py', 'content': TEST, 'asserts': 'payload returns nothing'})
    return '{}'


def _git(cwd, *args):
    subprocess.run(['git', '-c', 'user.email=t@t', '-c', 'user.name=t', *args], cwd=cwd,
                   check=True, capture_output=True)


@pytest.fixture()
def repo(tmp_path, monkeypatch):
    r = tmp_path / 'repo'
    (r / 'app').mkdir(parents=True)
    (r / 'tests').mkdir()
    (r / 'app' / '__init__.py').write_text('')
    (r / 'tests' / '__init__.py').write_text('')
    (r / 'app' / 'db.py').write_text(
        'import sqlite3\n\n\ndef conn():\n    c = sqlite3.connect(":memory:")\n'
        '    c.execute("create table users (id integer, name text)")\n'
        '    c.execute("insert into users values (1, \'alice\'), (2, \'bob\')")\n    return c\n')
    (r / 'tests' / 'test_db.py').write_text(
        'from app.db import conn\n\n\ndef test_conn():\n'
        '    assert conn().execute("select count(*) from users").fetchone()[0] == 2\n')
    (r / 'requirements.txt').write_text('pytest\n')
    (r / '.t7.json').write_text(json.dumps({'test_command': f'{sys.executable} -m pytest -x -q {{target}}'}))
    _git(r, 'init', '-q', '-b', 'main')
    _git(r, 'add', '-A')
    _git(r, 'commit', '-qm', 'init')
    (r / 'app' / 'users.py').write_text(
        'from app.db import conn\n\n\ndef find_user(name):\n    c = conn()\n' + VULN + '\n    return rows\n')
    _git(r, 'add', '-A')
    _git(r, 'commit', '-qm', 'vuln')
    monkeypatch.chdir(r)
    monkeypatch.setenv('T7_LLM', 'openai')
    monkeypatch.setenv('T7_LLM_MODEL', 'fake')
    monkeypatch.delenv('T7_TOKEN', raising=False)
    monkeypatch.setattr(llm_mod.LLM, '_dispatch', fake_dispatch)
    return r


def test_full_chain_verified_and_proven(repo):
    from t7.orchestrator import scan_repo
    res = scan_repo(base='HEAD~1', quiet=True)
    h = res['surfaced'][0]
    assert h.fix['status'] == 'verified', h.fix
    assert h.fix['checks']['tests'] == 'pass'
    assert h.proof_level == 'L2'
    patch = next((repo / '.t7' / 'fixes').glob('*.patch')).read_text()
    assert '__pycache__' not in patch and 'tests/test_t7_sqli.py' in patch
    assert subprocess.run(['git', 'status', '--porcelain'], cwd=repo, capture_output=True,
                          text=True).stdout.strip() == ''   # developer's tree untouched


def test_zero_tests_never_counts_as_pass(tmp_path):
    from t7.agents.fixer import _check
    res, _ = _check(f'{sys.executable} -c "print(\'Ran 0 tests in 0.000s\')"', tmp_path, 30)
    assert res == 'skip'


def test_mcp_scan_explain_apply(repo):
    from t7 import mcp
    calls = [
        {'jsonrpc': '2.0', 'id': 1, 'method': 'initialize', 'params': {'protocolVersion': '2025-06-18'}},
        {'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call', 'params': {'name': 't7_scan', 'arguments': {'base': 'HEAD~1'}}},
        {'jsonrpc': '2.0', 'id': 3, 'method': 'tools/call', 'params': {'name': 't7_findings', 'arguments': {}}},
    ]
    out = io.StringIO()
    mcp.serve(io.StringIO('\n'.join(json.dumps(c) for c in calls) + '\n'), out)
    replies = [json.loads(line) for line in out.getvalue().splitlines()]
    text = replies[2]['result']['content'][0]['text']
    assert 'SQL injection in find_user' in text and 'fix verified' in text
    fid = json.loads((repo / '.t7' / 'last_scan.json').read_text())['findings'][0]['fingerprint'][:12]

    out = io.StringIO()
    mcp.serve(io.StringIO('\n'.join(json.dumps(c) for c in [
        {'jsonrpc': '2.0', 'id': 4, 'method': 'tools/call', 'params': {'name': 't7_explain', 'arguments': {'id': fid}}},
        {'jsonrpc': '2.0', 'id': 5, 'method': 'tools/call', 'params': {'name': 't7_show_fix', 'arguments': {'id': fid}}},
        {'jsonrpc': '2.0', 'id': 6, 'method': 'tools/call', 'params': {'name': 't7_apply_fix', 'arguments': {'id': fid}}},
    ]) + '\n'), out)
    r = [json.loads(line) for line in out.getvalue().splitlines()]
    assert 'Attack' in r[0]['result']['content'][0]['text']
    assert '+    rows = c.execute("select id, name from users where name = ?"' in r[1]['result']['content'][0]['text']
    assert r[2]['result']['isError'] is False
    assert '?", (name,)' in (repo / 'app' / 'users.py').read_text()
    assert (repo / 'tests' / 'test_t7_sqli.py').exists()


def test_mcp_stdout_is_protocol_only(repo):
    env = {**os.environ, 'T7_LLM': 'ollama'}
    p = subprocess.run([sys.executable, '-m', 't7.cli', 'mcp'], cwd=repo, env=env, text=True,
                       capture_output=True, timeout=60,
                       input=json.dumps({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/list'}) + '\n')
    lines = [line for line in p.stdout.splitlines() if line.strip()]
    assert len(lines) == 1 and json.loads(lines[0])['result']['tools']


def test_dedupe_collapses_same_issue_from_different_sources():
    from t7.agents import Hypothesis
    from t7.agents.triage import dedupe_confirmed
    a = Hypothesis('a', 'Unauthenticated flow crosses a trust boundary', 'critical', cwe='CWE-306',
                   file_path='tower/urls.py', line_start=15, verdict='confirmed', origin='threat-model')
    b = Hypothesis('b', 'Missing authentication for public endpoint', 'high', cwe='CWE-862',
                   file_path='tower/urls.py', line_start=17, verdict='confirmed', origin='analyst:authz')
    c = Hypothesis('c', 'SQL built from input', 'high', cwe='CWE-89',
                   file_path='tower/urls.py', line_start=16, verdict='confirmed')
    assert dedupe_confirmed([a, b, c]) == 1
    assert [h.verdict for h in (a, b, c)] == ['confirmed', 'merged', 'confirmed']


def test_structural_guard_catches_duplicated_body(tmp_path):
    from t7.agents.fixer import structural_problems
    (tmp_path / 'v.py').write_text(
        'class TestClickView:\n'
        '    def get(self, request):\n        return 1\n\n'
        '    def post(self, request):\n        return self.get(request)\n'
        '    """stray docstring"""\n\n'
        '    def get(self, request):\n        return 2\n\n'
        '    @property\n    def x(self):\n        return 1\n\n'
        '    @x.setter\n    def x(self, v):\n        pass\n')
    probs = structural_problems(tmp_path, ['v.py'])
    assert len(probs) == 1 and '`get` defined twice' in probs[0]


def test_django_no_tests_with_nonzero_exit_is_skip(tmp_path):
    from t7.agents.fixer import _check
    cmd = f'{sys.executable} -c "import sys; print(\'Found 0 test(s).\'); print(\'NO TESTS RAN\'); sys.exit(5)"'
    assert _check(cmd, tmp_path, 30)[0] == 'skip'
    fail = f'{sys.executable} -c "import sys; print(\'FAILED (failures=1)\'); sys.exit(1)"'
    assert _check(fail, tmp_path, 30)[0] == 'fail'


def test_gitlab_mr_context_and_note(monkeypatch, tmp_path):
    from t7.agents import Hypothesis
    from t7.agents import reporter
    from t7.trace import Tracer
    monkeypatch.setenv('GITLAB_CI', 'true')
    monkeypatch.setenv('CI_MERGE_REQUEST_IID', '42')
    monkeypatch.setenv('CI_PROJECT_ID', '7')
    monkeypatch.setenv('CI_API_V4_URL', 'https://gitlab.example.com/api/v4')
    monkeypatch.setenv('CI_MERGE_REQUEST_DIFF_BASE_SHA', 'b' * 40)
    monkeypatch.setenv('CI_COMMIT_SHA', 'h' * 40)
    monkeypatch.setenv('T7_GITLAB_TOKEN', 'glpat-test')
    monkeypatch.setenv('CI_PROJECT_DIR', str(tmp_path))
    (tmp_path / 'app.py').write_text('a = 1\nrows = q(f"{x}")\nb = 2\n')
    ctx = reporter.gitlab_context()
    assert ctx['kind'] == 'gitlab' and ctx['number'] == 42
    calls = []

    def fake_gl(method, url, token, body=None):
        calls.append((method, url, body))
        return [] if method == 'GET' else {}
    monkeypatch.setattr(reporter, '_gl', fake_gl)
    h = Hypothesis('fp', 'SQLi', 'high', file_path='app.py', line_start=2)
    h.fix = {'status': 'verified', 'explanation': 'bind it'}
    h.edits = [{'file': 'app.py', 'find': 'rows = q(f"{x}")', 'replace': 'rows = q("?", (x,))'}]
    reporter.post_mr(ctx, '### summary', [h], {'fp': 'SEC-REQ-APP-001'}, Tracer(quiet=True))
    assert calls[1][0] == 'POST' and calls[1][1].endswith('/merge_requests/42/notes')
    disc = calls[2]
    assert disc[1].endswith('/discussions') and disc[2]['position']['new_line'] == 2
    assert '```suggestion:-0+0' in disc[2]['body']


def test_command_parsing():
    from t7.commands import parse
    body = ("Thanks!\n/t7 accept-risk SEC-REQ-SHOP-004 Only reachable from the VPN; WAF in front.\n"
            "/t7 false-positive sec-req-shop-005 enum value, never user input\n/t7 reopen SEC-REQ-SHOP-001")
    assert parse(body) == [('accept_risk', 'SEC-REQ-SHOP-004', 'Only reachable from the VPN; WAF in front.'),
                           ('false_positive', 'SEC-REQ-SHOP-005', 'enum value, never user input'),
                           ('reopen', 'SEC-REQ-SHOP-001', '')]
    assert parse('/t7 delete-everything SEC-REQ-X-1 now') == []


def test_untrusted_commenter_cannot_decide(tmp_path, monkeypatch):
    import json as _json
    from t7 import commands
    ev = {'issue': {'number': 7, 'pull_request': {}}, 'comment': {
        'id': 1, 'body': '/t7 accept-risk SEC-REQ-A-001 because reasons here', 'user': {'login': 'mallory'},
        'author_association': 'NONE'}}
    p = tmp_path / 'ev.json'
    p.write_text(_json.dumps(ev))
    monkeypatch.setenv('GITHUB_EVENT_NAME', 'issue_comment')
    monkeypatch.setenv('GITHUB_EVENT_PATH', str(p))
    posted, decided = [], []
    monkeypatch.setattr(commands, '_gh', lambda m, u, t, b=None: posted.append(b))
    monkeypatch.setattr(commands.Byteramp, 'decision', lambda self, **k: decided.append(k))
    monkeypatch.setattr(commands.urllib.request, 'urlopen', lambda *a, **k: None)
    commands.run_command()
    assert decided == [] and 'only repository collaborators' in posted[0]['body']


def test_merges_from_git_history(tmp_path):
    import subprocess as sp
    from t7.ci import merges
    r = tmp_path
    def g(*a): sp.run(['git', '-c', 'user.email=t@t', '-c', 'user.name=dev', *a], cwd=r, check=True, capture_output=True)
    g('init', '-q', '-b', 'main'); (r / 'a').write_text('1'); g('add', '-A'); g('commit', '-qm', 'init')
    base = sp.run(['git', 'rev-parse', 'HEAD'], cwd=r, capture_output=True, text=True).stdout.strip()
    (r / 'a').write_text('2'); g('commit', '-qam', 'Add export (#12)')
    (r / 'a').write_text('3'); g('commit', '-qam', 'Merge branch x into main', '-m', 'See merge request acme/app!34')
    (r / 'a').write_text('4'); g('commit', '-qam', 'hotfix straight to main')
    ms = merges(r, base)
    assert [m['pr_number'] for m in ms] == [None, 34, 12]


def test_rejection_memory_skips_model(repo, monkeypatch):
    from t7.agents import Hypothesis
    from t7.agents.triage import region_hash, triage_all
    from t7.trace import Tracer
    from t7 import gitops
    root = gitops.repo_root()
    h = Hypothesis('fp1', 'Something', 'high', cwe='CWE-89', file_path='app/users.py', line_start=6)
    key = f'fp1:{region_hash(root, h)}'
    calls = []

    class NoLLM:
        def json(self, *a, **k):
            calls.append(a)
            return {}
    mem = {}
    out = triage_all([h], root, [], NoLLM(), Tracer(quiet=True), rejections={key}, memory=mem)
    assert out[0].verdict == 'rejected' and calls == [] and mem['reused'] == [key]


def test_critic_needs_verbatim_control_quote():
    from t7.agents.triage import critic_refutes
    code = 'sort = ALLOWED_SORT.get(request.GET.get("sort"), "created_at")\nc.execute(f"... ORDER BY {sort}")'
    ok = {'verdict': 'blocked', 'control': 'allowlist',
          'quote': 'sort = ALLOWED_SORT.get(request.GET.get("sort"), "created_at")'}
    assert critic_refutes(ok, code, [2])
    assert not critic_refutes({**ok, 'verdict': 'exploitable'}, code, [2])
    assert not critic_refutes({**ok, 'control': 'other'}, code, [2])
    assert not critic_refutes({**ok, 'quote': 'validate(sort)'}, code, [2])
    # the vulnerable line itself is never the control (seen with small models)
    assert not critic_refutes({'verdict': 'blocked', 'control': 'validation',
                               'quote': 'c.execute(f"... ORDER BY {sort}")'}, code, [2])


def test_mcp_scan_uses_editor_model_via_sampling(repo, monkeypatch):
    """The editor (e.g. VS Code Copilot) runs every model call via MCP sampling."""
    import os as _os
    import threading
    from t7 import mcp
    monkeypatch.delenv('T7_LLM', raising=False)
    monkeypatch.delenv('T7_LLM_DEFAULT', raising=False)
    monkeypatch.setattr(llm_mod.LLM, '_dispatch', _ORIG_DISPATCH)   # real path → MCP sampling
    roles = [('PLANNER', 'plan'), ('ARCHITECTURE MAPPER', 'map'), ('SPECIALIST', 'analyze'),
             ('INDEPENDENT VERIFIER', 'critic'), ('INDEPENDENT CRITIC', 'critic'), ('VERIFIER', 'triage'),
             ('FIXER', 'fix'), ('PROVER', 'prove')]
    c2s_r, c2s_w = _os.pipe()
    s2c_r, s2c_w = _os.pipe()
    srv_in, srv_out = _os.fdopen(c2s_r, 'r'), _os.fdopen(s2c_w, 'w')
    cli_out, cli_in = _os.fdopen(c2s_w, 'w'), _os.fdopen(s2c_r, 'r')
    server = threading.Thread(target=mcp.serve, args=(srv_in, srv_out), daemon=True)
    server.start()

    def send(obj):
        cli_out.write(json.dumps(obj) + '\n')
        cli_out.flush()
    send({'jsonrpc': '2.0', 'id': 1, 'method': 'initialize',
          'params': {'protocolVersion': '2025-06-18', 'capabilities': {'sampling': {}},
                     'clientInfo': {'name': 'Visual Studio Code', 'version': '1.106'}}})
    send({'jsonrpc': '2.0', 'id': 2, 'method': 'tools/call',
          'params': {'name': 't7_scan', 'arguments': {'base': 'HEAD~1'}, '_meta': {'progressToken': 'p1'}}})
    samples, progress, result = 0, 0, None
    while result is None:
        msg = json.loads(cli_in.readline())
        if msg.get('method') == 'sampling/createMessage':
            samples += 1
            p = msg['params']
            purpose = next((r for k, r in roles if k in p['systemPrompt']), 'plan')
            text = fake_dispatch(None, purpose, p['systemPrompt'], p['messages'][0]['content']['text'],
                                 True, p['maxTokens'], 0)
            send({'jsonrpc': '2.0', 'id': msg['id'], 'result': {
                'role': 'assistant', 'model': 'gpt-4.1', 'content': {'type': 'text', 'text': text}}})
        elif msg.get('method') == 'notifications/progress':
            progress += 1
        elif msg.get('id') == 2:
            result = msg['result']
    cli_out.close()
    text = result['content'][0]['text']
    assert samples >= 5 and progress >= 5
    assert 'SQL injection in find_user' in text and 'fix verified' in text
    _os.environ.pop('T7_LLM_DEFAULT', None)


def test_single_commit_and_untracked_files(tmp_path, monkeypatch):
    import subprocess as sp
    from t7 import gitops
    r = tmp_path / 'r'
    r.mkdir()
    def g(*a): sp.run(['git', '-c', 'user.email=t@t', '-c', 'user.name=t', *a], cwd=r, check=True, capture_output=True)
    g('init', '-q', '-b', 'main')
    (r / 'new.py').write_text('import os\nos.system("rm " + input())\n')   # untracked, no commits
    assert gitops.resolve_base(r) == gitops.EMPTY_TREE and gitops.head_sha(r) == ''
    files = gitops.changed_files(r, gitops.resolve_base(r))
    assert [f.path for f in files] == ['new.py'] and len(files[0].added) == 2
    g('add', '-A'); g('commit', '-qm', 'one')                              # exactly one commit
    (r / 'other.py').write_text('x = 1\n')
    files = gitops.changed_files(r, gitops.resolve_base(r))      # on main: only uncommitted work
    assert [f.path for f in files] == ['other.py']
    files = gitops.changed_files(r, gitops.EMPTY_TREE)           # t7 scan --all
    assert sorted(f.path for f in files) == ['new.py', 'other.py']


def test_mcp_config_is_not_an_llm_tool_call():
    from t7.signals import scan
    from t7.gitops import ChangedFile, Hunk
    h = Hunk(1, 2)
    h.added_lines = [(1, '{"servers": {"triple-seven": {"command": "t7", "args": ["mcp"]}}}')]
    sigs, _ = scan([ChangedFile('src/settings.json', 'A', [h])])
    assert not [s for s in sigs if s['kind'] == 'llm_tool_call']
    h.added_lines = [(1, 'resp = client.chat.completions.create(model=m, tools=[refund_tool])')]
    sigs, _ = scan([ChangedFile('app/agent.py', 'A', [h])])
    assert [s for s in sigs if s['kind'] == 'llm_tool_call']


def test_scan_requires_access_without_dev_flag(repo, monkeypatch):
    import pytest
    from t7.access import AccessError
    from t7.orchestrator import scan_repo
    monkeypatch.delenv('T7_ALLOW_OFFLINE')
    with pytest.raises(AccessError, match='t7 setup'):
        scan_repo(fix=False, quiet=True)


def test_mcp_scan_without_access_tells_user_to_setup(repo, monkeypatch):
    from t7 import mcp
    monkeypatch.delenv('T7_ALLOW_OFFLINE')
    r = mcp.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                    'params': {'name': 't7_scan', 'arguments': {}}})
    assert r['result']['isError'] and 't7 setup' in r['result']['content'][0]['text']


def test_setup_token_is_stored_per_repo_and_env_wins(repo, monkeypatch):
    import os, stat
    from t7 import credentials
    from t7.config import Config
    credentials.store('t7_stored', 'https://example.test/api', 'acme/app', repo)
    assert stat.S_IMODE(os.stat(credentials.path()).st_mode) == 0o600
    c = Config.load(repo)
    assert (c.token, c.token_source, c.api_url) == ('t7_stored', 'setup', 'https://example.test/api')
    assert not c.offline
    monkeypatch.setenv('T7_TOKEN', 't7_env')
    assert Config.load(repo).token == 't7_env'
    monkeypatch.delenv('T7_TOKEN')
    credentials.remove(repo)
    assert Config.load(repo).offline


def test_setup_verifies_before_storing(repo, monkeypatch, capsys):
    from t7 import cli, credentials
    from t7.api import APIError, Byteramp
    monkeypatch.setattr(cli, '_read_token', lambda: 't7_bad')
    def deny(self):
        raise APIError(401, 'Invalid token')
    monkeypatch.setattr(Byteramp, 'config', deny)
    args = type('A', (), {'default': False, 'api_url': None, 'token': True, 'no_editors': True, 'yes': False})()
    assert cli.cmd_setup(args) == 1
    assert credentials.lookup(repo) == (None, None)
    monkeypatch.setattr(cli, '_read_token', lambda: 't7_good')
    monkeypatch.setattr(Byteramp, 'config', lambda self: {'repository': {'full_name': 'acme/app'},
                                                          'llm': {'byteramp_allowed': True},
                                                          'token': {'kind': 'developer', 'expires_at': None}})
    assert cli.cmd_setup(args) == 0
    assert credentials.lookup(repo)[1]['token'] == 't7_good'
    assert 'acme/app' in capsys.readouterr().out


def test_doctor_and_welcome_outside_git(tmp_path, monkeypatch, capsys):
    import pytest
    from t7 import cli
    monkeypatch.chdir(tmp_path)
    monkeypatch.setattr('t7.editors.detect', lambda: [])
    assert cli.cmd_doctor(None) == 1
    assert 'not inside a git repository' in capsys.readouterr().out
    with pytest.raises(SystemExit) as e:
        cli.main([])
    assert e.value.code == 0 and 't7 setup' in capsys.readouterr().out


def test_browser_sign_in_stores_token_and_registers_editors(repo, monkeypatch, capsys):
    from t7 import cli, credentials
    from t7.api import Byteramp
    calls = []

    def fake_public(api_url, path, body, timeout=30):
        calls.append(path)
        if path == 'device/':
            assert body['repo_hint']                       # git remote or folder name, never code
            return {'device_code': 'dev', 'user_code': 'BCDF-GHJK', 'interval': 0, 'expires_in': 60,
                    'verification_uri_complete': 'https://app.example/t7-device?code=BCDF-GHJK'}
        if calls.count('device/poll/') < 2:
            return {'status': 'pending'}
        return {'status': 'approved', 'token': 't7_fromdevice', 'api_url': 'https://t7.example/api',
                'repository': 'acme/app', 'email': 'dev@acme.io', 'kind': 'developer',
                'expires_at': '2099-01-01T00:00:00Z'}
    monkeypatch.setattr(Byteramp, 'public', staticmethod(fake_public))
    monkeypatch.setattr('time.sleep', lambda s: None)
    registered = []
    monkeypatch.setattr('t7.editors.detect', lambda: [('VS Code', lambda: registered.append(1) or ('VS Code', 'added', 'x'))])
    args = type('A', (), {'default': False, 'api_url': None, 'token': False, 'no_editors': False, 'yes': True})()
    assert cli.cmd_setup(args) == 0
    key, entry = credentials.lookup(repo)
    assert entry['token'] == 't7_fromdevice' and entry['api_url'] == 'https://t7.byteramp.se/api'
    assert registered == [1]
    out = capsys.readouterr().out
    assert 'BCDF-GHJK' in out and 'acme/app' in out and 't7_fromdevice' not in out


def test_developer_token_renews_itself_when_close_to_expiry(repo, monkeypatch):
    from datetime import datetime, timedelta, timezone
    from t7 import access, credentials
    from t7.api import Byteramp
    from t7.config import Config
    soon = (datetime.now(timezone.utc) + timedelta(days=3)).isoformat()
    credentials.store('t7_old', 'https://t7.example/api', 'acme/app', repo, expires_at=soon, kind='developer')
    cfg = Config.load(repo)
    monkeypatch.setattr(Byteramp, 'rotate', lambda self: {'token': 't7_new', 'expires_at': '2099-01-01T00:00:00Z'})
    assert access.renew_if_due(cfg, Byteramp(cfg))
    assert cfg.token == 't7_new' and credentials.lookup(repo)[1]['token'] == 't7_new'
    # Far from expiry, or a T7_TOKEN from the environment: nothing happens.
    assert not access.renew_if_due(Config.load(repo), Byteramp(cfg))
    monkeypatch.setenv('T7_TOKEN', 't7_ci')
    assert not access.renew_if_due(Config.load(repo), Byteramp(cfg))


def test_editor_registration_merges_and_is_idempotent(tmp_path, monkeypatch):
    import json
    from t7 import editors
    monkeypatch.setattr(editors, '_home', lambda: tmp_path)
    monkeypatch.setattr(editors, '_vscode_user_dirs', lambda: [('VS Code', tmp_path / 'Code' / 'User')])
    monkeypatch.setattr(editors.shutil, 'which', lambda name: '/usr/local/bin/t7' if name == 't7' else None)
    (tmp_path / 'Code' / 'User').mkdir(parents=True)
    (tmp_path / 'Code' / 'User' / 'mcp.json').write_text(json.dumps({'servers': {'other': {'command': 'x'}}}))
    (tmp_path / '.cursor').mkdir()
    (tmp_path / '.codex').mkdir()
    first = {label: state for label, state, _ in editors.register()}
    assert first == {'VS Code': 'added', 'Cursor': 'added', 'Codex': 'added'}
    vs = json.loads((tmp_path / 'Code' / 'User' / 'mcp.json').read_text())
    assert vs['servers']['other'] == {'command': 'x'}                       # kept
    assert vs['servers']['triple-seven'] == {'type': 'stdio', 'command': '/usr/local/bin/t7', 'args': ['mcp']}
    assert 'T7_TOKEN' not in (tmp_path / '.cursor' / 'mcp.json').read_text()
    second = {label: state for label, state, _ in editors.register()}
    assert set(second.values()) == {'ok'}
    assert (tmp_path / '.codex' / 'config.toml').read_text().count('[mcp_servers.triple-seven]') == 1
    # JSON with comments is never rewritten.
    (tmp_path / '.cursor' / 'mcp.json').write_text('{ // mine\n "mcpServers": {} }')
    assert dict((l, s) for l, s, _ in editors.register())['Cursor'] == 'manual'


def test_mcp_scan_without_git_repo_asks_for_repo_path(tmp_path, monkeypatch):
    from t7 import mcp
    monkeypatch.chdir(tmp_path)
    monkeypatch.delenv('T7_REPO', raising=False)
    r = mcp.handle({'jsonrpc': '2.0', 'id': 1, 'method': 'tools/call',
                    'params': {'name': 't7_scan', 'arguments': {}}})
    assert r['result']['isError'] and 'repo_path' in r['result']['content'][0]['text']


def test_setup_in_new_project_folder_offers_git_init(tmp_path, monkeypatch):
    from t7 import cli
    proj = tmp_path / 'Felicia'
    proj.mkdir()
    monkeypatch.chdir(proj)
    monkeypatch.setattr(cli, '_browser_sign_in', lambda api, root: {
        'token': 't7_x', 'repository': 'Felicia', 'kind': 'developer', 'expires_at': None})
    args = type('A', (), {'default': False, 'api_url': None, 'token': False, 'no_editors': True, 'yes': True})()
    assert cli.cmd_setup(args) == 0
    assert (proj / '.git').is_dir()
    # Never in the home directory.
    monkeypatch.setattr('pathlib.Path.home', lambda: tmp_path)
    monkeypatch.chdir(tmp_path)
    assert cli._offer_git_init(assume_yes=True) is None and not (tmp_path / '.git').exists()
