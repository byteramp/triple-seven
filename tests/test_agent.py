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
