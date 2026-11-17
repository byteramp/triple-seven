from contextlib import nullcontext
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock, patch

import pytest

from t7.agents.analysts import review_batches, run_analysts
from t7.agents.fixer import Verifier, apply_edits
from t7.api import Byteramp
from t7.config import Config
from t7.gitops import ChangedFile, Hunk, contained_path
from t7.llm import LLM, LLMError
from t7.trace import Tracer


def test_repository_cannot_redirect_token_or_provider_key(tmp_path, monkeypatch):
    (tmp_path / '.t7.json').write_text('{"api_url":"https://attacker.invalid","llm_base_url":"https://attacker.invalid","offline":true}')
    monkeypatch.setenv('T7_TOKEN', 't7_example')
    monkeypatch.delenv('T7_API_URL', raising=False)
    monkeypatch.delenv('T7_LLM_BASE_URL', raising=False)
    cfg = Config.load(tmp_path)
    assert cfg.api_url == 'https://t7.byteramp.se/api'
    assert cfg.llm_base_url == ''
    assert not cfg.offline
    monkeypatch.setenv('T7_API_URL', 'https://trusted.example/api')
    assert Config.load(tmp_path).api_url == 'https://trusted.example/api'


def test_specialist_failure_cannot_become_empty_success():
    with patch('t7.agents.analysts._run_one', side_effect=LLMError('unavailable')):
        with pytest.raises(LLMError):
            run_analysts({'specialists': [{'name': 'authz', 'why': 'test'}]},
                         [], Path('.'), None, Tracer(quiet=True))


def test_invalid_json_after_repair_fails():
    llm = LLM(Config(), None)
    with patch.object(llm, 'complete', return_value='invalid JSON'):
        with pytest.raises(LLMError, match='invalid JSON'):
            llm.json('critic', '', '', default={})


@pytest.mark.parametrize('response', [{}, {'still_vulnerable': False},
                                     {'still_vulnerable': 'false', 'breaks_behaviour': False}])
def test_invalid_fix_verification_cannot_pass(tmp_path, response):
    profile = SimpleNamespace(lint_cmd='', type_cmd='', test_cmd='')
    verifier = Verifier(tmp_path, profile, Config(), SimpleNamespace(json=lambda *a, **kw: response),
                        Tracer(quiet=True))
    finding = SimpleNamespace(rule='analyst.authz', file_path='a.py', title='test', cwe='', description='')
    with patch('t7.agents.fixer.gitops.worktree', return_value=nullcontext(tmp_path)),          patch('t7.agents.fixer.apply_edits', return_value=(True, '')),          patch('t7.agents.fixer.structural_problems', return_value=[]),          patch('t7.agents.fixer.gitops.git', return_value=''),          patch('t7.agents.fixer.gitops.changed_files', return_value=[]):
        checks, _, _ = verifier.verify(finding, [{'file': 'a.py'}])
    assert checks['recheck'] == 'fail'


def test_edits_reject_absolute_symlink_and_partial_application(tmp_path):
    root = tmp_path / 'root'
    root.mkdir()
    outside = tmp_path / 'outside'
    outside.write_text('original')
    inside = root / 'inside'
    inside.write_text('original')
    (root / 'link').symlink_to(outside)
    for path in (str(outside), 'link', '../outside', 'C:\\outside.txt'):
        ok, _ = apply_edits(root, [{'file': 'inside', 'find': 'original', 'replace': 'changed'},
                                    {'file': path, 'find': 'original', 'replace': 'changed'}])
        assert not ok
        assert inside.read_text() == outside.read_text() == 'original'


def test_batching_reviews_late_files_and_late_lines(tmp_path):
    files = []
    for index in range(35):
        name = f'{index}.py'
        lines = [f'value_{index}_{n} = {n}' for n in range(900)]
        (tmp_path / name).write_text('\n'.join(lines))
        files.append(ChangedFile(name, 'A', [Hunk(1, 900, list(enumerate(lines, 1)))]))
    batches = list(review_batches(tmp_path, files))
    joined = '\n'.join(batches)
    assert all(f'## {index}.py ' in joined for index in range(35))
    assert 'value_34_899 = 899' in joined
    assert all(len(batch) < 37000 for batch in batches)


def test_removed_control_is_visible_to_analysis(tmp_path):
    from t7.agents.analysts import changed_region_listing
    (tmp_path / 'a.py').write_text('do_sensitive_work()')
    file = ChangedFile('a.py', 'M', [Hunk(1, 0, removed_lines=['require_admin()'])])
    assert 'require_admin()' in changed_region_listing(tmp_path, file)
    assert 'do_sensitive_work()' in changed_region_listing(tmp_path, file)


def test_metadata_redacts_without_touching_model_prompt():
    from t7.metadata import clean
    value = clean({'summary': 'password=example-secret', 'meta': {'body': 'def unsafe(): pass'}})
    assert 'example-secret' not in str(value)
    assert 'def unsafe' not in str(value)
    api = Byteramp(Config(token='t7_example'))
    with patch('t7.api.open_request') as request:
        request.return_value.__enter__.return_value.read.return_value = b'{}'
        api.llm('map', '', 'def actual_source(): pass')
        assert b'def actual_source' in request.call_args.args[0].data


def test_authenticated_redirects_cannot_leak_credentials():
    import urllib.error
    import urllib.request
    from t7.transport import SameOriginRedirect
    request = urllib.request.Request('https://trusted.example/api', headers={'Authorization': 'Bearer fake'})
    for destination in ('https://attacker.invalid/api', 'http://trusted.example/api'):
        with pytest.raises(urllib.error.HTTPError, match='Cross-origin'):
            SameOriginRedirect().redirect_request(request, None, 302, '', {}, destination)


def test_ci_marks_pending_before_a_model_failure(tmp_path, monkeypatch):
    from t7 import orchestrator
    context = {'kind': 'github', 'head_sha': 'a'*40}
    monkeypatch.setattr(orchestrator.gitops, 'repo_root', lambda: tmp_path)
    monkeypatch.setattr(orchestrator.Config, 'load', lambda root: Config(token='fake'))
    monkeypatch.setattr(orchestrator, 'github_context', lambda: context)
    monkeypatch.setattr(orchestrator, 'set_github_status', Mock())
    monkeypatch.setattr(orchestrator.gitops, 'resolve_base', Mock(side_effect=RuntimeError('git failed')))
    with pytest.raises(RuntimeError):
        orchestrator.scan_repo(ci=True)
    orchestrator.set_github_status.assert_called_once_with(context, 'pending')
