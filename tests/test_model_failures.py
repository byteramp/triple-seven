from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from t7 import cli, policy
from t7.access import AccessError
from t7.agents.mapper import map_architecture
from t7.api import APIError
from t7.config import Config
from t7.gitops import ChangedFile
from t7.llm import LLM, LLMError
from t7.trace import Tracer


def test_empty_file_skips_model_and_preserves_signals():
    model = Mock()
    tracer = Tracer(quiet=True)
    signals = [{'kind': 'config', 'file': 'index.html', 'line': 1, 'detail': 'test'}]
    delta = map_architecture(None, [ChangedFile('index.html', 'A')], signals,
                             {'focus_files': []}, model, tracer, lambda *args: '')
    model.json.assert_not_called()
    assert delta == {'components': [], 'flows': [], 'signals': signals}
    assert tracer.steps[0]['status'] == 'skipped'


def test_removal_only_change_maps_remaining_source():
    model = Mock()
    model.json.return_value = {}
    map_architecture(None, [ChangedFile('app.py', 'M')], [], {'focus_files': []},
                     model, Tracer(quiet=True), lambda *args: '1 | remaining_source()')
    assert 'remaining_source()' in model.json.call_args.args[2]


def test_editor_only_policy_never_selects_cli(monkeypatch):
    monkeypatch.setattr('t7.assistants.installed', lambda: ['copilot'])
    cfg = Config()
    with pytest.raises(AccessError, match='Copilot Chat'):
        policy.apply(cfg, {'provider': 'editor', 'kind': 'sampling'}, can_sample=False)
    policy.apply(cfg, {'provider': 'editor', 'kind': 'sampling'}, can_sample=True)
    assert cfg.llm == 'client'


def test_bad_request_is_not_retried(monkeypatch):
    api = Mock()
    api.llm.side_effect = APIError(400, 'prompt missing')
    sleep = Mock()
    monkeypatch.setattr('t7.llm.time.sleep', sleep)
    with pytest.raises(LLMError, match='prompt missing'):
        LLM(Config(), api).complete('map', 'system', 'prompt')
    assert api.llm.call_count == 1
    sleep.assert_not_called()


def test_missing_copilot_has_actionable_error_without_retry(monkeypatch):
    from t7 import assistants
    run = Mock(return_value=SimpleNamespace(returncode=127, stdout='', stderr='CLI not found'))
    monkeypatch.setattr(assistants, '_run', run)
    with pytest.raises(LLMError, match='Copilot Chat'):
        LLM(Config(llm='assistant', assistant='copilot'), None).complete('map', '', 'prompt')
    assert run.call_count == 1


def test_cli_model_failure_is_concise(monkeypatch, capsys):
    monkeypatch.setattr(cli, 'cmd_scan', Mock(side_effect=LLMError('model unavailable')))
    with pytest.raises(SystemExit) as error:
        cli.main(['scan', '--all'])
    assert error.value.code == 2
    assert capsys.readouterr().err == 't7: model unavailable\n'
