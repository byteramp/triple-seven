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
    model.json.return_value = {'components': [], 'flows': []}
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


@pytest.mark.parametrize('response', [
    # Actual shape returned by the Copilot SDK when a sampling handler has no result.
    {'model': '', 'stopReason': 'cancelled', 'role': 'user',
     'content': {'type': 'text', 'text': 'The user cancelled the request.'}},
    {'model': 'test', 'stopReason': 'refusal', 'role': 'assistant',
     'content': {'type': 'text', 'text': 'Request refused.'}},
    {'model': 'test', 'role': 'assistant', 'content': {'type': 'image'}},
    {'model': 'test', 'role': 'assistant', 'content': {'type': 'text', 'text': ''}},
    [],
])
def test_editor_failure_is_not_json_repaired_or_retried(monkeypatch, response):
    from t7 import mcp
    request = Mock(return_value=response)
    monkeypatch.setattr(mcp, '_request', request)
    monkeypatch.setattr('t7.llm.time.sleep', Mock(side_effect=AssertionError('must not retry')))
    with pytest.raises(LLMError, match='No review completed') as error:
        LLM(Config(llm='client'), None).json('plan', 'system', 'prompt')
    assert 'invalid JSON' not in str(error.value)
    assert 'model access' in str(error.value)
    assert request.call_count == 1


def test_editor_provider_error_is_actionable_and_does_not_leak_body(monkeypatch):
    from t7 import mcp
    request = Mock(side_effect=RuntimeError('model_not_supported; private_source_text'))
    monkeypatch.setattr(mcp, '_request', request)
    with pytest.raises(LLMError, match='model_not_supported') as error:
        LLM(Config(llm='client'), None).json('plan', '', 'prompt')
    assert 'private_source_text' not in str(error.value)
    assert request.call_count == 1


def test_editor_truncated_response_cannot_pass_as_complete_json(monkeypatch):
    from t7 import mcp
    monkeypatch.setattr(mcp, '_request', Mock(return_value={
        'role': 'assistant', 'stopReason': 'maxTokens', 'model': 'test',
        'content': {'type': 'text', 'text': '{}'},
    }))
    with pytest.raises(LLMError, match='output limit'):
        LLM(Config(llm='client'), None).json('plan', '', 'prompt')


def test_editor_joins_text_blocks_and_ignores_other_content(monkeypatch):
    from t7 import mcp
    monkeypatch.setattr(mcp, '_request', Mock(return_value={
        'role': 'assistant', 'model': 'test', 'stopReason': 'endTurn',
        'content': [{'type': 'text', 'text': '{"ok":'}, {'type': 'image'},
                    {'type': 'text', 'text': 'true}'}],
    }))
    model = LLM(Config(llm='client'), None)
    assert model.json('plan', '', 'prompt') == {'ok': True}
    assert model.model == 'client:test'
