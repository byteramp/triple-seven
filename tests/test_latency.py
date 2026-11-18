import io
import json
import urllib.error
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from t7 import mcp, trace
from t7.agents.analysts import review_batches
from t7.agents.mapper import map_architecture
from t7.agents.planner import plan
from t7.api import APIError, Byteramp
from t7.config import Config
from t7.gitops import ChangedFile, Hunk
from t7.llm import LLM, LLMError
from t7.trace import Tracer


def test_cpu_batches_keep_late_files_and_lines(tmp_path):
    files = []
    for n in range(3):
        path = f'file_{n}.py'
        lines = [f'value_{n}_{i} = {i}' for i in range(1500)]
        (tmp_path / path).write_text('\n'.join(lines))
        files.append(ChangedFile(path, 'A', [Hunk(1, len(lines), list(enumerate(lines, 1)))]))
    batches = list(review_batches(tmp_path, files, max_chars=8000))
    assert all(len(batch) <= 8000 for batch in batches)
    for n in range(3):
        assert f'value_{n}_1499 = 1499' in '\n'.join(batches)


def test_mapper_uses_cpu_budget_and_keeps_all_source(tmp_path):
    path = tmp_path / 'app.py'
    path.write_text('last_line()')
    source = '\n'.join(f'{n} | source_{n}()' for n in range(3000))
    model = Mock(cfg=Config(llm='byteramp'))
    model.json.return_value = {'components': [], 'flows': []}
    tracer = Tracer(quiet=True)
    map_architecture(tmp_path, [ChangedFile('app.py', 'A')], [], {'focus_files': []},
                     model, tracer, lambda *args: source)
    prompts = [call.args[2] for call in model.json.call_args_list]
    assert len(prompts) > 1
    assert max(map(len, prompts)) <= 8000
    assert 'source_2999()' in '\n'.join(prompts)
    assert any('batch 1/' in step['title'] for step in tracer.steps)


def test_planner_bounds_cpu_input_and_keeps_file_index():
    files = [ChangedFile(f'app_{n}.py', 'A', [Hunk(1, 25, [(i, 'x'*180) for i in range(1, 26)])])
             for n in range(40)]
    model = Mock(cfg=Config(llm='byteramp'))
    model.json.return_value = {}
    plan(files, {'secrets'}, [], SimpleNamespace(can_prove=False, stack=['python']),
         model, Tracer(quiet=True))
    prompt = model.json.call_args.args[2]
    assert len(prompt) <= 8000
    assert all(f'## app_{n}.py ' in prompt for n in range(40))


def test_server_model_timeout_is_not_repeated(monkeypatch):
    body = json.dumps({'detail': 'model time limit', 'retryable': False}).encode()
    request = Mock(side_effect=urllib.error.HTTPError('https://example.test', 504, 'timeout', {}, io.BytesIO(body)))
    monkeypatch.setattr('t7.api.open_request', request)
    monkeypatch.setattr('t7.llm.time.sleep', Mock(side_effect=AssertionError('must not retry')))
    with pytest.raises(LLMError, match='model time limit'):
        LLM(Config(), Byteramp(Config(token='test'))).complete('map', '', 'prompt')
    assert request.call_count == 1


def test_new_step_is_visible_before_work_starts(monkeypatch):
    api = Mock()
    events = []
    monkeypatch.setattr(trace, 'ON_STEP', lambda node: events.append(dict(node)))
    tracer = Tracer(api, 'run', quiet=True)
    with tracer.step('planner', 'Plan'):
        with tracer.step('mapper', 'Map batch'):
            sent = [step for call in api.steps.call_args_list for step in call.args[1]]
            assert any(step['agent'] == 'mapper' and step['status'] == 'running' for step in sent)
            assert events[-1]['status'] == 'running'
    assert [event['status'] for event in events] == ['running', 'running', 'done', 'done']


def test_mcp_reports_started_steps(monkeypatch):
    messages = []
    monkeypatch.setattr(mcp.SESSION, 'progress_token', 'progress')
    monkeypatch.setattr(mcp.SESSION, 'progress', 0)
    monkeypatch.setattr(mcp, '_write', messages.append)
    mcp.on_step({'status': 'running', 'agent': 'mapper', 'title': 'batch 1/8'})
    assert messages[0]['params']['progress'] == 1
    assert 'batch 1/8 (running)' in messages[0]['params']['message']
