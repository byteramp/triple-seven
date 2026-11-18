import json
from types import SimpleNamespace
from unittest.mock import Mock
import pytest
from t7 import assistants,policy
from t7.config import Config
from t7.access import AccessError


def test_auto_router_result_uses_final_completed_response():
    events=[{'type':'assistant.message','data':{'content':'draft','model':'draft'}},
            {'type':'assistant.message','data':{'content':'{ "ok": true }','model':'available-model'}},
            {'type':'result','exitCode':0}]
    text,model=assistants._copilot_result('\n'.join(json.dumps(e) for e in events))
    assert json.loads(text)=={'ok':True}
    assert model=='auto/available-model'


@pytest.mark.parametrize('events', [
    [{'type':'assistant.message','data':{'content':'{}'}}, {'type':'result','exitCode':1}],
    [{'type':'assistant.message','data':{'content':'{}'}}],
    [{'type':'tool.execution_start','data':{}}, {'type':'result','exitCode':0}],
])
def test_incomplete_or_tool_using_response_cannot_pass(events):
    with pytest.raises(assistants.AssistantError):
        assistants._copilot_result('\n'.join(json.dumps(e) for e in events))


def test_explicit_copilot_runtime_respects_policy(monkeypatch):
    monkeypatch.setenv('T7_ASSISTANT','copilot')
    monkeypatch.setattr(assistants,'installed',lambda:['copilot','claude'])
    cfg=Config()
    policy.apply(cfg,{'provider':'editor','kind':'sampling,copilot'},can_sample=True)
    assert cfg.llm=='assistant' and cfg.assistant=='copilot'
    cfg=Config()
    policy.apply(cfg,{'provider':'editor','kind':'sampling'},can_sample=True)
    assert cfg.llm=='client'  # no widening of administrator policy
    cfg=Config()
    policy.apply(cfg,{'provider':'byteramp'},can_sample=True)
    assert cfg.llm=='byteramp'  # no cross-provider fallback


def test_copilot_runtime_isolated_and_tools_unavailable(monkeypatch,tmp_path):
    events='\n'.join(json.dumps(e) for e in [
        {'type':'assistant.message','data':{'content':'{}','model':'test'}},
        {'type':'result','exitCode':0}])
    run=Mock(return_value=SimpleNamespace(returncode=0,stdout=events,stderr=''))
    monkeypatch.setattr(assistants,'_run',run)
    monkeypatch.setattr('t7.credentials.path',lambda:tmp_path/'credentials.json')
    monkeypatch.setenv('COPILOT_GITHUB_TOKEN','test-oauth-token')
    monkeypatch.setenv('T7_TOKEN','must-not-reach-copilot')
    monkeypatch.setenv('COPILOT_PROVIDER_BASE_URL','https://unapproved.example')
    assistants.complete('copilot','system','prompt')
    cmd=run.call_args.args[0];env=run.call_args.kwargs['env']
    assert cmd[cmd.index('--model')+1]=='auto'
    assert '--available-tools=__t7_model_only__' in cmd and '--sync-session=off' in cmd
    assert env['COPILOT_HOME']==str(tmp_path/'copilot')
    assert env['COPILOT_GITHUB_TOKEN']=='test-oauth-token'
    assert 'T7_TOKEN' not in env and 'COPILOT_PROVIDER_BASE_URL' not in env


def test_runtime_timeout_is_not_retried(monkeypatch,tmp_path):
    from t7.llm import LLM,LLMError
    run=Mock(side_effect=assistants.AssistantError('copilot did not answer within 30s'))
    monkeypatch.setattr(assistants,'_run',run)
    monkeypatch.setattr(assistants,'_copilot_env',lambda cwd:{})
    with pytest.raises(LLMError):
        LLM(Config(llm='assistant',assistant='copilot'),None).complete('analyze','','prompt')
    assert run.call_count==1
