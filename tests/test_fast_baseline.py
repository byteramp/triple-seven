import json
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import Mock

import pytest

from t7.agents import Hypothesis
from t7.baseline import discover,architecture_inventory
from t7.baseline_schema import verification
from t7.baseline_verify import _apply,_quote_line,batches
from t7.gitops import ChangedFile,Hunk
from t7.local_precision import literal_value
from t7.risk_context import context


def file(root,path,source):
    target=root/path;target.parent.mkdir(parents=True,exist_ok=True);target.write_text(source)
    lines=list(enumerate(source.splitlines(),1))
    return ChangedFile(path,'A',hunks=[Hunk(1,len(lines),added_lines=lines)])


def hypothesis(path='app.py',line=3):
    return Hypothesis(fingerprint='a'*64,title='SQL injection',severity='high',cwe='CWE-89',file_path=path,line_start=line,line_end=line)


def answer(vulnerable=False,**kw):
    return {'reason':'Bound input is treated as data.','vulnerable':vulnerable,'needs_context':False,'source_quote':'','sink_quote':'','control_quote':'',**kw}


def test_all_labelled_vulnerabilities_have_local_candidates(tmp_path):
    from bench.corpus import C
    for index,case in enumerate(C):
        if not case['vuln']:continue
        root=tmp_path/str(index);root.mkdir()
        changed=file(root,case['path'],case['code'])
        candidates,*_=discover(root,[changed])
        assert candidates,case['id']


def test_local_checks_do_not_call_or_execute_project_code(tmp_path):
    source="raise RuntimeError('must not execute')\ndef view(request):\n    return open(request.GET['path']).read()\n"
    changed=file(tmp_path,'app.py',source)
    candidates,_,_,methods=discover(tmp_path,[changed])
    assert any(h.cwe=='CWE-22' for h in candidates)
    assert 'intraprocedural' in methods['app.py']


def test_direct_and_indirect_scope_is_explicit(tmp_path):
    source="def helper(path):\n    return open(path).read()\n\ndef endpoint(request):\n    return helper(request.GET['path'])\n"
    changed=file(tmp_path,'app.py',source)
    _,_,_,methods=discover(tmp_path,[changed])
    assert methods['app.py'].startswith('Python intraprocedural')


def test_reference_examples_are_not_executable_crypto(tmp_path):
    changed=file(tmp_path,'guide.md','Example: hashlib.md5(password)\n')
    candidates,*_=discover(tmp_path,[changed])
    assert not candidates


def test_constant_diagnostic_messages_do_not_leak_credentials(tmp_path):
    changed=file(tmp_path,'app.py','print("No password configured")\nprint("token count", 3)\n')
    candidates,*_=discover(tmp_path,[changed])
    assert not any(h.cwe=='CWE-532' for h in candidates)


def test_actual_password_output_stays_a_candidate(tmp_path):
    changed=file(tmp_path,'app.py','def log(request):\n    password = request.POST["password"]\n    print(f"password={password}")\n')
    candidates,*_=discover(tmp_path,[changed])
    assert any(h.cwe=='CWE-532' for h in candidates)


def test_class_based_request_input_stays_a_candidate(tmp_path):
    changed=file(tmp_path,'app.py','import requests\nclass View:\n    def fetch(self):\n        return requests.get(self.request.GET["url"])\n')
    candidates,*_=discover(tmp_path,[changed])
    assert any(h.cwe=='CWE-918' for h in candidates)


def test_global_constant_cannot_hide_a_shadowed_query(tmp_path):
    changed=file(tmp_path,'app.py','query="SELECT 1"\ndef view(request,query):\n    return db.execute(query)\n')
    candidates,*_=discover(tmp_path,[changed])
    assert any(h.cwe=='CWE-89' for h in candidates)


def test_loop_write_cannot_be_treated_as_a_literal(tmp_path):
    changed=file(tmp_path,'app.py','def view(request):\n    query="SELECT 1"\n    for query in request.data:\n        db.execute(query)\n')
    candidates,*_=discover(tmp_path,[changed])
    assert any(h.cwe=='CWE-89' for h in candidates)


def test_constant_sql_is_not_input_interpolation(tmp_path):
    changed=file(tmp_path,'app.py','def view(request):\n    query="SELECT 1"\n    return db.execute(query)\n')
    candidates,*_=discover(tmp_path,[changed])
    assert not any(h.cwe=='CWE-89' for h in candidates)


def test_request_method_checks_url_not_http_method(tmp_path):
    changed=file(tmp_path,'app.py','import requests\ndef view(request):\n    return requests.request("GET",request.GET["url"])\n')
    candidates,*_=discover(tmp_path,[changed])
    assert any(h.cwe=='CWE-918' for h in candidates)


def test_source_quote_returns_actual_line_not_window_start():
    rows={1:'import sqlite3',2:'',3:'def view(request):',4:'    value = request.GET["q"]',5:'    ignored = 1',6:'    return db.execute(value)'}
    assert _quote_line('return db.execute(value)',rows)==6
    assert _quote_line('request.GET["q"]',rows)==4
    assert _quote_line('not actually present',rows) is None
    assert _quote_line('if allowed:',{1:'# if allowed:'}) is None


@pytest.mark.parametrize('data',[{}, {'results':{}}, {'results':{'h0':answer(vulnerable='false')}}, {'results':{'h0':answer(),'unexpected':answer()}}])
def test_missing_or_malformed_verdict_cannot_pass(data):
    h=hypothesis()
    with pytest.raises(Exception):_apply([('h0',h,{3:'db.execute(value)'},[])],data)


def test_unmatched_evidence_is_unconfirmed_not_verified():
    h=hypothesis()
    _apply([('h0',h,{3:'db.execute(value)'},[])],{'results':{'h0':answer(True,source_quote='imagined source',sink_quote='imagined sink')}})
    assert h.verdict=='uncertain' and h.proof_level=='L0'


def test_evidence_quotes_never_leave_in_finding_metadata():
    h=hypothesis(line=4)
    source='password = request.POST["password"]';sink='db.execute(password)'
    _apply([('h0',h,{3:source,4:sink},[])],{'results':{'h0':answer(True,source_quote=source,sink_quote=sink)}})
    assert h.line_start==4 and h.proof_level=='L1'
    metadata=json.dumps(h.to_api(True))
    assert source not in metadata and sink not in metadata


def test_helper_parameter_alone_cannot_confirm_attacker_input(tmp_path):
    changed=file(tmp_path,'helper.py','import subprocess\ndef run(cmd):\n    return subprocess.run(cmd, shell=True)\n')
    h=Hypothesis(fingerprint='f'*64,title='Command injection',severity='high',cwe='CWE-78',
                 file_path='helper.py',line_start=3,line_end=3)
    items,_=next(batches([h],tmp_path,[changed]))
    _apply(items,{'results':{'h0':answer(True,source_quote='def run(cmd):',sink_quote='subprocess.run(cmd, shell=True)')}})
    assert h.verdict=='uncertain' and h.proof_level=='L0'


def test_reference_credential_needs_authenticity_validation(tmp_path):
    changed=file(tmp_path,'cases.yaml','example: |\n    API_KEY = "syntheticcredential123"\n')
    h=Hypothesis(fingerprint='f'*64,title='Possible credential',severity='high',cwe='CWE-798',
                 rule='signal.secret_literal',file_path='cases.yaml',line_start=2,line_end=2)
    items,_=next(batches([h],tmp_path,[changed]))
    _apply(items,{'results':{'h0':answer(True,source_quote='syntheticcredential123',sink_quote='syntheticcredential123')}})
    assert h.verdict=='uncertain' and h.proof_level=='L0'


def test_early_class_guards_are_preserved(tmp_path):
    source='class View:\n    permission_classes = [IsAdminUser]\n    def get(self, request):\n        if not request.user.is_staff:\n            raise PermissionError()\n'+'        # padding\n'*90+'        return open(request.GET["path"]).read()\n'
    changed=file(tmp_path,'app.py',source)
    h=hypothesis(line=len(source.splitlines()))
    text,_,_=context(tmp_path,h,[changed])
    assert 'permission_classes = [IsAdminUser]' in text and 'request.user.is_staff' in text


def test_inventory_does_not_invent_runtime_flows(tmp_path):
    changed=file(tmp_path,'api/app.py','import requests\n')
    delta=architecture_inventory([changed],[])
    assert delta['components'][0]['tags']==['source-inventory']
    assert delta['flows']==[]
    assert delta['inventory']['runtime_boundaries_inferred'] is False


@pytest.mark.parametrize('ids',[[],['h1','h1'],['not-a-risk'],['h0']*17])
def test_response_identifiers_are_bounded(ids):
    with pytest.raises(ValueError):verification(ids)
