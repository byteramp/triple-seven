from types import SimpleNamespace
from t7.signals import scan
from t7.agents.prover import _test_context


def test_crypto_names_do_not_match_swedish_words():
    files=[SimpleNamespace(path='app.py',added=[(1,'# Mailet skickades när koden användes.'),(2,'cipher = DES.new(key, DES.MODE_ECB)'),(3,'digest = hashlib.md5(password)')])]
    signals,_=scan(files)
    assert [s['line'] for s in signals if s['kind']=='crypto_weak']==[2,3]


def test_prover_receives_existing_test_conventions(tmp_path,monkeypatch):
    (tmp_path/'tests').mkdir()
    (tmp_path/'tests/test_api.py').write_text('from types import SimpleNamespace\ndef test_api(): pass\n')
    monkeypatch.setattr('t7.agents.prover.gitops.git',lambda *args:'tests/test_api.py\napp.py')
    context=_test_context(tmp_path,'pytest')
    assert 'tests/test_api.py (existing; do not overwrite)' in context
    assert 'SimpleNamespace' in context


def test_late_finding_keeps_early_function_guard(tmp_path):
    from t7.agents.triage import _context
    source = "# header\n" * 800 + "def endpoint(request):\n    if not request.user.is_staff:\n        raise PermissionError()\n" + "    # unrelated work\n" * 90 + "    return db.execute(request.GET['sql'])\n"
    (tmp_path/'views.py').write_text(source)
    hypothesis=SimpleNamespace(file_path='views.py',line_start=894,line_end=894)
    context=_context(tmp_path,hypothesis,[])
    assert 'request.user.is_staff' in context
    assert 'db.execute' in context
    assert '# header' not in context


def test_enclosing_function_does_not_erase_removed_controls(tmp_path):
    from t7.agents.triage import _context
    (tmp_path/'views.py').write_text('def endpoint(request):\n    return request.GET["value"]\n')
    file=SimpleNamespace(path='views.py',status='M',hunks=[SimpleNamespace(start=2,removed_lines=['    require_staff(request)'])])
    hypothesis=SimpleNamespace(file_path='views.py',line_start=2,line_end=2)
    assert 'removed near line 2 |     require_staff(request)' in _context(tmp_path,hypothesis,[file])


def test_class_controls_are_in_context_and_rejection_hash(tmp_path):
    from t7.agents.triage import _context,region_hash
    source = 'class View:\n    permission_classes = [IsAdminUser]\n' + '    # padding\n' * 100 + '    def get(self, request):\n        return export_records()\n'
    (tmp_path/'views.py').write_text(source)
    hypothesis=SimpleNamespace(file_path='views.py',line_start=104,line_end=104)
    before=region_hash(tmp_path,hypothesis)
    assert 'permission_classes = [IsAdminUser]' in _context(tmp_path,hypothesis,[])
    (tmp_path/'views.py').write_text(source.replace('[IsAdminUser]','[AllowAny]'))
    assert before != region_hash(tmp_path,hypothesis)
