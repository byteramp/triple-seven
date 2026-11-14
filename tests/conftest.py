import pytest


@pytest.fixture(autouse=True)
def _isolated(monkeypatch, tmp_path_factory):
    # The suite runs the pipeline with fake models and no Byteramp API.
    monkeypatch.setenv('T7_ALLOW_OFFLINE', '1')
    monkeypatch.setenv('XDG_CONFIG_HOME', str(tmp_path_factory.mktemp('xdg')))
    monkeypatch.delenv('T7_TOKEN', raising=False)
