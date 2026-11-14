"""Stored repository tokens (`t7 setup`).

Tokens are repository-scoped, so they are stored per local repository path,
plus an optional default for use outside a repository. The file is created
with 0600 permissions under the user's config directory. Precedence when
running: T7_TOKEN env var  >  token stored for this repository  >  default.
"""
import json
import os
from pathlib import Path


def path():
    base = os.environ.get('XDG_CONFIG_HOME') or str(Path.home() / '.config')
    return Path(base) / 't7' / 'credentials.json'


def _load():
    try:
        return json.loads(path().read_text())
    except (OSError, ValueError):
        return {}


def _save(data):
    p = path()
    p.parent.mkdir(parents=True, exist_ok=True)
    os.chmod(p.parent, 0o700)
    tmp = p.with_suffix('.tmp')
    fd = os.open(tmp, os.O_WRONLY | os.O_CREAT | os.O_TRUNC, 0o600)
    with os.fdopen(fd, 'w') as fh:
        json.dump(data, fh, indent=2)
    os.replace(tmp, p)


def store(token, api_url, repository, repo_root=None):
    data = _load()
    entry = {'token': token, 'api_url': api_url, 'repository': repository}
    if repo_root:
        data.setdefault('repos', {})[str(Path(repo_root).resolve())] = entry
    else:
        data['default'] = entry
    _save(data)


def lookup(repo_root=None):
    """The stored entry for this repository (or the default), or None."""
    data = _load()
    if repo_root:
        hit = (data.get('repos') or {}).get(str(Path(repo_root).resolve()))
        if hit:
            return hit
    return data.get('default')


def remove(repo_root=None):
    data = _load()
    if repo_root:
        (data.get('repos') or {}).pop(str(Path(repo_root).resolve()), None)
    else:
        data.pop('default', None)
    _save(data)
