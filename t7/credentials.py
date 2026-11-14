"""Stored repository tokens (`t7 setup`).

Tokens are repository-scoped, so they are stored per local repository path
(plus an optional default, `t7 setup --default`). The file lives under the
user's config directory with 0600 permissions. Precedence when running:
T7_TOKEN env var  >  token stored for this repository  >  stored default.
Developer tokens renew themselves here (see access.renew_if_due).
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


def key_for(repo_root):
    return str(Path(repo_root).resolve()) if repo_root else None


def store(token, api_url, repository, repo_root=None, expires_at=None, kind='developer', email=''):
    data = _load()
    entry = {'token': token, 'api_url': api_url, 'repository': repository,
             'expires_at': expires_at, 'kind': kind, 'email': email}
    if repo_root:
        data.setdefault('repos', {})[key_for(repo_root)] = entry
    else:
        data['default'] = entry
    _save(data)


def update(key, **fields):
    """Update the entry stored under `key` (a repo path, or None for the default)."""
    data = _load()
    entry = (data.get('repos') or {}).get(key) if key else data.get('default')
    if entry is None:
        return
    entry.update({k: v for k, v in fields.items() if v is not None})
    _save(data)


def lookup(repo_root=None):
    """(key, entry) stored for this repository, else the default, else (None, None)."""
    data = _load()
    if repo_root:
        k = key_for(repo_root)
        hit = (data.get('repos') or {}).get(k)
        if hit:
            return k, hit
    if data.get('default'):
        return None, data['default']
    return None, None


def entries():
    data = _load()
    out = [(k, v) for k, v in (data.get('repos') or {}).items()]
    if data.get('default'):
        out.append(('(default)', data['default']))
    return out


def remove(repo_root=None):
    data = _load()
    if repo_root:
        (data.get('repos') or {}).pop(key_for(repo_root), None)
    else:
        data.pop('default', None)
    _save(data)
