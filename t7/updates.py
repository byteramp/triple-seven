"""Update reminders (plan §0c, Phase U): at most one notice a day, from the version info
the Byteramp API returns anyway (no extra call to PyPI from this machine)."""
import json
import os
import re
import sys
import time
from pathlib import Path

from . import __version__


def parse(v):
    nums = re.findall(r'\d+', str(v or ''))[:3]
    return tuple(int(n) for n in nums) + (0,) * (3 - len(nums)) if nums else (0, 0, 0)


def _state_path():
    base = os.environ.get('XDG_CACHE_HOME') or str(Path.home() / '.cache')
    return Path(base) / 't7' / 'update.json'


def notice(info, force=False):
    """'t7 X is available — run `t7 update`' at most once a day, else ''."""
    latest = (info or {}).get('latest') or ''
    if not latest or parse(latest) <= parse(__version__):
        return ''
    p = _state_path()
    try:
        state = json.loads(p.read_text())
    except (OSError, ValueError):
        state = {}
    if not force and state.get('shown') == latest and time.time() - state.get('at', 0) < 86400:
        return ''
    try:
        p.parent.mkdir(parents=True, exist_ok=True)
        p.write_text(json.dumps({'shown': latest, 'at': time.time()}))
    except OSError:
        pass
    return f't7 {latest} is available (you have {__version__}) — run `t7 update`. What\'s new: {info.get("changelog_url", "")}'


def install_kind():
    prefix = Path(sys.prefix).resolve()
    if 'pipx' in prefix.parts:
        return 'pipx'
    data = Path(os.environ.get('XDG_DATA_HOME') or Path.home() / '.local' / 'share') / 't7' / 'venv'
    if data.exists() and prefix == data.resolve():
        return 'installer'
    return 'pip'


def update_command():
    kind = install_kind()
    if kind == 'pipx':
        return ['pipx', 'upgrade', 't7-agent']
    return [sys.executable, '-m', 'pip', 'install', '--upgrade', '--quiet', 't7-agent']
