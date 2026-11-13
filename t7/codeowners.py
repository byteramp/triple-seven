"""CODEOWNERS → owning team per file (GitHub / GitLab syntax, last match wins)."""
import re
from pathlib import Path

LOCATIONS = ('.github/CODEOWNERS', 'CODEOWNERS', 'docs/CODEOWNERS', '.gitlab/CODEOWNERS')


def _pattern_to_regex(pat):
    anchored = pat.startswith('/')
    pat = pat.lstrip('/')
    if pat.endswith('/'):
        pat += '**'
    rx = ''
    i = 0
    while i < len(pat):
        if pat[i:i + 3] == '**/':
            rx += '(?:.*/)?'
            i += 3
        elif pat[i:i + 2] == '**':
            rx += '.*'
            i += 2
        elif pat[i] == '*':
            rx += '[^/]*'
            i += 1
        elif pat[i] == '?':
            rx += '[^/]'
            i += 1
        else:
            rx += re.escape(pat[i])
            i += 1
    if '/' not in pat.rstrip('*'):
        prefix = '' if anchored else '(?:.*/)?'      # bare name matches at any depth
    else:
        prefix = ''
    return re.compile(f'^{prefix}{rx}(?:/.*)?$')


class CodeOwners:
    def __init__(self, rules):
        self.rules = rules  # [(regex, [owners])]

    @classmethod
    def load(cls, root: Path):
        for loc in LOCATIONS:
            p = root / loc
            if p.exists():
                rules = []
                for line in p.read_text(errors='ignore').splitlines():
                    line = line.split('#', 1)[0].strip()
                    if not line or line.startswith('['):       # GitLab section headers
                        continue
                    parts = line.split()
                    owners = [o for o in parts[1:] if o.startswith('@') or '@' in o]
                    try:
                        rules.append((_pattern_to_regex(parts[0]), owners))
                    except re.error:
                        continue
                return cls(rules)
        return cls([])

    def owners(self, path):
        hit = []
        for rx, owners in self.rules:
            if rx.match(path):
                hit = owners
        return hit

