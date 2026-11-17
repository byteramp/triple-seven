"""Best-effort minimisation for persisted agent metadata; not a source-code detector."""
import re

_FENCES = re.compile(r'```.*?(```|$)', re.S)
_INLINE = re.compile(r'`[^`\n]+`')
_SECRETS = re.compile(
    r'\b(?:t7_[A-Za-z0-9_-]{16,}|sk-[A-Za-z0-9_-]{16,})'
    r'|\bBearer\s+[^\s,;]+'
    r'|\b(?:password|api[_-]?key|secret|access[_-]?token)\s*[=:]\s*[^\s,;]+', re.I)
_CODE = re.compile(r'^\s*(?:def |class |import |from \w.* import |function |const |let |var |'
                   r'SELECT .+ FROM |INSERT INTO |UPDATE .+ SET )', re.I)


def text(value, limit=4000):
    value = _INLINE.sub('[code omitted]', _FENCES.sub('[code omitted]', str(value or '')))
    value = _SECRETS.sub('[secret omitted]', value)
    return '\n'.join('[code omitted]' if _CODE.match(line) else line
                     for line in value.splitlines())[:limit]


def clean(value):
    if isinstance(value, str):
        return text(value)
    if isinstance(value, dict):
        return {text(key, 100): clean(item) for key, item in value.items()}
    if isinstance(value, list):
        return [clean(item) for item in value]
    return value
