"""Source-free file inventory and static import impact analysis.

Python import names resolve against all matching in-repository module paths (including
src layouts). Ambiguous matches are conservative. JavaScript and TypeScript support
literal relative imports, re-exports and require(). Dynamic/runtime dependencies,
package aliases and other languages have no inferred edges.
"""
import ast
import errno
import os
import posixpath
import re
import stat
from collections import defaultdict, deque
from pathlib import Path, PurePosixPath, PureWindowsPath

MAX_BYTES = 512_000
JS = {'.js', '.jsx', '.mjs', '.cjs'}
TS = {'.ts', '.tsx', '.mts', '.cts'}
_JS_TOKENS = re.compile(
    r'//[^\n]*|/\*[\s\S]*?(?:\*/|$)|`(?:\\[\s\S]|[^`\\])*(?:`|$)'
    r'|"(?:\\[^\n]|[^"\\\n])*(?:"|$)|\'(?:\\[^\n]|[^\'\\\n])*(?:\'|$)'
    r'|[A-Za-z_$][\w$]*|[^\s]'
)


def _entry(kind, imports=(), symbols=(), reason=None):
    node = {'kind': kind, 'imports': sorted(set(imports)), 'symbols': sorted(set(symbols))}
    if reason:
        node['reason'] = reason
    return node


def _parts(path):
    # Git uses '/' even on Windows. Reject drive/UNC and traversal on every OS.
    if not isinstance(path, str) or not path or '\0' in path or '\\' in path:
        raise ValueError('invalid repository graph path')
    parts = path.split('/')
    if any(part.casefold() in ('', '.', '..', '.git') or PureWindowsPath(part).drive for part in parts):
        raise ValueError('invalid repository graph path')
    return parts


def _read_fd(fd):
    mode = os.fstat(fd)
    if not stat.S_ISREG(mode.st_mode):
        return None, 'non-regular file'
    if mode.st_size > MAX_BYTES:
        return None, 'file exceeds 512 KB'
    with os.fdopen(fd, 'rb', closefd=False) as stream:
        data = stream.read(MAX_BYTES + 1)
    if len(data) > MAX_BYTES:
        return None, 'file exceeds 512 KB'
    if b'\0' in data:
        return None, 'binary file'
    return data, ''


def _contents(root, parts):
    """Open path without traversing repository symlinks, including parent directories."""
    if os.open in os.supports_dir_fd and hasattr(os, 'O_NOFOLLOW'):
        flags = os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK
        parent = os.open(root, flags | os.O_DIRECTORY)
        try:
            for name in parts[:-1]:
                child = os.open(name, flags | os.O_DIRECTORY, dir_fd=parent)
                os.close(parent)
                parent = child
            fd = os.open(parts[-1], flags, dir_fd=parent)
            try:
                return _read_fd(fd)
            finally:
                os.close(fd)
        finally:
            os.close(parent)
    target = root.joinpath(*parts)
    resolved = target.resolve(strict=True)
    if not resolved.is_relative_to(root) or resolved != target or not target.is_file():
        return None, 'symlink or non-regular file'
    fd = os.open(target, os.O_RDONLY | getattr(os, 'O_BINARY', 0))
    try:
        return _read_fd(fd)
    finally:
        os.close(fd)


def _python(path, source):
    try:
        tree = ast.parse(source)
    except (SyntaxError, ValueError, RecursionError):
        return _entry('python', reason='Python syntax could not be indexed')
    parent = list(PurePosixPath(path).parent.parts)
    imports = set()
    symbols = set()
    for node in ast.walk(tree):
        if isinstance(node, (ast.FunctionDef, ast.AsyncFunctionDef, ast.ClassDef)):
            symbols.add(node.name)
        if isinstance(node, ast.Import):
            for item in node.names:
                bits = item.name.split('.')
                imports.update('py:' + '.'.join(bits[:i]) for i in range(1, len(bits) + 1))
        if isinstance(node, ast.ImportFrom):
            module = node.module.split('.') if node.module else []
            # "from package import name" may reference a submodule as well as a symbol.
            if node.level:
                if node.level - 1 > len(parent):
                    continue
                prefix = parent[:len(parent) - node.level + 1]
                stem = 'py-local:'
                separator = '/'
            else:
                prefix = []
                stem = 'py:'
                separator = '.'
            base = prefix + module
            imports.update(stem + separator.join(base[:i]) for i in range(1, len(base) + 1))
            imports.update(stem + separator.join(base + [alias.name]) for alias in node.names if alias.name != '*')
    return _entry('python', imports, symbols)


def _javascript(path, kind, source):
    try:
        source = source.decode('utf-8-sig')
    except UnicodeError:
        return _entry(kind, reason='unsupported text encoding')
    tokens = [match.group() for match in _JS_TOKENS.finditer(source)
              if not match.group().startswith(('//', '/*'))]
    imports, symbols = set(), set()
    for i, token in enumerate(tokens):
        if token in ('class', 'function', 'interface', 'type', 'const', 'let', 'enum'):
            nxt = i + 2 if tokens[i + 1:i + 2] == ['*'] else i + 1
            if nxt < len(tokens) and re.fullmatch(r'[A-Za-z_$][\w$]*', tokens[nxt]):
                symbols.add(tokens[nxt])
        if token not in ('import', 'require', 'from'):
            continue
        j = i + 1
        if tokens[j:j + 1] == ['('] and token in ('require', 'import'):
            j += 1
            if tokens[j + 1:j + 2] not in ([')'], [',']):
                continue
        if j >= len(tokens):
            continue
        literal = tokens[j]
        if len(literal) < 3 or literal[0] not in '"\'' or literal[0] != literal[-1]:
            continue
        spec = literal[1:-1]
        if not spec.startswith(('./', '../')) or not re.fullmatch(r'[\w./ @+-]+', spec):
            continue
        target = posixpath.normpath(posixpath.join(posixpath.dirname(path), spec))
        if target != '..' and not target.startswith('../'):
            imports.add('local:' + target)
    return _entry(kind, imports, symbols)


def read_file(root, path):
    """Read bounded regular-file bytes without following symlinks. Missing files raise."""
    return _contents(root, _parts(path))


def _node(root, path):
    try:
        source, reason = read_file(root, path)
    except FileNotFoundError:
        return None
    except OSError as exc:
        reason = 'symlink or non-regular file' if exc.errno in (errno.ELOOP, errno.ENOTDIR) else 'unreadable file'
        return _entry('skipped', reason=reason)
    if reason:
        return _entry('skipped', reason=reason)
    ext = posixpath.splitext(path)[1].lower()
    if ext in {'.py', '.pyi'}:
        return _python(path, source)
    if ext in JS | TS:
        return _javascript(path, 'javascript' if ext in JS else 'typescript', source)
    return _entry('file')


def build(root, paths):
    """Build an inventory for the explicitly selected Git paths."""
    return update(root, {}, paths)


def update(root, graph, paths):
    """Return an updated inventory. For moves, provide both old and new paths."""
    root = Path(root).resolve(strict=True)
    result = graph.copy()
    for path in sorted(set(paths)):
        node = _node(root, path)
        if node is None:
            result.pop(path, None)
        else:
            result[path] = node
    return result


def _aliases(path):
    yield 'local:' + path
    stem, ext = posixpath.splitext(path)
    if ext in {'.py', '.pyi'}:
        if posixpath.basename(stem) == '__init__':
            stem = posixpath.dirname(stem)
        yield 'py-local:' + stem
        parts = stem.split('/')
        for i in range(len(parts)):
            if all(p.isidentifier() for p in parts[i:]):
                yield 'py:' + '.'.join(parts[i:])
    if ext in JS | TS:
        yield 'local:' + stem
        if posixpath.basename(stem) == 'index':
            yield 'local:' + posixpath.dirname(stem)
        # Node-style TS projects commonly import the emitted .js filename.
        emitted = {'.ts': '.js', '.tsx': '.js', '.mts': '.mjs', '.cts': '.cjs'}.get(ext)
        if emitted:
            yield 'local:' + stem + emitted


def affected(old, new, changed_paths):
    """Return changed paths and transitive importers, resolving edges before and after edits."""
    reverse = defaultdict(set)
    for graph in (old, new):
        targets = defaultdict(list)
        for path in graph:
            for alias in _aliases(path):
                targets[alias].append(path)
        for path, node in graph.items():
            for dependency in node['imports']:
                for target in targets.get(dependency, ()):
                    reverse[target].add(path)
    seen = set(changed_paths)
    pending = deque(seen)
    while pending:
        current = pending.popleft()
        for importer in reverse.get(current, ()):
            if importer not in seen:
                seen.add(importer)
                pending.append(importer)
    return seen
