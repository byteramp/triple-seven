"""Versioned repo maps. Git shares only the binding; dirty review state is worktree-local."""
import hashlib
import json
import os
import re
import tempfile
from pathlib import Path

from . import __version__, gitops, repo_graph
from .access import AccessError


class MapError(AccessError):
    pass


def digest(value):
    return hashlib.sha256(json.dumps(value, sort_keys=True, separators=(',', ':')).encode()).hexdigest()


def _atomic(path, value):
    path.parent.mkdir(parents=True, exist_ok=True)
    with tempfile.NamedTemporaryFile('w', dir=path.parent, delete=False) as stream:
        try:
            json.dump(value, stream, sort_keys=True)
            stream.close()
            os.replace(stream.name, path)
        finally:
            Path(stream.name).unlink(missing_ok=True)


def marker_path(root):
    target = root / '.t7' / 'repository.json'
    if target.parent.is_symlink() or target.is_symlink():
        raise MapError('The T7 repository marker must be a regular file inside the checkout.')
    return target


def _load(path):
    try:
        return json.loads(path.read_text())
    except (OSError, ValueError):
        return None


def changed_paths(root, base, ignore, ci):
    args = ['diff', '--name-only', '--no-renames', '-z', base]
    if ci:
        args.append('HEAD')
    names = [os.fsdecode(raw) for raw in gitops._git_bytes(root, *args).split(b'\0')]
    if not ci:
        names.extend(os.fsdecode(raw) for raw in gitops._git_bytes(root, 'ls-files', '--others', '--exclude-standard', '-z').split(b'\0'))
    return {p for p in names if p and not p.startswith('.t7/') and
            gitops.included_path(p, ignore)}


def _clean(root):
    return not gitops.git(root, 'status', '--porcelain', '-z', '--untracked-files=all', '--', '.',
                          ':(exclude).t7/**')


def _binding(pre, base):
    return {'format': 1, 'repository': pre['repository']['id'], 'baseline_commit': base}


def _read_marker(root, pre, baseline):
    marker = marker_path(root)
    if marker.exists() and (not baseline or _load(marker) != _binding(pre, baseline['head'])):
        raise MapError('Repository marker does not match the authenticated repository and its baseline. '
                       'Check origin, your checkout and t7 status.')


def _chunks(graph):
    # Stable buckets limit how much is uploaded after an edit. Split buckets for large repos.
    buckets = {}
    for path, node in sorted(graph.items()):
        bucket = hashlib.sha256(path.encode()).digest()[0] // 16
        buckets.setdefault(bucket, []).append([path, node])
    for entries in buckets.values():
        batch, size = [], 0
        for entry in entries:
            cost = len(json.dumps(entry)) + 2
            if batch and (size + cost > 220000 or len(batch) == 1024):
                yield digest(batch), batch
                batch, size = [], 0
            batch.append(entry)
            size += cost
        if batch:
            yield digest(batch), batch


def _source_state(root, paths):
    state = []
    for path in sorted(paths):
        try:
            data, reason = repo_graph.read_file(root, path)
        except (FileNotFoundError, NotADirectoryError):
            data, reason = None, 'absent'
        except (OSError, ValueError):
            data, reason = None, 'inaccessible'
        state.append([path, reason or hashlib.sha256(data).hexdigest()])
    return digest(state)


class MapReview:
    def __init__(self, root, cfg, api, pre, *, setup, ci, fix, requested, ref, rebuild=False):
        self.root, self.cfg, self.api, self.pre = root, cfg, api, pre
        self.setup, self.ci, self.fix, self.ref = setup, ci, fix, ref
        self.head = gitops.head_sha(root)
        self.cache = Path(gitops.git(root, 'rev-parse', '--absolute-git-dir').strip()) / 't7-map' / pre['repository']['id']
        self.model_head = (pre.get('architecture') or {}).get('head_sha')
        self.scope_key = digest(sorted(cfg.ignore_paths))
        self.key = digest([__version__, cfg.llm, cfg.llm_model, cfg.assistant, cfg.llm_base_url, cfg.ignore_paths,
                           pre.get('llm', {}).get('required'), pre.get('gate_policy'), fix, cfg.context,
                           cfg.test_command, cfg.lint_command, cfg.type_command, sorted(pre.get('suppressed_fingerprints') or [])])
        self.receipt_key = digest([self.key, pre.get('suppressed_fingerprints'), pre.get('open_findings'), cfg.api_url, pre.get('token', {}).get('kind')])
        self.done = None
        if setup:
            default = pre['repository']['default_branch']
            remote_head = gitops.git(root, 'rev-parse', '--verify', 'refs/remotes/origin/' + default, check=False).strip()
            if not pre.get('can_initialize'):
                raise MapError('Sign in with t7 setup --browser as the repository owner before setup-repo.')
            if ref != default or not self.head or remote_head != self.head or not _clean(root):
                raise MapError(f'On a clean {default} checkout, fetch origin and sync HEAD to origin/{default}, then retry.')
        start = requested or self.head
        history = gitops.git(root, 'rev-list', '--max-count=256', start).splitlines() if start else []
        if start:
            fork = gitops.git(root, 'merge-base', start, 'refs/remotes/origin/' + pre['repository']['default_branch'],
                              check=False).strip()
            if fork and fork not in history:
                history.append(fork)
        lookup = api._req('POST', 'maps/lookup/', {'commits': history, 'review_key': self.key, 'ref': ref})
        baseline = lookup['baseline']
        self.generation = baseline['generation'] if baseline else None
        self.replace = self.generation if rebuild else None
        if setup and baseline:
            current = _load(marker_path(root))
            if current is not None and (not isinstance(current, dict) or current.get('repository') != pre['repository']['id']):
                raise MapError('The marker belongs to another repository. Check origin and t7 status.')
        else:
            _read_marker(root, pre, baseline)
        if baseline and not rebuild and self.scope_key != baseline['scope_key']:
            raise MapError('Inventory exclusions changed. Ask the owner to run t7 setup-repo --rebuild and share the marker.')
        if setup and baseline and not rebuild:
            if gitops.run(['git', 'merge-base', '--is-ancestor', baseline['head'], self.head], root).returncode:
                raise MapError('Existing baseline belongs to another history. Fetch full history. After an intentional rewrite, use t7 setup-repo --rebuild.')
            self.mark(baseline['head'])
            self.done = self.previous(baseline, 'Repository already initialized.')
            return
        if not setup and not baseline:
            raise MapError('This repository has no completed shared baseline. Ask the repository owner to run t7 setup-repo.')
        anchor = (lookup.get('checkpoint') or baseline) if not setup else None
        self.anchor = anchor
        self.base = anchor['head'] if anchor else gitops.EMPTY_TREE
        if anchor and gitops.run(['git', 'merge-base', '--is-ancestor', self.base, start], root).returncode:
            raise MapError('No applicable reviewed ancestor. Fetch full Git history and integrate the initialized default branch.')
        # Keep locally generated reports and patches out of an ordinary git add.
        output = marker_path(root).parent
        output.mkdir(exist_ok=True)
        try:
            with (output / '.gitignore').open('x') as rules:
                rules.write('*\n!repository.json\n')
        except FileExistsError:
            pass
        self.clean = _clean(root)
        if ci and not self.clean:
            raise MapError('CI requires a clean checkout of the reviewed commit.')
        self.paths = changed_paths(root, self.base, cfg.ignore_paths, ci)
        if anchor and not self.paths and not ci:
            message = 'No source changes since the reviewed commit.'
            if anchor['review_key'] != self.key:
                message += ' The linked run used different review settings. No new assessment was performed.'
            self.done = self.previous(anchor, message)
            return
        self.state = self.fingerprint()
        receipt = _load(self.cache / 'last.json')
        if not setup and not ci and not self.clean and receipt and receipt.get('state') == self.state and receipt.get('pass'):
            self.done = {'no_changes': True, 'scope_message': 'This working copy already passed review.',
                         'run_id': receipt['run'], 'gate': {'verdict': 'pass'}, 'coverage': receipt['coverage']}
            return
        previous = self.fetch_graph(anchor) if anchor else {}
        self.graph = repo_graph.update(root, previous, self.paths)
        self.impacted = (repo_graph.affected(previous, self.graph, self.paths) - self.paths) if anchor else set()

    @staticmethod
    def previous(anchor, message):
        return {'no_changes': True, 'scope_message': message, 'run_id': anchor['run'],
                'gate': anchor['gate'], 'coverage': {'changed_files': 0, 'reviewed_files': 0,
                                                     'excluded_files': []}}

    def mark(self, head):
        _atomic(marker_path(self.root), _binding(self.pre, head))

    def fingerprint(self):
        return digest([self.generation, self.ref, self.head, self.base, self.receipt_key, _source_state(self.root, self.paths)])

    def fetch_graph(self, anchor):
        graph = {}
        for key in anchor['chunks']:
            if not re.fullmatch('[a-f0-9]{64}', key):
                raise MapError('Invalid repository map manifest.')
            path = self.cache / 'chunks' / key
            entries = _load(path)
            if digest(entries) != key:
                entries = self.api._req('GET', f'maps/chunks/{key}/')['entries']
                if digest(entries) != key:
                    raise MapError('Repository map failed verification. Retry after checking the connection.')
                _atomic(path, entries)
            graph.update(entries)
        return graph

    def expand(self, changed):
        for path in sorted(self.impacted):
            node = self.graph.get(path)
            if not node or node['kind'] == 'skipped':
                continue
            data, reason = repo_graph.read_file(self.root, path)
            if reason:
                raise MapError(f'Impacted file changed while opening it: {path}')
            lines = data.decode(errors='replace').splitlines()
            changed.append(gitops.ChangedFile(path, 'I', [gitops.Hunk(1, len(lines), list(enumerate(lines, 1)))]))

    def manifest(self, run_id):
        if (gitops.head_sha(self.root) != self.head or
                (not self.ci and gitops.current_branch(self.root) != self.ref) or
                changed_paths(self.root, self.base, self.cfg.ignore_paths, self.ci) != self.paths or
                self.fingerprint() != self.state):
            raise MapError('The checkout changed during review. Run t7 scan again.')
        if not self.clean or not _clean(self.root):
            if self.setup or self.ci:
                raise MapError('The checkout changed during review. Retry from a clean checkout.')
            return None
        original = set(self.anchor['chunks']) if self.anchor else set()
        keys = []
        for key, entries in _chunks(self.graph):
            if key not in original:
                self.api._req('POST', f'runs/{run_id}/map-chunks/', {'entries': entries, 'digest': key})
            keys.append(key)
        model_parent = None
        if self.model_head and re.fullmatch('[a-f0-9]{40}|[a-f0-9]{64}', self.model_head):
            if not gitops.run(['git', 'merge-base', '--is-ancestor', self.model_head, self.head], self.root).returncode:
                model_parent = self.model_head
        return {'chunks': keys, 'model_parent': model_parent, 'baseline': self.setup, 'review_key': self.key, 'scope_key': self.scope_key,
                'generation': self.generation, 'replace': self.replace}

    def complete(self, result):
        if self.setup:
            self.mark(self.head)
        if result['gate']['verdict'] == 'pass' and not (result.get('surfaced') or result.get('unconfirmed')):
            _atomic(self.cache / 'last.json', {'run': result['run_id'], 'state': self.state, 'pass': True,
                                               'coverage': result['coverage']})
