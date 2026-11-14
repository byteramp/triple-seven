"""Step chain recorder. Every subagent call becomes a node that streams to the
portal timeline (batched) and to the console. Summaries are prose — no code."""
import sys
import threading
import time
from contextlib import contextmanager
from datetime import datetime, timezone


def _now():
    return datetime.now(timezone.utc).isoformat()


ON_STEP = None   # optional callback(node) for finished steps (MCP progress)


class Tracer:
    ICON = {'running': '…', 'done': '✓', 'skipped': '·', 'failed': '✗'}

    def __init__(self, api=None, run_id=None, quiet=False):
        self.api, self.run_id, self.quiet = api, run_id, quiet
        self._seq = 0
        self._lock = threading.Lock()
        self._pending = {}
        self._last_flush = 0.0
        self.steps = []
        self._local = threading.local()

    def _next(self):
        with self._lock:
            self._seq += 1
            return self._seq

    @property
    def _parent(self):
        stack = getattr(self._local, 'stack', None)
        return stack[-1] if stack else None

    def _emit(self, node, force=False):
        with self._lock:
            self._pending[node['seq']] = dict(node)
            due = force or time.time() - self._last_flush > 1.5
        if due:
            self.flush()

    def flush(self):
        with self._lock:
            batch = list(self._pending.values())
            self._pending.clear()
            self._last_flush = time.time()
        if batch and self.api and self.run_id:
            try:
                self.api.steps(self.run_id, batch)
            except Exception:  # noqa: BLE001  — telemetry must never break a run
                pass

    def _print(self, node):
        if self.quiet:
            return
        depth = 0
        p = node.get('parent_seq')
        by_seq = {s['seq']: s for s in self.steps}
        while p:
            depth += 1
            p = by_seq.get(p, {}).get('parent_seq')
        icon = self.ICON.get(node['status'], ' ')
        dur = f" {node['duration_ms'] / 1000:.1f}s" if node.get('duration_ms') else ''
        line = f"{'  ' * depth}{icon} [{node['agent']}] {node['title']}{dur}"
        if node['status'] in ('done', 'failed') and node.get('summary'):
            line += f" — {node['summary'][:140]}"
        print(line, file=sys.stderr)

    @contextmanager
    def step(self, agent, title, **meta):
        node = {'seq': self._next(), 'parent_seq': self._parent, 'agent': agent, 'title': title,
                'status': 'running', 'summary': '', 'meta': meta, 'started_at': _now()}
        self.steps.append(node)
        stack = getattr(self._local, 'stack', None)
        if stack is None:
            stack = self._local.stack = []
        stack.append(node['seq'])
        t0 = time.time()
        self._emit(node)
        handle = _Handle(node)
        try:
            yield handle
            node['status'] = handle.status or 'done'
        except Exception as e:  # noqa: BLE001
            node['status'] = 'failed'
            node['summary'] = node['summary'] or f'{type(e).__name__}: {str(e)[:300]}'
            raise
        finally:
            stack.pop()
            node['finished_at'] = _now()
            node['duration_ms'] = int((time.time() - t0) * 1000)
            self._print(node)
            self._emit(node, force=node['parent_seq'] is None)
            if ON_STEP:
                try:
                    ON_STEP(node)
                except Exception:  # noqa: BLE001 — progress must never break a run
                    pass

    def skip(self, agent, title, reason):
        node = {'seq': self._next(), 'parent_seq': self._parent, 'agent': agent, 'title': title,
                'status': 'skipped', 'summary': reason, 'meta': {}, 'started_at': _now(),
                'finished_at': _now(), 'duration_ms': 0}
        self.steps.append(node)
        self._print(node)
        self._emit(node)

    def fork(self):
        """Capture the CURRENT step (in the calling thread) as parent for work that
        may run in another thread. Use: `f = tracer.fork()` then `with f:` in the worker."""
        parent = self._parent
        tracer = self

        class _Fork:
            def __enter__(self):
                self._saved = getattr(tracer._local, 'stack', None)
                tracer._local.stack = [parent] if parent else []

            def __exit__(self, *a):
                tracer._local.stack = self._saved if self._saved is not None else []
        return _Fork()


class _Handle:
    def __init__(self, node):
        self.node = node
        self.status = None

    def summary(self, text):
        self.node['summary'] = str(text)[:2000]

    def meta(self, **kw):
        self.node['meta'].update(kw)

    def skip(self, reason):
        self.status = 'skipped'
        self.node['summary'] = reason
