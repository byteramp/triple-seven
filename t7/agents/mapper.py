"""Mapper — derives the ABSTRACT architecture delta. This is the only artefact
that leaves the customer's boundary, so its schema is strict and contains no
code: ids, names, kinds, trust zones, data classes, booleans."""
import re

from . import GROUND_RULES

KINDS = {'service', 'datastore', 'external', 'llm', 'queue', 'function', 'client', 'iac_resource'}
ZONES = {'internet', 'dmz', 'internal', 'restricted'}
DATA = {'pii', 'credentials', 'secrets', 'payment', 'health', 'internal'}
CHANGES = {'added', 'modified', 'removed', 'unchanged'}

SYSTEM = GROUND_RULES + (
    "\nYou are the ARCHITECTURE MAPPER. From the changed code, describe ONLY the architecture "
    "the change touches, as an abstract model. Never include code, identifiers of secrets, or "
    "literal values. Return JSON: {\"components\": [{\"id\", \"name\", \"kind\": one of "
    f"{sorted(KINDS)}, \"trust_zone\": one of {sorted(ZONES)}, \"data_classes\": subset of "
    f"{sorted(DATA)}, \"tags\": [\"tools\"|\"agentic\"|\"public-endpoint\"|\"admin\"], "
    "\"change\": added|modified|unchanged}], \"flows\": [{\"id\", \"source\", \"target\", "
    "\"protocol\", \"authenticated\": bool, \"encrypted\": bool, \"data_classes\": [...], "
    "\"change\": added|modified|unchanged}]}. The browser/end user is a component with kind "
    "client in zone internet. Third-party APIs are kind external."
)

_ID = re.compile(r'[^a-z0-9_-]')


def _clean(delta):
    comps, ids = [], set()
    for c in (delta.get('components') or [])[:60]:
        cid = _ID.sub('-', str(c.get('id', '')).lower())[:60]
        if not cid or cid in ids:
            continue
        ids.add(cid)
        comps.append({
            'id': cid, 'name': str(c.get('name', cid))[:80],
            'kind': c.get('kind') if c.get('kind') in KINDS else 'service',
            'trust_zone': c.get('trust_zone') if c.get('trust_zone') in ZONES else 'internal',
            'data_classes': [d for d in (c.get('data_classes') or []) if d in DATA],
            'tags': [str(t)[:30] for t in (c.get('tags') or [])][:6],
            'change': c.get('change') if c.get('change') in CHANGES else 'modified',
        })
    flows = []
    for i, f in enumerate((delta.get('flows') or [])[:120]):
        s = _ID.sub('-', str(f.get('source', '')).lower())[:60]
        t = _ID.sub('-', str(f.get('target', '')).lower())[:60]
        if s in ids and t in ids:
            flows.append({
                'id': f'f{i + 1}', 'source': s, 'target': t,
                'protocol': str(f.get('protocol', ''))[:20],
                'authenticated': bool(f.get('authenticated', False)),
                'encrypted': bool(f.get('encrypted', True)),
                'data_classes': [d for d in (f.get('data_classes') or []) if d in DATA],
                'change': f.get('change') if f.get('change') in CHANGES else 'modified',
            })
    return {'components': comps, 'flows': flows}


def map_architecture(root, changed, signals, chain, llm, tracer, read):
    with tracer.step('mapper', 'Map the architecture delta') as h:
        focus = set(chain['focus_files'])
        files = sorted([f for f in changed if f.added],
                       key=lambda f: (f.path not in focus, -len(f.added)))[:25]
        parts = []
        for f in files:
            body = read(root, f.path)[:5000]
            parts.append(f'## {f.path} (status {f.status})\n{body}')
        data = llm.json('map', SYSTEM, '\n\n'.join(parts)[:60000], default={}) or {}
        delta = _clean(data)
        # Signals: kind + location only (no code) feed the threat model's code rules.
        delta['signals'] = [{'kind': s['kind'], 'file': s['file'], 'line': s['line'],
                             'detail': s['detail']} for s in signals[:200]]
        h.summary(f"{len(delta['components'])} components, {len(delta['flows'])} flows, "
                  f"{len(delta['signals'])} code signals")
        return delta
