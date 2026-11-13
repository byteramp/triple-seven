"""Planner — builds the dynamic step chain for THIS diff.

Deterministic core (areas from signals + file kinds) so the chain is
reproducible; the LLM may add specialists for areas the regexes can't see
(e.g. business-logic / multi-tenant changes) but can never remove a
deterministic one.
"""
import json

from . import GROUND_RULES

SPECIALISTS = {
    'authz': 'Access control: authentication, authorization, object-level/tenant checks, IDOR',
    'injection': 'Injection & unsafe sinks: SQL, shell, template, deserialization, SSRF, path traversal',
    'llm': 'LLM/agent security (OWASP LLM Top-10 2025): prompt injection, excessive agency, output handling, data leakage',
    'iac': 'Infrastructure as code: exposure, IAM, encryption, network policy, container hardening',
    'secrets': 'Secrets, cryptography and sensitive-data handling (logging, storage, transport)',
    'logic': 'Business logic & multi-tenant invariants: state machines, money, quotas, race conditions',
}

AREA_TO_SPECIALIST = {'authz': 'authz', 'surface': 'authz', 'data': 'injection', 'input': 'injection',
                      'llm': 'llm', 'iac': 'iac', 'secrets': 'secrets', 'crypto': 'secrets'}

SYSTEM = GROUND_RULES + (
    "\nYou are the PLANNER. Given a list of changed files with a short excerpt of added lines, "
    "decide which additional specialist reviewers are needed beyond those already selected. "
    "Only add one if the excerpt gives a concrete reason. Return JSON: "
    '{"add": [{"specialist": one of ' + json.dumps(sorted(SPECIALISTS)) + ', "why": "..."}], '
    '"focus_files": ["path", ...], "risk": "low|medium|high"}'
)


def plan(changed, areas, signals, profile, llm, tracer, use_llm=True):
    with tracer.step('planner', 'Plan the review chain') as h:
        selected = {}
        for a in sorted(areas):
            sp = AREA_TO_SPECIALIST.get(a)
            if sp:
                selected.setdefault(sp, f'deterministic: {a} patterns in added lines')
        code_files = [f for f in changed if f.added]
        risk = 'high' if {'authz', 'llm', 'secrets'} & areas else ('medium' if areas else 'low')
        focus = sorted({s['file'] for s in signals})

        if use_llm and code_files:
            listing = []
            for f in code_files[:40]:
                sample = '\n'.join(t for _, t in f.added[:25])
                listing.append(f'## {f.path} (+{len(f.added)})\n{sample[:1500]}')
            data = llm.json('plan', SYSTEM, f"Already selected: {sorted(selected)}\n\n" +
                            '\n\n'.join(listing)[:24000], default={}) or {}
            for item in data.get('add', [])[:3]:
                sp = item.get('specialist')
                if sp in SPECIALISTS and sp not in selected:
                    selected[sp] = f"planner: {str(item.get('why', ''))[:160]}"
            focus = sorted(set(focus) | {p for p in data.get('focus_files', [])
                                         if any(p == f.path for f in code_files)})
            risk = data.get('risk', risk) if data.get('risk') in ('low', 'medium', 'high') else risk

        if not selected and code_files:
            selected['logic'] = 'default: no pattern hit, general secure-code review'

        chain = {
            'specialists': [{'name': k, 'why': v} for k, v in selected.items()],
            'risk': risk,
            'focus_files': focus[:50],
            'fix': True,
            'prove': profile.can_prove,
            'stack': profile.stack,
            'steps': ['map-architecture', 'threat-model', *[f'analyst:{k}' for k in selected],
                      'triage', 'critic', 'fix+verify', *(['prove'] if profile.can_prove else []),
                      'report'],
        }
        h.summary(f"{len(selected)} specialists ({', '.join(selected)}), risk {risk}, "
                  f"proof {'enabled' if profile.can_prove else 'unavailable (no test runner)'}")
        h.meta(chain=chain)
        return chain
