"""Whole-repository local discovery. AI receives candidate risk paths, not every file.

No finding is confirmed here. Every candidate still needs real-code verification.
Structural events (an endpoint, dependency or decorator appearing) are inventory,
not evidence of a vulnerability.
"""
import ast
import re
from collections import Counter
from pathlib import PurePosixPath

from . import gitops
from .agents import Hypothesis
from .agents.analysts import fingerprint
from .rules import CODE_RULES
from .signals import scan

INVENTORY_ONLY = {'new_endpoint', 'authz_change', 'dependency_add'}
EXTRA = [
    ('mass_assignment', {'python'}, r'\bfields\s*=\s*["\']__all__["\']'),
    ('jwt_noverify', None, r'verify_signature["\']?\s*[:=]\s*(?:False|false)|\bverify\s*=\s*False'),
    ('dynamic_exec', {'python'}, r'\b(?:eval|exec)\s*\('),
    ('dynamic_exec', {'javascript', 'typescript'}, r'\b(?:eval|Function)\s*\('),
    ('nosql_query', {'javascript', 'typescript'}, r'\b(?:find|findOne|findById|findByPk)\s*\([^;\n]*(?:req\.(?:body|query|params)|\$where)' ),
    ('html_output', {'javascript', 'typescript'}, r'innerHTML\s*=|dangerouslySetInnerHTML|res\.(?:send|end)\(\s*(?:req\.|`[^`]*\$\{)' ),
    ('sql_construct', {'go'}, r'fmt\.Sprintf\(\s*["`](?:SELECT|UPDATE|INSERT|DELETE)\b'),
    ('privileged_action', None, r'\.(?:refund|transfer_funds|charge_card|delete_user|set_role)\s*\('),
]
EXTRA = [(kind, languages, re.compile(pattern, re.I if kind == 'sql_construct' else 0))
         for kind, languages, pattern in EXTRA]


def _name(node):
    if isinstance(node, ast.Name):
        return node.id
    if isinstance(node, ast.Attribute):
        return _name(node.value) + '.' + node.attr
    return ''


def _python_signals(source, file, added, flow):
    """Parse calls, including aliases and multiline arguments missed by line patterns."""
    tree = ast.parse(source)
    aliases = {}
    for node in ast.walk(tree):
        if isinstance(node, ast.Import):
            aliases.update((a.asname or a.name.split('.')[0], a.name) for a in node.names)
        elif isinstance(node, ast.ImportFrom):
            aliases.update((a.asname or a.name, (node.module or '') + '.' + a.name) for a in node.names)
    for node in ast.walk(tree):
        if not isinstance(node, ast.Call) or not any(line in added for line in range(node.lineno,node.end_lineno+1)):
            continue
        raw = _name(node.func)
        first, _, rest = raw.partition('.')
        name = aliases.get(first, first) + ('.' + rest if rest else '')
        kinds = []
        if name in ('eval','exec','builtins.eval','builtins.exec'):
            kinds.append('dynamic_exec')
        if name in ('open','builtins.open','send_file','flask.send_file','django.http.FileResponse') or raw.endswith(('.open','.read_text','.read_bytes','.write_text','.write_bytes','.unlink','.extractall')):
            if flow.path_is_risk(file.path,node.lineno,node):
                kinds.append('path_access')
        if name.startswith(('requests.','httpx.','urllib.request.')) and name.rsplit('.',1)[-1] in ('get','post','put','patch','delete','request','urlopen'):
            index=1 if name.endswith('.request') else 0
            url = next((kw.value for kw in node.keywords if kw.arg=='url'),node.args[index] if len(node.args)>index else None)
            if url is not None and not isinstance(url,ast.Constant):
                kinds.append('ssrf_sink')
        if raw.endswith(('.execute','.executemany','.raw','.extra')) and node.args:
            query=node.args[0]
            if not isinstance(query,ast.Constant):
                kinds.append('sql_construct')
        if name.startswith(('pickle.','marshal.','jsonpickle.')) and name.rsplit('.',1)[-1] in ('load','loads','decode'):
            kinds.append('deserialization')
        for kind in kinds:
            yield {'kind':kind,'file':file.path,'line':node.lineno,'detail':'Local syntax analysis identified a potential security-sensitive operation; input trust and controls are unverified.'}


def discover(root, changed, extra_signals=()):
    from .context import lang_of
    from .flow_index import FlowIndex
    signals,areas=scan(changed)
    signals.extend(extra_signals)
    flow=FlowIndex(root,changed)
    methods={}
    for file in changed:
        if not file.hunks or file.status=='D':
            methods[file.path]='diff and deterministic text checks'
            continue
        path=gitops.contained_path(root,file.path)
        source=path.read_text(errors='replace')
        language=lang_of(file.path)
        methods[file.path]='deterministic text checks'
        # Keep fixtures in inventory; application code is the risk candidate source.
        parts=PurePosixPath(file.path).parts
        if any(p in ('tests','test','__tests__') for p in parts) or PurePosixPath(file.path).name.startswith('test_'):
            continue
        for line,text in file.added:
            for kind,languages,pattern in EXTRA:
                if (not languages or language in languages) and pattern.search(text):
                    signals.append({'kind':kind,'file':file.path,'line':line,'detail':'Potential security-sensitive operation on an added line; exploitability is unverified.'})
        if language=='python':
            try:
                signals.extend(_python_signals(source,file,{line for line,_ in file.added},flow))
                methods[file.path]='Python intraprocedural source-flow and deterministic text checks'
            except (SyntaxError,ValueError,RecursionError):
                methods[file.path]='deterministic text checks; Python parser unavailable for this file'
    unique={}
    for signal in signals:
        if PurePosixPath(signal['file']).suffix.lower() in ('.md','.rst','.txt') and signal['kind']!='secret_literal':
            continue  # reference examples are data; runtime consumers are checked in executable source
        key=(signal['kind'],signal['file'],signal['line'])
        unique[key]=signal
    from .local_precision import refine
    unique_signals=refine(list(unique.values()),root,changed,flow)
    candidates=[]
    for signal in unique_signals:
        kind=signal['kind']; rule=CODE_RULES.get(kind)
        if not rule or kind in INVENTORY_ONLY:
            continue
        # A tool declaration alone is inventory. Runtime execution and dangerous
        # side effects remain candidates through their own detectors.
        if kind=='llm_tool_call':
            line=dict(next(f for f in changed if f.path==signal['file']).added).get(signal['line'],'')
            if re.search(r'\btools\s*=\s*\[|\bbind_tools\s*\(|@tool\b',line) and not re.search(r'tool_calls|function_call',line):
                continue
        subject=f"{signal['file']}:{signal['line']}"
        candidates.append(Hypothesis(fingerprint=fingerprint('signal.'+kind,subject),title=rule['title'],severity=rule['severity'],cwe=rule['cwe'],rule='signal.'+kind,owasp=rule.get('owasp',''),llm_code=rule.get('llm_code',''),stride=rule['stride'],file_path=signal['file'],line_start=signal['line'],line_end=signal['line'],description=signal['detail'],attack_scenario=rule['attack'],recommendation=rule['fix'],source='agent',origin='local-baseline'))
    return candidates,unique_signals,areas,methods


def architecture_inventory(changed,signals,known=None):
    """Source-module inventory, not inferred runtime network/data-flow assertions.

    Keep the existing living architecture; add explicit source-inventory nodes.
    Runtime trust boundaries require their own evidence, never default booleans.
    """
    from .context import lang_of
    groups={}
    for file in changed:
        if file.status=='D' or not lang_of(file.path):continue
        parts=PurePosixPath(file.path).parts
        if any(part in ('tests','test','__tests__') for part in parts):continue
        group=parts[0] if len(parts)>1 else 'project'
        groups.setdefault(group,Counter())[lang_of(file.path)]+=1
    existing={component.get('name'):component for component in (known or {}).get('components',[]) if component.get('name')}
    components=[]
    for group,languages in sorted(groups.items()):
        name='Source: '+group
        component=existing.get(name)
        if component:
            components.append({**component,'change':'modified'})
        else:
            components.append({'id':'c_'+fingerprint(name.casefold(),'function')[:20],'name':name,'kind':'function','trust_zone':'internal','data_classes':[],'tags':['source-inventory'],'change':'added'})
    current_names={component['name'] for component in components}
    for name,component in existing.items():
        if 'source-inventory' in component.get('tags',[]) and name not in current_names:
            components.append({**component,'change':'removed'})
    # No new network flows are asserted from imports, filenames or absent guards.
    return {'components':components,'flows':[],
            'signals':[dict(signal) for signal in signals[:200]],
            'inventory':{'method':'local-source-index','runtime_boundaries_inferred':False,
                         'modules':{key:dict(value) for key,value in groups.items()},
                         'signal_count':len(signals)}}


def plan_baseline(profile,hypotheses,tracer):
    with tracer.step('planner','Plan local checks and targeted AI verification') as step:
        risk='high' if any(h.severity in ('critical','high') for h in hypotheses) else 'medium' if hypotheses else 'low'
        chain={'specialists':[],'risk':risk,'focus_files':sorted({h.file_path for h in hypotheses}),
               'fix':True,'prove':profile.can_prove,'stack':profile.stack,
               'review_mode':'local-baseline-targeted-ai',
               'steps':['local-index','source-inventory','threat-model','targeted-verification','critic','fix+verify','report']}
        step.meta(chain=chain)
        step.summary(f'{len(hypotheses)} supported risk paths for AI; independent challenge before confirmation')
        return chain
