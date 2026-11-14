"""Deterministic first pass over ADDED lines — fast, free, no LLM.

Produces (a) signals for the server-side threat model and (b) the "areas" the
planner uses to decide which specialist subagents to spawn. High recall by
design; the triage subagent removes false positives against real code.
"""
import re

from .context import lang_of

# kind → (languages or None for all, regex, area)
DETECTORS = [
    ('sql_construct', {'python'}, r'(execute|raw|extra)\s*\(\s*(f["\']|["\'].*%\s|["\'].*\.format\(|.*\+\s*\w)', 'data'),
    ('sql_construct', {'javascript', 'typescript'}, r'(query|execute|raw)\s*\(\s*`[^`]*\$\{', 'data'),
    ('sql_construct', {'go'}, r'(Query|Exec)(Context)?\(.*(Sprintf|\+\s*\w)', 'data'),
    ('shell_exec', {'python'}, r'(os\.system|os\.popen|subprocess\.\w+\(.*shell\s*=\s*True)', 'input'),
    ('shell_exec', {'javascript', 'typescript'}, r'child_process|\bexec(Sync)?\s*\(', 'input'),
    ('shell_exec', {'go'}, r'exec\.Command\(\s*"(sh|bash)"', 'input'),
    ('deserialization', {'python'}, r'pickle\.loads?|yaml\.load\((?!.*SafeLoader)|marshal\.loads|jsonpickle', 'input'),
    ('deserialization', {'javascript', 'typescript'}, r'node-serialize|unserialize\(', 'input'),
    ('ssrf_sink', {'python'}, r'requests\.(get|post|put|request)\(\s*(request\.|url\b|f["\'])', 'input'),
    ('ssrf_sink', {'javascript', 'typescript'}, r'(fetch|axios\.\w+)\(\s*(req\.|url\b|`)', 'input'),
    ('secret_literal', None, r'(?i)(api[_-]?key|secret|passwd|password|token|private[_-]?key)\s*[:=]\s*["\'][A-Za-z0-9/+_\-]{12,}["\']', 'secrets'),
    ('secret_literal', None, r'(AKIA[0-9A-Z]{16}|ghp_[A-Za-z0-9]{36}|sk-[A-Za-z0-9]{32,}|xox[bp]-[A-Za-z0-9-]{20,}|-----BEGIN (RSA |EC )?PRIVATE KEY)', 'secrets'),
    ('crypto_weak', None, r'(?i)\b(md5|sha1)\s*\(|DES\b|ECB|Math\.random\(\).*(token|secret|id)|random\.random\(\).*(token|secret)', 'crypto'),
    ('authz_change', {'python'}, r'(permission_classes|@login_required|@permission_required|IsAuthenticated|AllowAny|has_permission|has_object_permission|authentication_classes)', 'authz'),
    ('authz_change', {'javascript', 'typescript'}, r'(isAdmin|hasRole|authorize|requireAuth|@UseGuards|middleware.*auth)', 'authz'),
    ('auth_bypass_risk', {'python'}, r'AllowAny|csrf_exempt|authentication_classes\s*=\s*\[\s*\]', 'authz'),
    ('idor', {'python'}, r'\.(get|filter)\(\s*(pk|id)\s*=\s*(request\.|kwargs|self\.kwargs|\w+_id\b)', 'authz'),
    ('idor', {'javascript', 'typescript'}, r'findBy(Pk|Id)\(\s*req\.(params|query|body)', 'authz'),
    ('new_endpoint', {'python'}, r'^\s*(path|re_path|url)\(|@(app|router)\.(get|post|put|patch|delete|route)\(', 'surface'),
    ('new_endpoint', {'javascript', 'typescript'}, r'(app|router)\.(get|post|put|patch|delete)\(\s*["\'`]/', 'surface'),
    ('llm_prompt_untrusted', None, r'(?i)(prompt|messages|content)\s*[=:+].*(request\.|req\.|user_input|body\[|params\[)', 'llm'),
    ('llm_tool_call', {'python', 'javascript', 'typescript'},
     r'(?i)(\btools\s*=\s*\[|function_call|tool_choice|bind_tools|@tool\b|AgentExecutor|\.tool_calls\b)', 'llm'),
    ('llm_output_exec', None, r'(?i)(eval|exec|innerHTML|dangerouslySetInnerHTML|execute)\s*\(?.*(completion|response\.choices|llm|output_text|\.content)', 'llm'),
    ('iac_public_exposure', {'terraform', 'yaml'}, r'0\.0\.0\.0/0|publicly_accessible\s*=\s*true|acl\s*=\s*"public-read|block_public_acls\s*=\s*false|type:\s*LoadBalancer', 'iac'),
    ('pii_logging', None, r'(?i)(log(ger)?\.\w+|print|console\.log)\(.*(password|token|ssn|personnummer|email|card)', 'data'),
]
_COMPILED = [(k, langs, re.compile(rx), area) for k, langs, rx, area in DETECTORS]

LLM_IMPORTS = re.compile(r'(?i)\b(openai|anthropic|langchain|llama_index|ollama|transformers|'
                         r'@ai-sdk|bedrock|vertexai|generativeai|mistralai)\b')
DEP_FILES = {'requirements.txt', 'package.json', 'pyproject.toml', 'go.mod', 'Pipfile',
             'poetry.lock', 'package-lock.json', 'pnpm-lock.yaml', 'yarn.lock'}


def scan(changed):
    signals, areas = [], set()
    for f in changed:
        lang = lang_of(f.path)
        name = f.path.rsplit('/', 1)[-1]
        if name in DEP_FILES and f.added:
            areas.add('deps')
            signals.append({'kind': 'dependency_add', 'file': f.path, 'line': f.added[0][0],
                            'detail': f'{len(f.added)} dependency lines changed'})
        if lang == 'terraform' or '/k8s/' in f.path or f.path.endswith(('Dockerfile', '.tf')):
            areas.add('iac')
        if 'test' in f.path.lower():
            continue  # don't flag fixtures in tests
        for line_no, text in f.added:
            if LLM_IMPORTS.search(text):
                areas.add('llm')
            for kind, langs, rx, area in _COMPILED:
                if langs and lang not in langs:
                    continue
                if rx.search(text):
                    areas.add(area)
                    signals.append({'kind': kind, 'file': f.path, 'line': line_no,
                                    'detail': f'{kind} pattern on an added line'})
    # one signal per (kind, file, line)
    seen, uniq = set(), []
    for s in signals:
        k = (s['kind'], s['file'], s['line'])
        if k not in seen:
            seen.add(k)
            uniq.append(s)
    return uniq, areas
