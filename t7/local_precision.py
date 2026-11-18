"""Precision checks for the defined intraprocedural baseline profile.

These checks remove literal diagnostic messages, token *counts*, data-file code
examples and locally constant SQL/HTTP destinations. Unknown direct source flows stay candidates; custom cross-function flows are outside this pass. No customer code is executed.
"""
import ast
import re

SENSITIVE=re.compile(r'(?i)(?:^|[._])(password|passwd|secret|api_key|access_token|refresh_token|id_token|auth_token|token|email|ssn|personnummer|card)(?:$|[._])')
LABEL=re.compile(r'(?i)\b(password|passwd|secret|api[_ -]?key|access[_ -]?token|auth[_ -]?token|token|email|ssn|personnummer|card)\b')


def _dynamic(node):
    if isinstance(node,ast.Constant):return False
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in ('len','bool','type'):
        return False
    if isinstance(node,ast.JoinedStr):return any(_dynamic(v.value) for v in node.values if isinstance(v,ast.FormattedValue))
    return True


def _sensitive(node):
    if isinstance(node,ast.Name):return bool(SENSITIVE.search(node.id))
    if isinstance(node,ast.Attribute):
        return bool(SENSITIVE.search(node.attr)) or _sensitive(node.value)
    if isinstance(node,ast.Constant):return False
    if isinstance(node,ast.Call) and isinstance(node.func,ast.Name) and node.func.id in ('len','bool','type'):return False
    if isinstance(node,ast.Dict):
        return any((isinstance(k,ast.Constant) and LABEL.search(str(k.value)) and _dynamic(v)) or _sensitive(v) for k,v in zip(node.keys,node.values))
    return any(_sensitive(child) for child in ast.iter_child_nodes(node))


def logging_value(call):
    values=list(call.args)+[kw.value for kw in call.keywords if kw.arg not in ('exc_info','stack_info','stacklevel')]
    if any(_sensitive(value) for value in values):return True
    labels=' '.join(str(n.value) for value in values for n in ast.walk(value) if isinstance(n,ast.Constant) and isinstance(n.value,str))
    # Preserve hard-coded credential-looking output even without interpolation.
    if re.search(r'(?i)(?:password|secret|token|api[_ -]?key)\s*[=:]\s*[A-Za-z0-9_+/-]{8,}',labels):return True
    return bool(LABEL.search(labels)) and any(_dynamic(value) for value in values)


def refine(signals,root,files,flow=None):
    from . import gitops
    trees={}
    for file in files:
        if file.path.endswith('.py') and file.status!='D':
            try:trees[file.path]=ast.parse(gitops.contained_path(root,file.path).read_text(errors='replace'))
            except (SyntaxError,ValueError,RecursionError):pass
    output=[]
    for signal in signals:
        path=signal['file'];kind=signal['kind'];tree=trees.get(path)
        if kind=='crypto_weak' and path.endswith(('.yaml','.yml','.json')):
            file=next(f for f in files if f.path==path)
            line=dict(file.added).get(signal['line'],'')
            if not re.search(r'(?i)^\s*["\']?(?:cipher|algorithm|hash_algorithm|crypto_mode)["\']?\s*[:=]',line):
                continue
        if kind in ('sql_construct','ssrf_sink') and tree:
            from .baseline import _name
            calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and node.lineno<=signal['line']<=node.end_lineno]
            relevant=[node for node in calls if (kind=='sql_construct' and _name(node.func).rsplit('.',1)[-1] in ('execute','executemany','raw','extra')) or (kind=='ssrf_sink' and _name(node.func).rsplit('.',1)[-1] in ('get','post','put','patch','request','urlopen'))]
            if relevant:
                resolved=[]
                for call in relevant:
                    scopes=[fn for fn in ast.walk(tree) if isinstance(fn,(ast.FunctionDef,ast.AsyncFunctionDef)) and fn.lineno<=call.lineno<=fn.end_lineno]
                    scope=min(scopes,key=lambda fn:fn.end_lineno-fn.lineno) if scopes else tree
                    index=1 if kind=='ssrf_sink' and _name(call.func).endswith('.request') else 0
                    argument=next((kw.value for kw in call.keywords if kw.arg=='url'),call.args[index] if len(call.args)>index else None)
                    value=literal_value(argument,scope)
                    constant=isinstance(value,str) and (kind=='sql_construct' or value.startswith(('https://','http://')))
                    within_known_flow=flow.argument_is_input(path,call.lineno,argument) if flow else True
                    resolved.append(constant or not within_known_flow)
                if all(resolved):continue
        if kind=='crypto_weak' and tree:
            nodes=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and node.lineno<=signal['line']<=node.end_lineno]
            weak_hash=[node for node in nodes if isinstance(node.func,(ast.Name,ast.Attribute)) and (node.func.id if isinstance(node.func,ast.Name) else node.func.attr).lower() in ('md5','sha1')]
            if weak_hash:
                scopes=[fn for fn in ast.walk(tree) if isinstance(fn,(ast.FunctionDef,ast.AsyncFunctionDef)) and fn.lineno<=signal['line']<=fn.end_lineno]
                scope=min(scopes,key=lambda fn:fn.end_lineno-fn.lineno) if scopes else None
                identifiers=' '.join(([scope.name] if scope else [])+[node.id for call in weak_hash for node in ast.walk(call) if isinstance(node,ast.Name)])
                if not re.search(r'(?i)(password|passwd|secret|token|auth|sign|salt|hmac|credential)',identifiers):continue
        if kind=='pii_logging' and tree:
            calls=[node for node in ast.walk(tree) if isinstance(node,ast.Call) and node.lineno<=signal['line']<=node.end_lineno and (isinstance(node.func,ast.Name) and node.func.id=='print' or isinstance(node.func,ast.Attribute) and re.search(r'(?i)log',ast.unparse(node.func.value)))]
            if calls and not any(logging_value(call) for call in calls):continue
        output.append(signal)
    return output


def literal_value(node,scope,seen=frozenset()):
    """Resolve only unambiguous literal assignments. Unknown writes stay unknown."""
    if isinstance(node,ast.Constant):return node.value
    if not isinstance(node,ast.Name) or node.id in seen:return None
    if isinstance(scope,(ast.FunctionDef,ast.AsyncFunctionDef)) and any(a.arg==node.id for a in scope.args.posonlyargs+scope.args.args+scope.args.kwonlyargs):return None
    values=[]
    nodes=[]
    def visit(item):
        nodes.append(item)
        if item is not scope and isinstance(item,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):return
        for child in ast.iter_child_nodes(item):visit(child)
    visit(scope)
    for item in nodes:
        if isinstance(item,(ast.For,ast.AsyncFor)) and any(isinstance(n,ast.Name) and n.id==node.id for n in ast.walk(item.target)):return None
        if isinstance(item,(ast.With,ast.AsyncWith)) and any(isinstance(n,ast.Name) and n.id==node.id for binding in item.items if binding.optional_vars is not None for n in ast.walk(binding.optional_vars)):return None
        targets=item.targets if isinstance(item,ast.Assign) else [item.target] if isinstance(item,(ast.AnnAssign,ast.AugAssign,ast.NamedExpr)) else []
        if any(isinstance(n,ast.Name) and n.id==node.id for target in targets for n in ast.walk(target)):
            if any(not isinstance(target,ast.Name) for target in targets):return None
            if isinstance(item,ast.AugAssign):return None
            value=literal_value(item.value,scope,seen|{node.id})
            if value is None:return None
            values.append(value)
    if values and all(value==values[0] for value in values):return values[0]
    return None
