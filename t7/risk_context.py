"""Finding-centred Python dependency and control context for baseline verification.

Source line numbers are preserved. The caller records exact included ranges and
must treat omitted callees as unknown, not as evidence that controls are absent.
Other languages retain the existing full-scope context until a parser exists.
"""
import ast

from . import gitops
from .agents.triage import _context


def _lines(node):
    return range(node.lineno,node.end_lineno+1)


def _names(node):
    return {n.id for n in ast.walk(node) if isinstance(n,ast.Name)} if node else set()


def _header(node):
    if isinstance(node,(ast.If,ast.While)):
        return range(node.lineno,node.test.end_lineno+1)
    if isinstance(node,(ast.For,ast.AsyncFor)):
        return range(node.lineno,node.iter.end_lineno+1)
    if isinstance(node,(ast.With,ast.AsyncWith)):
        return range(node.lineno,max(item.context_expr.end_lineno for item in node.items)+1)
    return _lines(node)


def _targets(node):
    if isinstance(node,ast.Assign):
        return set().union(*(_names(target) for target in node.targets))
    if isinstance(node,(ast.AnnAssign,ast.AugAssign)):
        return _names(node.target)
    if isinstance(node,(ast.For,ast.AsyncFor)):
        return _names(node.target)
    if isinstance(node,(ast.With,ast.AsyncWith)):
        return set().union(*(_names(item.optional_vars) for item in node.items))
    return set()


def context(root,h,changed):
    if h.file_path.endswith(('.md','.rst','.txt')):
        return '## '+h.file_path+' (reference data, not executable source)\n'+gitops.read(root,h.file_path,h.line_start or 1,h.line_end or h.line_start or 1,pad=5),[], 'reference literal and direct context'
    if not h.file_path.endswith('.py'):
        return _context(root,h,changed),[], 'full surrounding scope'
    source=gitops.contained_path(root,h.file_path).read_text(errors='replace')
    try:tree=ast.parse(source)
    except (SyntaxError,ValueError,RecursionError):
        return _context(root,h,changed),[], 'full surrounding scope; parser fallback'
    lines=source.splitlines()
    anchor=max(1,h.line_start or 1)
    functions=[n for n in ast.walk(tree) if isinstance(n,(ast.FunctionDef,ast.AsyncFunctionDef)) and n.lineno<=anchor<=n.end_lineno]
    if not functions:
        return _context(root,h,changed),[], 'full surrounding scope'
    fn=min(functions,key=lambda n:n.end_lineno-n.lineno)
    # Traverse this function's statements; nested callable bodies are separate scopes.
    nodes=[]
    def visit(node):
        nodes.append(node)
        if node is not fn and isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):
            return
        for child in ast.iter_child_nodes(node):visit(child)
    visit(fn)
    selected=set(range(min([fn.lineno]+[d.lineno for d in fn.decorator_list]),fn.body[0].lineno))
    selected.update(range(anchor,min(len(lines),max(anchor,h.line_end or anchor))+1))
    needed=_names(fn.args)|set().union(*(_names(d) for d in fn.decorator_list))
    # Include the complete statement owning the anchor, not an arbitrary character slice.
    statements=[n for n in nodes if isinstance(n,ast.stmt) and n is not fn and n.lineno<=anchor<=n.end_lineno]
    if statements:
        statement=min(statements,key=lambda n:n.end_lineno-n.lineno)
        selected.update(_header(statement))
        if isinstance(statement,(ast.With,ast.AsyncWith)):
            for item in statement.items:needed.update(_names(item.context_expr))
        elif isinstance(statement,(ast.If,ast.While)):
            needed.update(_names(statement.test))
        else:needed.update(_names(statement))
    # Keep enclosing branches and every earlier early-exit guard. Unrelated UI
    # branches without a control effect are not source-to-sink context.
    for node in nodes:
        if getattr(node,'lineno',anchor+1)>=anchor:continue
        if isinstance(node,(ast.If,ast.While,ast.For,ast.AsyncFor,ast.With,ast.AsyncWith,ast.Assert)):
            enclosing=node.lineno<=anchor<=node.end_lineno
            exits=any(isinstance(n,(ast.Return,ast.Raise,ast.Break,ast.Continue)) and n.lineno<anchor for n in ast.walk(node))
            test=getattr(node,'test',None) or getattr(node,'iter',None)
            if enclosing or exits or _names(test)&needed or isinstance(node,ast.Assert):
                selected.update(_header(node));needed.update(_names(test))
        if isinstance(node,(ast.Raise,ast.Return,ast.Break,ast.Continue)):
            # The early-exit control is the return/raise, not a large UI value.
            selected.add(node.lineno)
    # Backward dependencies include mutation calls and context-manager bindings.
    definitions=[n for n in nodes if _targets(n)]
    calls=[n for n in nodes if isinstance(n,ast.Expr) and isinstance(n.value,ast.Call) and n.lineno<anchor]
    changed_names=True
    while changed_names:
        before=set(needed)
        for node in definitions:
            if node.lineno>anchor or not (_targets(node)&needed):continue
            selected.update(_header(node))
            if isinstance(node,(ast.With,ast.AsyncWith)):
                for item in node.items:needed.update(_names(item.context_expr))
            else:needed.update(_names(getattr(node,'value',None) or getattr(node,'iter',None)))
        for node in calls:
            if _names(node)&needed:
                selected.update(_lines(node));needed.update(_names(node))
        changed_names=before!=needed
    for node in nodes:
        if isinstance(node,(ast.If,ast.While,ast.For,ast.AsyncFor,ast.With,ast.AsyncWith)) and any(node.lineno<=line<=node.end_lineno for line in selected):
            selected.update(_header(node))
    # Class permissions and query/authorization hooks can enforce remote boundaries.
    for cls in (n for n in ast.walk(tree) if isinstance(n,ast.ClassDef) and n.lineno<=anchor<=n.end_lineno):
        selected.update(range(cls.lineno,cls.body[0].lineno))
        for node in cls.body:
            if isinstance(node,(ast.Assign,ast.AnnAssign)):
                selected.update(_lines(node));needed.update(_names(node))
            if isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node is not fn and any(term in node.name.lower() for term in ('permission','auth','queryset','get_object','dispatch','initial')):
                selected.update(_lines(node));needed.update(_names(node))
    # Retain imports, related globals and small local helpers actually called on the path.
    omitted=[]
    while True:
        before=set(needed)
        for node in tree.body:
            if isinstance(node,(ast.Import,ast.ImportFrom)):
                aliases={a.asname or a.name.split('.')[0] for a in node.names}
                if aliases&needed or '*' in aliases:selected.update(_lines(node))
            elif isinstance(node,(ast.Assign,ast.AnnAssign)) and _targets(node)&needed:
                selected.update(_lines(node));needed.update(_names(node))
            elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)) and node is not fn and node.name in needed:
                body='\n'.join(lines[node.lineno-1:node.end_lineno])
                if len(body)<=3000:
                    selected.update(_lines(node));needed.update(_names(node))
                elif node.name not in omitted:omitted.append(node.name)
        if needed==before:break
    output=[];ranges=[];last=0
    for line in sorted(selected):
        if not 1<=line<=len(lines):continue
        if last and line!=last+1:output.append('  ... [unselected source; do not assume missing controls]')
        if not ranges or line!=ranges[-1][1]+1:ranges.append([line,line])
        else:ranges[-1][1]=line
        output.append(f'{line:>5} | {lines[line-1]}');last=line
    file=next((f for f in changed if f.path==h.file_path),None)
    if file:
        output.extend(f'-- removed near line {part.start} | {line}' for part in file.hunks if fn.lineno<=part.start<=fn.end_lineno for line in part.removed_lines)
    note=('\nLocal helper bodies omitted (request more context before relying on them): '+', '.join(omitted)) if omitted else ''
    return f'## {h.file_path} (dependency and control context; gaps explicit){note}\n'+'\n'.join(output),ranges,'Python dependency and control context'
