"""Intraprocedural Python source-flow discovery for a fast baseline.

Recognizes framework request/tool arguments and model/network outputs. Values
stay tainted through local expressions and helper calls; sanitizers are not
trusted merely because of their names. Custom cross-function source/sink paths
are outside this baseline pass; contextual change reviews remain separate.
"""
import ast
import re

from . import gitops

BOUNDARY=re.compile(r'(?:^|\.)(?:get|post|put|patch|delete|route|api_route|websocket|tool|command|api_view)$')
NETWORK={'recv','recvfrom','receive','receive_json','receive_text','receive_bytes'}
MODEL={'invoke','ainvoke','generate','agenerate','complete','acomplete','completion','chat'}


def name(node):
    if isinstance(node,ast.Name):return node.id
    if isinstance(node,ast.Attribute):return name(node.value)+'.'+node.attr
    if isinstance(node,ast.Call):return name(node.func)
    if isinstance(node,ast.Subscript):return name(node.value)
    return ''


class FlowIndex:
    def __init__(self,root,files):
        self.frames={};self.failed=set()
        for file in files:
            if not file.path.endswith('.py') or file.status=='D':continue
            try:tree=ast.parse(gitops.contained_path(root,file.path).read_text(errors='replace'))
            except (SyntaxError,ValueError,RecursionError):self.failed.add(file.path);continue
            aliases={}
            for node in ast.walk(tree):
                if isinstance(node,ast.Import):aliases.update((a.asname or a.name.split('.')[0],a.name) for a in node.names)
                elif isinstance(node,ast.ImportFrom):aliases.update((a.asname or a.name,(node.module or '')+'.'+a.name) for a in node.names)
            frames=[]
            def collect(nodes,inherited=frozenset()):
                for node in nodes:
                    if isinstance(node,ast.ClassDef):collect(node.body)
                    elif isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef)):
                        boundary=any(BOUNDARY.search(name(d.func if isinstance(d,ast.Call) else d)) for d in node.decorator_list) or any(a.arg in ('request','req') or name(a.annotation).rsplit('.',1)[-1] in ('Request','HttpRequest') for a in node.args.posonlyargs+node.args.args+node.args.kwonlyargs)
                        args=node.args.posonlyargs+node.args.args+node.args.kwonlyargs
                        taint=set(inherited)|{a.arg for a in args if a.arg in ('request','req') or (boundary and a.arg not in ('self','cls')) or name(a.annotation).rsplit('.',1)[-1] in ('Request','HttpRequest')}
                        frame=(node,taint,aliases);frames.append(frame)
                        self._analyse(frame)
                        collect(node.body,taint)
            collect(tree.body)
            self.frames[file.path]=frames

    @staticmethod
    def expression(node,taint,aliases):
        if node is None:return False
        raw=name(node)
        if raw in ('self.request', 'self.kwargs') or raw.startswith(('self.request.', 'self.kwargs.')):return True
        if raw and (raw in taint or any(raw.startswith(t+'.') for t in taint)):return True
        if isinstance(node,ast.Name):return aliases.get(node.id) in ('flask.request','bottle.request')
        if isinstance(node,ast.Attribute):
            first,_,rest=raw.partition('.')
            resolved=aliases.get(first,first)+'.'+rest
            if resolved.startswith(('flask.request.','bottle.request.','sys.stdin.')):return True
        if isinstance(node,ast.Call):
            called=name(node.func);first,_,rest=called.partition('.')
            resolved=aliases.get(first,first)+('.'+rest if rest else '')
            method=called.rsplit('.',1)[-1]
            if method in NETWORK or resolved.startswith(('requests.','httpx.','urllib.request.')):return True
            if method in MODEL and re.search(r'(?i)(llm|model|client|ollama|openai|anthropic|agent)',called):return True
            if called.endswith(('.chat.completions.create','.responses.create','.messages.create')):return True
            return any(FlowIndex.expression(value,taint,aliases) for value in list(node.args)+[kw.value for kw in node.keywords]) or (isinstance(node.func,ast.Attribute) and FlowIndex.expression(node.func.value,taint,aliases))
        return any(FlowIndex.expression(child,taint,aliases) for child in ast.iter_child_nodes(node))

    def _analyse(self,frame):
        fn,taint,aliases=frame
        nodes=[]
        def visit(node):
            nodes.append(node)
            if node is not fn and isinstance(node,(ast.FunctionDef,ast.AsyncFunctionDef,ast.ClassDef,ast.Lambda)):return
            for child in ast.iter_child_nodes(node):visit(child)
        visit(fn)
        while True:
            before=set(taint)
            for node in nodes:
                if isinstance(node,(ast.Assign,ast.AnnAssign,ast.NamedExpr,ast.AugAssign)) and self.expression(node.value,taint,aliases):
                    targets=node.targets if isinstance(node,ast.Assign) else [node.target]
                    for target in targets:
                        if isinstance(target,(ast.Tuple,ast.List)):taint.update(n.id for n in ast.walk(target) if isinstance(n,ast.Name))
                        elif name(target):taint.add(name(target))
                elif isinstance(node,(ast.For,ast.AsyncFor)) and self.expression(node.iter,taint,aliases):taint.add(name(node.target))
                elif isinstance(node,ast.Call) and isinstance(node.func,ast.Attribute) and node.func.attr in ('update','append','extend','insert','setdefault') and any(self.expression(value,taint,aliases) for value in node.args):taint.add(name(node.func.value))
            if before==taint:break

    def path_is_risk(self,path,line,call):
        if path in self.failed:return True
        frames=[frame for frame in self.frames.get(path,[]) if frame[0].lineno<=line<=frame[0].end_lineno]
        if not frames:return False  # no recognized lower-trust input in module initialization
        fn,taint,aliases=min(frames,key=lambda f:f[0].end_lineno-f[0].lineno)
        target=call.func.value if isinstance(call.func,ast.Attribute) and call.func.attr in ('open','read_text','read_bytes','write_text','write_bytes','unlink','extractall') else call.args[0] if call.args else None
        return self.expression(target,taint,aliases)


    def argument_is_input(self,path,line,node):
        frames=[frame for frame in self.frames.get(path,[]) if frame[0].lineno<=line<=frame[0].end_lineno]
        if not frames:return False
        fn,taint,aliases=min(frames,key=lambda f:f[0].end_lineno-f[0].lineno)
        return self.expression(node,taint,aliases)
