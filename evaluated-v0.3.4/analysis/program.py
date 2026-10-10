"""Project AST index and receiver-aware, conservative call graph."""
from dataclasses import dataclass, replace
from collections import defaultdict, Counter
from pathlib import Path
import re
from parser.java_parser import JavaParser


def walk(node):
    if node is not None:
        yield node
        for child in node.named_children:
            yield from walk(child)


def field(node, name):
    return node.child_by_field_name(name)


def split_types(text):
    result=[];depth=0;start=0
    for i,c in enumerate(text):
        if c=='<':depth+=1
        elif c=='>':depth-=1
        elif c==',' and depth==0:
            if text[start:i].strip():result.append(text[start:i].strip())
            start=i+1
    if text[start:].strip():result.append(text[start:].strip())
    return result


def simple(name):
    return re.sub(r'<.*>', '', name).replace('[]', '').split('.')[-1]


@dataclass
class Method:
    id: str
    owner: str
    name: str
    params: list
    node: object
    unit: object
    types: dict
    annotations: str
    declared_owner: str = ""
    return_type: str = ""

    def text(self, node):
        return self.unit['bytes'][node.start_byte:node.end_byte].decode('utf-8') if node else ''

    def event(self, node, kind, detail, **extra):
        expression = self.text(node)
        if self.declared_owner and self.declared_owner != self.owner:
            extra['inherited_from'] = self.declared_owner
        if kind == 'BRANCH':
            expression = self.text(field(node, 'condition'))
        if len(expression) > 1500:
            extra['expression_truncated'] = True
            expression = expression[:1500]
        return dict(file=self.unit['file'], line=node.start_point[0]+1,
                    method=self.id, kind=kind, expression=expression, detail=detail, **extra)


class Program:
    def __init__(self, root):
        self.root = Path(root).resolve()
        self.methods = {}
        self.classes = {}
        self.diagnostics = []
        self.stats = Counter()
        self._resolved = {}
        self._owners = {}
        parser = JavaParser()
        for path in sorted(self.root.rglob('*.java')):
            if any(x in path.relative_to(self.root).parts for x in ('target', '.git', 'build')):
                continue
            source = path.read_text(encoding='utf-8')
            tree = parser.parse(source)
            unit = dict(file=str(path.relative_to(self.root)), bytes=source.encode(), tree=tree)
            text = lambda n: unit['bytes'][n.start_byte:n.end_byte].decode() if n else ''
            package = next((text(n).removeprefix('package ').rstrip(';') for n in tree.root_node.named_children if n.type == 'package_declaration'), '')
            unit['package'] = package
            unit['imports'] = [text(n).removeprefix('import ').rstrip(';') for n in tree.root_node.named_children if n.type == 'import_declaration']
            if tree.root_node.has_error:
                self.diagnostics.append(dict(kind='parse_error', file=unit['file']))
            for cls in walk(tree.root_node):
                if cls.type not in ('class_declaration', 'interface_declaration'):
                    continue
                name = text(field(cls, 'name'))
                outer=[]
                parent=cls.parent
                while parent is not None:
                    if parent.type in ('class_declaration','interface_declaration'):
                        outer.append(text(field(parent,'name')))
                    parent=parent.parent
                owner = (package+'.' if package else '')+'.'.join(list(reversed(outer))+[name])
                body = field(cls, 'body')
                modifiers = next((text(n) for n in cls.named_children if n.type == 'modifiers'), '')
                parents = [text(n) for n in cls.named_children if n.type in ('super_interfaces', 'superclass', 'extends_interfaces')]
                types = {}
                for n in body.named_children:
                    if n.type == 'field_declaration':
                        for d in n.named_children:
                            if d.type == 'variable_declarator':
                                types[text(field(d,'name'))] = text(field(n,'type'))
                if owner in self.classes:
                    self.diagnostics.append(dict(kind='duplicate_class', owner=owner,
                                                 previous_file=self.classes[owner]['unit']['file'], file=unit['file']))
                type_params=next((n for n in cls.named_children if n.type=='type_parameters'),None)
                type_vars=[]
                if type_params:
                    for param in type_params.named_children:
                        first=next((c for c in param.named_children if c.type=='type_identifier'),None)
                        if first:type_vars.append(text(first))
                self.classes[owner] = dict(name=name, annotations=modifiers, parents=','.join(parents), unit=unit,
                                           fields=types, type_vars=type_vars, kind=cls.type)
                for n in body.named_children:
                    if n.type != 'method_declaration':
                        continue
                    params = []
                    for p in field(n,'parameters').named_children:
                        if p.type in ('formal_parameter', 'spread_parameter'):
                            params.append((text(field(p,'name')), text(field(p,'type')), p))
                    local_types = dict(types)
                    local_types.update({p:t for p,t,_ in params})
                    for d in walk(field(n,'body')):
                        if d.type == 'resource':
                            local_types[text(field(d,'name'))] = text(field(d,'type'))
                        if d.type == 'local_variable_declaration':
                            for v in d.named_children:
                                if v.type == 'variable_declarator':
                                    local_types[text(field(v,'name'))] = text(field(d,'type'))
                    method_name = text(field(n,'name'))
                    mid = owner+'#'+method_name+'('+','.join(t for _,t,_ in params)+')'
                    annotations = next((text(c) for c in n.named_children if c.type == 'modifiers'), '')
                    self.methods[mid] = Method(mid,owner,method_name,params,n,unit,local_types,annotations,owner,text(field(n,'type')))
        self._by_shape = defaultdict(list)
        self._by_name = defaultdict(set)
        self._children = defaultdict(set)
        self._bases = defaultdict(list)
        for owner, cls in self.classes.items():
            self._by_name[cls['name']].add(owner)
        for owner, cls in self.classes.items():
            parents=re.sub(r'\b(extends|implements)\b','',cls['parents'])
            for spec in split_types(parents):
                base_name=spec.split('<',1)[0].strip()
                owners=self.type_owners(base_name,cls['unit'])
                if not owners:
                    self.diagnostics.append(dict(kind='unresolved_parent_type',file=cls['unit']['file'],owner=owner,parent=spec))
                args=split_types(spec[spec.find('<')+1:spec.rfind('>')]) if '<' in spec else []
                for base in sorted(owners):
                    qualified=[]
                    for arg in args:
                        def qualify(match):
                            matches=self.type_owners(match.group(),cls['unit'])
                            return next(iter(matches)) if len(matches)==1 else match.group()
                        qualified.append(re.sub(r'[A-Za-z_$][\w.$]*',qualify,arg))
                    binding=dict(zip(self.classes[base]['type_vars'],qualified))
                    self._bases[owner].append((base,binding))
                    self._children[base].add(owner)
        self.materialize_inheritance()
        for method in self.methods.values():
            self._by_shape[(method.name, len(method.params))].append(method)
        self.edges = []
        for m in self.methods.values():
            for call in walk(field(m.node,'body')):
                if call.type == 'method_invocation':
                    targets = self.resolve(m,call)
                    for target in targets:
                        self.edges.append(dict(caller=m.id, callee=target.id, file=m.unit['file'], line=call.start_point[0]+1,
                                               dispatch='conservative' if len(targets)>1 else 'declared_receiver'))

        # Source reachability guards context-independent clean summaries.
        source_names={'getParameter','getHeader','getQueryString','getParameterValues'}
        self.may_create_source={m.id for m in self.methods.values()
                                if any(n.type=='method_invocation' and m.text(field(n,'name')) in source_names
                                       for n in walk(field(m.node,'body')))}
        callers=defaultdict(set)
        for edge in self.edges:
            callers[edge['callee']].add(edge['caller'])
        pending=list(self.may_create_source)
        while pending:
            callee=pending.pop()
            for caller in callers[callee]:
                if caller not in self.may_create_source:
                    self.may_create_source.add(caller);pending.append(caller)

    def materialize_inheritance(self):
        """Create declaration-backed inherited views; never invent missing bodies."""
        by_owner=defaultdict(list)
        for m in self.methods.values():by_owner[m.owner].append(m)
        done=set();active=set()
        def signature(m):
            return m.name,tuple(re.sub(r'<.*>','',t).split('.')[-1] for _,t,_ in m.params)
        def substitute(typ,binding):
            return re.sub(r'\b[A-Za-z_$][\w$]*\b',lambda x:binding.get(x.group(),x.group()),typ)
        def visit(owner):
            if owner in done:return
            if owner in active:
                self.diagnostics.append(dict(kind='inheritance_cycle',owner=owner));return
            active.add(owner)
            own=by_owner[owner]
            occupied={signature(m) for m in own}
            fields={}
            for base,binding in self._bases[owner]:
                visit(base)
                fields.update({k:substitute(t,binding) for k,t in self.classes[base]['fields'].items()})
                for method in list(by_owner[base]):
                    if re.search(r'\bprivate\b',method.annotations):continue
                    params=[(name,substitute(typ,binding),node) for name,typ,node in method.params]
                    mid=owner+'#'+method.name+'('+','.join(t for _,t,_ in params)+')'
                    inherited=replace(method,id=mid,owner=owner,params=params,
                                      types={k:substitute(t,binding) for k,t in method.types.items()},
                                      return_type=substitute(method.return_type,binding))
                    if signature(inherited) in occupied:continue
                    occupied.add(signature(inherited));own.append(inherited)
                    self.methods[mid]=inherited
            fields.update(self.classes[owner]['fields'])
            self.classes[owner]['fields']=fields
            for method in own:
                method.types={**fields,**method.types}
            active.remove(owner);done.add(owner)
        for owner in sorted(self.classes):visit(owner)

    def receiver_type(self,m,node):
        if node is None or m.text(node)=='this':
            return m.owner
        if m.text(node)=='super':
            return next((base for base,_ in self._bases[m.declared_owner or m.owner]
                         if self.classes[base]['kind']=='class_declaration'),'<unresolved-super>')
        if node.type == 'object_creation_expression':
            return m.text(field(node,'type'))
        if node.type == 'method_invocation':
            targets = self.resolve(m,node)
            if len(targets)==1:
                return targets[0].return_type
            name=m.text(field(node,'name'))
            return {'createStatement':'Statement','prepareStatement':'PreparedStatement','getConnection':'Connection'}.get(name,'')
        return m.types.get(m.text(node).removeprefix('this.'), m.text(node))

    def type_owners(self, receiver, unit):
        erased=re.sub(r'<.*>','',receiver).replace('[]','')
        if '.' in erased:
            options={erased,(unit['package']+'.' if unit['package'] else '')+erased}
            first,rest=erased.split('.',1)
            options.update(i+'.'+rest for i in unit['imports'] if i.split('.')[-1]==first)
            return {o for o in options if o in self.classes}
        typ=simple(receiver)
        if receiver in self.classes:
            return {receiver}
        explicit=[i for i in unit['imports'] if i.split('.')[-1]==typ]
        if explicit:
            return {i for i in explicit if i in self.classes}
        local=(unit['package']+'.' if unit['package'] else '')+typ
        if local in self.classes:
            return {local}
        wildcard={i[:-1]+typ for i in unit['imports'] if i.endswith('.*') and i[:-1]+typ in self.classes}
        return wildcard or set(self._by_name.get(typ,()))

    def resolve(self,m,call):
        self.stats['resolve_requests'] += 1
        key=(m.id,call.start_byte,call.end_byte)
        if key in self._resolved:
            self.stats['resolve_cache_hits'] += 1
            return self._resolved[key]
        self.stats['resolve_cache_misses'] += 1
        name=m.text(field(call,'name'))
        args=field(call,'arguments').named_children
        receiver=self.receiver_type(m,field(call,'object'))
        super_call=m.text(field(call,'object'))=='super'
        owner_key=(m.unit['package'],tuple(m.unit['imports']),receiver,super_call)
        if owner_key not in self._owners:
            owners=self.type_owners(receiver,m.unit)
            pending=[] if super_call else list(owners)
            while pending:
                base=pending.pop()
                for child in self._children.get(base,()):
                    if child not in owners:
                        owners.add(child);pending.append(child)
            self._owners[owner_key]=owners
        owners=self._owners[owner_key]
        candidates=[x for x in self._by_shape.get((name,len(args)),()) if x.owner in owners]
        # Disambiguate known argument types; unknown types retain all candidates.
        def compatible(target):
            for arg,(_,pt,_) in zip(args,target.params):
                at = 'String' if arg.type=='string_literal' else ('int' if arg.type=='decimal_integer_literal' else m.types.get(m.text(arg)))
                if at and simple(at)!=simple(pt) and simple(pt) not in ('Object',) and simple(pt) not in self.classes[target.declared_owner or target.owner]['type_vars']:
                    return False
            return True
        result=[x for x in candidates if compatible(x)]
        if m.text(field(call,'object')) in ('','this'):
            lexical_private=[x for x in self._by_shape.get((name,len(args)),())
                             if x.owner==(m.declared_owner or m.owner) and re.search(r'\bprivate\b',x.annotations) and compatible(x)]
            if lexical_private:
                result=lexical_private
        concrete=[x for x in result if field(x.node,'body') is not None]
        if concrete:
            result=concrete
        self._resolved[key]=result
        return result
