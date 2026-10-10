"""Static MyBatis XML expansion with lexical aliases and explicit gaps.
This models may-dependencies, not OGNL evaluation or executable SQL generation.
"""
from pathlib import Path
import re
import xml.etree.ElementTree as ET


class MapperIndex:
    def __init__(self,root):
        self.statements={}
        self.fragments={}
        self.diagnostics=[]
        self._diagnostic_keys=set()
        sources=[]
        for path in sorted(Path(root).rglob('*.xml')):
            if any(p in ('target','build','.git') for p in path.parts):continue
            try:
                raw=path.read_text(encoding='utf-8')
                tree=ET.fromstring(raw)
            except (ET.ParseError,UnicodeError) as e:
                self.issue('xml_parse_error',str(path.relative_to(root)),str(e));continue
            if tree.tag!='mapper':continue
            ns=tree.get('namespace','')
            file=str(path.relative_to(root))
            for element in tree:
                name=element.get('id')
                if not name:continue
                match=re.search(r'<'+element.tag+r'\b[^>]*\bid\s*=\s*[\"\']'+re.escape(name)+r'[\"\']',raw)
                line=raw[:match.start()].count('\n')+1 if match else 1
                record=dict(node=element,namespace=ns,file=file,line=line,id=name)
                if element.tag=='sql':self.fragments[ns+'.'+name]=record
                elif element.tag in ('select','insert','update','delete'):sources.append(record)
        for record in sources:
            refs=[];locations=[]
            text=self.expand(record['node'],record,{}, {},[],refs,locations)
            self.statements[(record['namespace'],record['id'])]=dict(
                file=record['file'],line=record['line'],sql=text,references=refs,fragments=locations,
                readonly_parameters=record['node'].tag=='select' and not any(n.tag=='selectKey' for n in record['node'].iter()))

    def issue(self,kind,file,detail):
        key=(kind,file,detail)
        if key not in self._diagnostic_keys:
            self._diagnostic_keys.add(key)
            self.diagnostics.append(dict(kind=kind,file=file,detail=detail))

    def roots(self,expression,aliases):
        # Remove strings before extracting identifiers: "constant" is not a parameter.
        cleaned=re.sub(r"'(?:[^'\\]|\\.)*'|\"(?:[^\"\\]|\\.)*\"",'',expression)
        if not re.fullmatch(r'[\w.\s+()\[\],?:!=<>\-*/]*',cleaned):
            return set(),False
        result=set()
        for match in re.finditer(r'(?<![\w.])([A-Za-z_$][\w$]*)',cleaned):
            name=match.group(1)
            if name in ('null','true','false'):continue
            if cleaned[match.end():].lstrip().startswith('('):continue
            result.update(aliases.get(name,{name}))
        return result,True

    def expand(self,node,record,aliases,properties,stack,refs,locations,resolution_namespace=None):
        resolution_namespace=resolution_namespace or record['namespace']
        local=dict(aliases)
        def substitute(text):
            text=text or ''
            return re.sub(r'\$\{\s*([\w.]+)\s*\}',lambda m:properties.get(m.group(1),m.group(0)),text)
        def capture(text):
            text=substitute(text)
            for expression in re.findall(r'\$\{([^}]+)\}',text):
                roots,known=self.roots(expression,local)
                if not known:self.issue('unsupported_ognl',record['file'],expression)
                refs.append(dict(expression=expression,roots=sorted(roots),file=record['file'],line=record['line'],known=known))
            return text
        pieces=[capture(node.text)]
        for child in node:
            if child.tag=='include':
                ref=substitute(child.get('refid',''))
                key=ref if '.' in ref else resolution_namespace+'.'+ref
                if '${' in ref or key not in self.fragments:
                    self.issue('unresolved_mapper_include',record['file'],ref)
                elif key in stack or len(stack)>=32:
                    self.issue('mapper_include_cutoff',record['file'],key)
                else:
                    props=dict(properties)
                    props.update({p.get('name'):substitute(p.get('value','')) for p in child if p.tag=='property'})
                    fragment=self.fragments[key]
                    locations.append(dict(file=fragment['file'],line=fragment['line'],id=key))
                    pieces.append(self.expand(fragment['node'],fragment,local,props,stack+[key],refs,locations,resolution_namespace))
            elif child.tag=='bind':
                roots,known=self.roots(substitute(child.get('value','')),local)
                local[substitute(child.get('name',''))]=roots
                if not known:self.issue('unsupported_ognl',record['file'],child.get('value',''))
            elif child.tag=='foreach':
                scope=dict(local)
                roots,known=self.roots(substitute(child.get('collection','')),scope)
                scope[substitute(child.get('item','item'))]=roots
                if child.get('index'):scope[substitute(child.get('index'))]=roots
                if not known:self.issue('unsupported_ognl',record['file'],child.get('collection',''))
                pieces.append(self.expand(child,record,scope,properties,stack,refs,locations,resolution_namespace))
            else:
                if child.tag in ('if','when','otherwise','choose') and any(n.tag=='bind' for n in child.iter()):
                    self.issue('conditional_bind_scope',record['file'],record['id'])
                # All conditional branches are may-branches, not evaluated OGNL.
                pieces.append(self.expand(child,record,local,properties,stack,refs,locations,resolution_namespace))
                if child.tag not in ('if','choose','when','otherwise','trim','where','set'):
                    self.issue('custom_mapper_element',record['file'],child.tag)
            pieces.append(capture(child.tail))
        if node.tag=='sql':
            aliases.update(local)
        return ''.join(pieces)
