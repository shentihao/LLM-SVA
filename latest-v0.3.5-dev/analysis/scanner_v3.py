"""Bounded context-sensitive may-taint interpreter. Paths are static evidence,
not proofs of runtime feasibility. No LLM or fabricated confidence scores.
"""
import re
import time
from collections import Counter
import xml.etree.ElementTree as ET
from pathlib import Path
from analysis.program import Program, field, walk, simple
from analysis.mybatis import MapperIndex
from analysis.servlet_sources import SERVLET_SOURCES


from analysis.map_state import Value, MapHeap, merge, append, origins

MAP_TYPES={'Map','HashMap','LinkedHashMap','TreeMap','SortedMap','NavigableMap','ConcurrentMap','ConcurrentHashMap'}

def state_key(env):
    return frozenset((name, origins(value), tuple(sorted(getattr(value,'refs',{})))) for name,value in env.items())


class EntryBudgetExceeded(Exception):
    pass


class Analyzer:
    def __init__(self,root,max_depth=24,max_steps=200000):
        self.started=time.perf_counter()
        self.program=Program(root)
        self.index_seconds=time.perf_counter()-self.started
        self.max_depth=max_depth
        self.max_steps=max_steps
        self.steps=0
        self.heap=MapHeap()
        self.work=Counter()
        self.entry_outcomes=[]
        self._diagnostic_keys=set()
        self._finding_keys=set()
        self._clean_summaries=set()
        self.findings=[]
        self.diagnostics=list(self.program.diagnostics)
        mapper=MapperIndex(Path(root))
        self.mapper=mapper.statements
        self.diagnostics.extend(mapper.diagnostics)

    def diagnostic(self,kind,m,node,**extra):
        item=m.event(node,kind,kind,**extra)
        key=(kind,m.id,node.start_byte,repr(extra))
        if key not in self._diagnostic_keys:
            self._diagnostic_keys.add(key)
            self.diagnostics.append(item)

    def emit(self,m,node,value,kind,**extra):
        for path in self.heap.flatten(value):
            location=extra.get('sink_location')
            event=m.event(node,'SINK',kind,**extra)
            if location:
                event.update(location)
            path=path+[event]
            finding=dict(cwe='CWE-89',sink_kind=kind,source=path[0],sink=path[-1],path=path,
                         call_chain=list(dict.fromkeys(e['method'] for e in path)),
                         verification=dict(source_valid=True,sink_valid=True,path_valid=True,
                                           runtime_feasibility='not_proven'),
                         evidence='static_may_taint')
            key=(path[0]['file'],path[0]['line'],path[0]['method'],path[0]['expression'],event['file'],event['line'],event['method'],kind)
            if key not in self._finding_keys:
                self._finding_keys.add(key)
                self.findings.append(finding)

    def mapper_sink(self,m,values):
        xml=self.mapper.get((m.owner,m.name)) or self.mapper.get((m.declared_owner,m.name))
        sql=xml['sql'] if xml else m.annotations
        if not xml and not re.search(r'@(Select|Update|Insert|Delete)\b',sql):
            return
        names=sorted({root for ref in xml['references'] for root in ref['roots']}) if xml else re.findall(r'\$\{\s*([\w.]+)\s*\}',sql)
        for i,(name,_,node) in enumerate(m.params):
            alias=re.search(r'@Param\s*\(\s*"([^"]+)"',m.text(node))
            aliases={name,f'param{i+1}',f'arg{i}'}
            if alias:
                aliases.add(alias.group(1))
            if len(m.params)==1:
                aliases.update(('_parameter','value'))
            candidate=values[i]
            selected=any(x.split('.')[0] in aliases for x in names)
            if simple(m.params[i][1]) in MAP_TYPES and getattr(candidate,'refs',{}):
                selected_values=[]
                expressions=[]
                if xml:
                    for ref in xml['references']:
                        expression=ref['expression'].strip()
                        if expression.split('.')[0] in ref['roots']: expressions.append(expression)
                        else: expressions.extend(ref['roots'])
                else: expressions=names
                for expression in expressions:
                    parts=expression.split('.')
                    if parts[0] in aliases: parts=parts[1:]
                    elif len(m.params)!=1: continue
                    value=candidate
                    for part in parts:
                        if not re.fullmatch(r'[A-Za-z_$][\w$]*',part):
                            value=self.heap.flatten(value); break
                        value=self.heap.read(value,part) if getattr(value,'refs',{}) else value
                    selected_values.append(value)
                candidate=merge(*selected_values)
                selected=bool(selected_values)
            if selected:
                extra={'sql_template':sql}
                if xml:
                    extra['mapper_file']=xml['file']
                    extra['mapper_fragments']=xml['fragments']
                    extra['substitutions']=xml['references']
                    extra['sink_location']=dict(file=xml['file'],line=xml['line'],expression=sql)
                self.emit(m,m.node,candidate, 'MyBatis ${} substitution',**extra)

    def tick(self):
        self.steps += 1
        self.work['ast_steps'] += 1
        if self.steps > self.max_steps:
            raise EntryBudgetExceeded()

    def run_method(self,m,values,stack):
        self.tick()
        clean=not any(values) and m.id not in self.program.may_create_source
        if stack and clean and m.id in self._clean_summaries:
            self.work['clean_summary_hits'] += 1
            return []
        result=self._run_method(m,values,stack)
        if clean and not result:
            self._clean_summaries.add(m.id)
        return result

    def _run_method(self,m,values,stack):
        self.tick()
        self.work['method_invocations'] += 1
        if len(stack)>=self.max_depth or m.id in stack:
            self.diagnostic('analysis_cutoff',m,m.node,call_stack=stack)
            return []
        stack=stack+[m.id]
        self.mapper_sink(m,values)
        if field(m.node,'body') is None:
            xml=self.mapper.get((m.owner,m.name)) or self.mapper.get((m.declared_owner,m.name))
            escaped=[] if xml and xml.get('readonly_parameters') else [v for v in values if getattr(v,'refs',{})]
            if escaped:
                self.diagnostic('escaped_map_call',m,m.node)
                effect=append(merge(*(self.heap.flatten(v) for v in values)),m.event(m.node,'UNKNOWN_CALL','Possible opaque Map mutation'))
                for value in escaped: self.heap.write(value,None,effect)
            self.diagnostic('opaque_method_body',m,m.node)
            if m.return_type=='void':return []
            return append(merge(*(self.heap.flatten(v) for v in values)),m.event(m.node,'OPAQUE_RETURN',
                          'Method body unavailable; conservative return dependency, not an observed return statement'))
        env={name:(val if getattr(val,'refs',{}) or simple(typ) not in MAP_TYPES else self.heap.new(val))
             for (name,typ,_),val in zip(m.params,values)}
        returns=Value()
        return_heaps=[]
        exception_envs=[]

        def observe_env():
            for state,last in exception_envs:
                for key in state:
                    value=env.get(key)
                    if value is not last.get(key):
                        state[key]=merge(state[key],value or Value())
                        last[key]=value

        def expr(n):
            self.tick()
            if n is None:
                return []
            typ=n.type
            if typ=='identifier':
                return env.get(m.text(n),[])
            if typ=='field_access':
                return merge(env.get(m.text(n),env.get(m.text(n).removeprefix('this.'),[])),expr(field(n,'object')))
            if typ in ('string_literal','character_literal','null_literal','decimal_integer_literal','true','false'):
                return []
            if typ=='assignment_expression':
                left=field(n,'left'); right=field(n,'right')
                value=expr(right)
                if m.text(field(n,'operator'))=='+=':
                    value=merge(expr(left),value)
                if simple(self.program.receiver_type(m,left)) in MAP_TYPES and not getattr(value,'refs',{}): value=self.heap.new(value)
                env[m.text(left)]=append(value,m.event(n,'ASSIGN',m.text(left)))
                observe_env()
                return env[m.text(left)]
            if typ=='method_invocation':
                name=m.text(field(n,'name'))
                obj=field(n,'object')
                rt=simple(self.program.receiver_type(m,obj))
                args=list(field(n,'arguments').named_children)
                values=[expr(a) for a in args]
                receiver=expr(obj) if obj is not None else []
                if name in SERVLET_SOURCES.get(rt,()):
                    value=Value([[m.event(n,'SOURCE','Servlet request input')]])
                    return self.heap.new(value) if name=='getParameterMap' else value
                if values:
                    if rt in ('Statement','PreparedStatement','CallableStatement') and name in ('execute','executeQuery','executeUpdate','executeLargeUpdate','addBatch'):
                        self.emit(m,n,values[0],'JDBC SQL text')
                    if rt=='Connection' and name in ('prepareStatement','prepareCall'):
                        self.emit(m,n,values[0],'JDBC prepared SQL text')
                    if rt in ('JdbcTemplate','JdbcOperations','NamedParameterJdbcTemplate','NamedParameterJdbcOperations') and name in ('query','queryForObject','queryForList','queryForMap','queryForRowSet','update','execute','batchUpdate'):
                        self.emit(m,n,values[0],'JdbcTemplate SQL text')
                if rt in MAP_TYPES and getattr(receiver,'refs',{}):
                    key=m.text(args[0])[1:-1] if args and args[0].type=='string_literal' and '\\' not in m.text(args[0]) else None
                    if name in ('get','getOrDefault') and values:
                        value=self.heap.read(receiver,key)
                        if name=='getOrDefault' and len(values)>1: value=merge(value,values[1])
                        return append(value,m.event(n,'MAP_GET','Map key: '+repr(key)))
                    if name=='put' and len(values)==2:
                        old=self.heap.read(receiver,key)
                        self.heap.write(receiver,key,append(values[1],m.event(n,'MAP_PUT','Map key: '+repr(key))))
                        return append(old,m.event(n,'MAP_PREVIOUS','Previous Map value'))
                    if name=='remove' and len(values)==1:
                        old=self.heap.read(receiver,key)
                        if key is not None: self.heap.write(receiver,key,Value())
                        return append(old,m.event(n,'MAP_PREVIOUS','Removed Map value'))
                    self.diagnostic('unsupported_map_operation',m,n,operation=name)
                    # An unmodeled mutator may invalidate a previous strong update.
                    if name not in ('containsKey','containsValue','size','isEmpty','keySet','values','entrySet'):
                        self.heap.write(receiver,None,append(merge(self.heap.flatten(receiver),*(self.heap.flatten(v) for v in values)),m.event(n,'UNKNOWN_CALL','Possible unmodeled Map mutation')))
                targets=self.program.resolve(m,n)
                if targets:
                    result=[]
                    heap_before=self.heap.snapshot() if len(targets)>1 else None
                    heaps=[]
                    for target in targets:
                        if heap_before is not None: self.heap.restore(heap_before)
                        bound=[]
                        for i,value in enumerate(values):
                            param=target.params[i]
                            value=append(value,m.event(n,'CALL',target.id,callee=target.id,argument_index=i))
                            value=append(value,target.event(param[2],'PARAMETER',param[0],caller=m.id,argument_index=i))
                            bound.append(value)
                        ret=self.run_method(target,bound,stack)
                        result=merge(result,append(ret,m.event(n,'CALL_RETURN',target.id,callee=target.id)))
                        if heap_before is not None: heaps.append(self.heap.snapshot())
                    if heaps: self.heap.join(*heaps)
                    return result
                if rt in ('Integer','Long','Short','Byte','Double','Float') and name.startswith(('parse','valueOf')):
                    return []
                # Explicit string models preserve receiver taint; trim is NOT a SQL sanitizer.
                if name in ('trim','strip','toLowerCase','toUpperCase','toString','substring','replace','concat','format','valueOf','append'):
                    value=append(merge(self.heap.flatten(receiver),*(self.heap.flatten(v) for v in values)),m.event(n,'TRANSFORM','String operation'))
                    if name=='append' and obj is not None:
                        env[m.text(obj)]=value
                        observe_env()
                    return value
                known=rt in ('Statement','PreparedStatement','CallableStatement','Connection','JdbcTemplate','JdbcOperations','NamedParameterJdbcTemplate','NamedParameterJdbcOperations')
                if not known:
                    self.diagnostic('unresolved_call',m,n,receiver_type=rt)
                    escaped=[v for v in values if getattr(v,'refs',{})]
                    if escaped:
                        self.diagnostic('escaped_map_call',m,n)
                        effect=append(merge(self.heap.flatten(receiver),*(self.heap.flatten(v) for v in values)),m.event(n,'UNKNOWN_CALL','Possible external Map mutation'))
                        for value in escaped: self.heap.write(value,None,effect)
                    return append(merge(self.heap.flatten(receiver),*(self.heap.flatten(v) for v in values)),m.event(n,'UNKNOWN_CALL','Conservative return propagation; implementation unavailable'))
                return []
            if typ=='object_creation_expression':
                args=field(n,'arguments')
                value=merge(*(expr(c) for c in args.named_children)) if args else Value()
                if simple(m.text(field(n,'type'))) in MAP_TYPES: return self.heap.new(self.heap.flatten(value))
                return value
            return merge(*(expr(c) for c in n.named_children))

        def statements(n):
            nonlocal returns
            self.tick()
            observe_env()
            if n is None:
                return False
            typ=n.type
            if typ=='return_statement':
                value=merge(*(expr(c) for c in n.named_children))
                returns=merge(returns,append(value,m.event(n,'RETURN','Return value')))
                return_heaps.append(self.heap.snapshot())
                return True
            if typ in ('throw_statement','break_statement','continue_statement'):
                for c in n.named_children:
                    expr(c)
                return True
            if typ=='resource':
                name=m.text(field(n,'name'))
                env[name]=append(expr(field(n,'value')),m.event(n,'ASSIGN',name))
                return False
            if typ=='local_variable_declaration':
                for d in n.named_children:
                    if d.type=='variable_declarator':
                        name=m.text(field(d,'name'))
                        value=expr(field(d,'value'))
                        if simple(m.text(field(n,'type'))) in MAP_TYPES and not getattr(value,'refs',{}): value=self.heap.new(value)
                        env[name]=append(value,m.event(d,'ASSIGN',name))
                return False
            if typ=='expression_statement':
                for c in n.named_children:
                    expr(c)
                return False
            if typ=='if_statement':
                expr(field(n,'condition'))
                before=dict(env)
                heap_before=self.heap.snapshot()
                heaps=[]
                stopped_heaps=[]
                outcomes=[]
                stops=[]
                for branch in ('consequence','alternative'):
                    env.clear();env.update(before)
                    self.heap.restore(heap_before)
                    for key,value in list(env.items()):
                        env[key]=append(value,m.event(n,'BRANCH',branch+' (feasibility not proven)',condition=m.text(field(n,'condition'))))
                    stop=statements(field(n,branch))
                    stops.append(stop)
                    if not stop:
                        heaps.append(self.heap.snapshot())
                        outcomes.append(dict(env))
                    elif any(c.type in ('break_statement','continue_statement') for c in walk(field(n,branch))):
                        # Loop control still needs its side effects at the loop exit.
                        heaps.append(self.heap.snapshot())
                    else:
                        stopped_heaps.append(self.heap.snapshot())
                self.heap.join(*(heaps or stopped_heaps))
                env.clear()
                for outcome in outcomes:
                    for key,val in outcome.items():
                        env[key]=merge(env.get(key,[]),val)
                return all(stops)
            if typ in ('while_statement','for_statement','enhanced_for_statement','do_statement'):
                self.diagnostic('bounded_loop',m,n)
                # A finite may-analysis approximation: preserve zero iterations and
                # iterate at most 3 times, stopping if modeled origin sets stabilize.
                # Include the small Map heap in convergence, not general Java heap state.
                for _ in range(3):
                    before=dict(env)
                    heap_before=self.heap.snapshot()
                    heap_signature=self.heap.signature(env.values())
                    for c in n.named_children:
                        statements(c)
                    for key,val in before.items():
                        env[key]=merge(env.get(key,[]),val)
                    self.heap.join(heap_before,self.heap.snapshot())
                    if state_key(before)==state_key(env) and heap_signature==self.heap.signature(env.values()):
                        self.work['loop_stable_stops'] += 1
                        break
                return False
            if typ=='finally_clause':
                return statements(next((c for c in n.named_children if c.type=='block'),None))
            if typ in ('block','constructor_body'):
                saved={}
                stopped=False
                for c in n.named_children:
                    if c.type=='local_variable_declaration':
                        for d in c.named_children:
                            if d.type=='variable_declarator':
                                key=m.text(field(d,'name'))
                                saved[key]=(key in env,env.get(key,[]))
                    if statements(c):
                        stopped=True
                        break
                for key,(existed,value) in saved.items():
                    if existed:
                        env[key]=value
                    else:
                        env.pop(key,None)
                return stopped
            if typ in ('lambda_expression','class_declaration'):
                self.diagnostic('unsupported_nested_execution',m,n)
                return False
            if typ in ('try_statement','try_with_resources_statement'):
                self.diagnostic('approximate_exception_flow',m,n,
                                model='Strong normal path; catches may observe any intermediate state; exception types not resolved')
                before=dict(env)
                prior_returns=returns
                return_start=len(return_heaps)
                exceptional_env=dict(env)
                exceptional_heap=self.heap.snapshot()
                exception_envs.append((exceptional_env,dict(env)))
                self.heap.observers.append(exceptional_heap)
                try:
                    statements(field(n,'resources'))
                    normal_stop=statements(field(n,'body'))
                    observe_env()
                finally:
                    exception_envs.pop()
                    self.heap.observers.pop()
                event=m.event(n,'EXCEPTION_PATH','Possible intermediate exception state; exception timing/type not proven')
                exceptional_env={key:append(value,event) for key,value in exceptional_env.items()}
                exceptional_heap={ident:{'default':append(cell['default'],event),
                                         'fields':{key:append(value,event) for key,value in cell['fields'].items()}}
                                  for ident,cell in exceptional_heap.items()}
                normal_env=dict(env)
                outcomes=[normal_env]
                heaps=[self.heap.snapshot()]
                stops=[normal_stop]
                for catch in (c for c in n.named_children if c.type=='catch_clause'):
                    env.clear();env.update(exceptional_env)
                    self.heap.restore(exceptional_heap)
                    for key,value in list(env.items()):
                        env[key]=append(value,m.event(catch,'EXCEPTION_PATH','Possible exception at an intermediate operation; type matching not proven'))
                    stops.append(statements(field(catch,'body')))
                    outcomes.append(dict(env));heaps.append(self.heap.snapshot())
                heaps.extend(return_heaps[return_start:])
                final=next((c for c in n.named_children if c.type=='finally_clause'),None)
                if final is not None:
                    # finally also executes when an exception escapes all catches.
                    outcomes.append(exceptional_env);heaps.append(exceptional_heap)
                env.clear()
                for outcome in outcomes:
                    for key,value in outcome.items(): env[key]=merge(env.get(key,Value()),value)
                self.heap.join(*heaps)
                final_stop=False
                if final is not None:
                    pending_returns=returns
                    returns=Value()
                    final_stop=statements(final)
                    final_returns=returns
                    returns=merge(prior_returns if final_stop else pending_returns,final_returns)
                if len(return_heaps)>return_start:
                    return_heaps[return_start:]=[self.heap.snapshot()]
                for key in set(env)-set(before): env.pop(key,None)
                return final_stop or all(stops)
            if typ in ('switch_expression','switch_statement'):
                self.diagnostic('approximate_control_flow',m,n)
                previous=self.heap.weak_updates
                self.heap.weak_updates=True
                try:
                    for c in n.named_children: statements(c)
                finally:
                    self.heap.weak_updates=previous
                return False
            if typ in ('method_invocation','assignment_expression'):
                expr(n)
            else:
                for c in n.named_children:
                    statements(c)
            return False

        statements(field(m.node,'body'))
        if return_heaps: self.heap.join(self.heap.snapshot(),*return_heaps)
        return merge(returns)

    def scan(self):
        entries=[]
        declarations_without_body=[]
        entry_declarations=set()
        inherited_entry_views=0
        for m in self.program.methods.values():
            controller=bool(re.search(r'@(RestController|Controller)\b',self.program.classes[m.owner]['annotations']))
            endpoint=controller and bool(re.search(r'@(RequestMapping|GetMapping|PostMapping|PutMapping|DeleteMapping|PatchMapping)\b',m.annotations))
            servlet=any(simple(t) in ('HttpServletRequest','ServletRequest') for _,t,_ in m.params)
            if not (endpoint or servlet):
                continue
            if field(m.node,'body') is None:
                declarations_without_body.append(m.id)
                self.diagnostic('entry_without_body',m,m.node)
                continue
            values=[]
            for name,typ,node in m.params:
                annotation=m.text(node)
                source=endpoint and (bool(re.search(r'@(RequestParam|PathVariable|RequestBody|RequestHeader|CookieValue|ModelAttribute|RequestPart)\b',annotation)) or simple(typ) in ('String','int','long','Integer','Long'))
                # Numeric conversion cannot carry SQL syntax.
                if simple(typ) in ('int','long','Integer','Long','double','Double','boolean','Boolean'):
                    source=False
                values.append([[m.event(node,'SOURCE','Spring MVC input: '+name)]] if source else [])
            entries.append(m.id)
            entry_declarations.add((m.unit['file'],m.node.start_byte))
            inherited_entry_views += int(m.declared_owner!=m.owner)
            self.steps=0
            self.heap=MapHeap()
            try:
                self.run_method(m,values,[])
                self.entry_outcomes.append(dict(method=m.id,status='visited',steps=self.steps))
            except EntryBudgetExceeded:
                self.diagnostic('entry_step_cutoff',m,m.node,max_steps=self.max_steps)
                self.entry_outcomes.append(dict(method=m.id,status='step_cutoff',steps=self.steps))
        return dict(version='0.3.5-dev',findings=self.findings,call_graph=dict(nodes=sorted(self.program.methods),edges=self.program.edges),
                    entry_points=entries,diagnostics=self.diagnostics,
                    coverage=dict(entries_total=len(entries),entries_attempted=len(entries),entries_skipped=0,
                                  non_executable_declarations=len(declarations_without_body),
                                  unique_entry_declarations=len(entry_declarations),
                                  inherited_entry_views=inherited_entry_views,
                                  declarations_without_body=declarations_without_body,
                                  entry_step_cutoffs=sum(x['status']=='step_cutoff' for x in self.entry_outcomes),
                                  outcomes=self.entry_outcomes),
                    performance=dict(index_seconds=self.index_seconds,total_seconds=time.perf_counter()-self.started,
                                     resolver=dict(self.program.stats),work=dict(self.work)),
                    analysis=dict(kind='bounded_context_sensitive_may_taint',max_call_depth=self.max_depth,
                                  max_steps_per_entry=self.max_steps,
                                  entry_model='Spring mapped methods or ServletRequest parameter methods; not HTTP route enumeration',
                                  witness_policy='one_representative_per_source_per_value',
                                  complete=False,limitations=['Only constant-key Map heap/aliases are modeled; no full Java heap, type solver or reflection',
                                  'Branches are may-paths; loops bounded to three iterations',
                                  'Exception timing/types and resource close effects are not resolved; finally merges normal and exceptional states',
                                  'Recursion is cut with diagnostics; unknown external returns conservatively propagate',
                                  'MyBatis expressions are dependency approximations; provider SQL and dynamic SqlSession IDs remain unsupported']))


def scan_project_v3(project,max_depth=24,max_steps=200000):
    return Analyzer(project,max_depth=max_depth,max_steps=max_steps).scan()
