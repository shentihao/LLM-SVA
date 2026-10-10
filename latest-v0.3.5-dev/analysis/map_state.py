"""Small constant-key Map heap. Not a general Java object/collection heap."""
class Value(list):
    def __init__(self, paths=(), refs=None):
        super().__init__(paths)
        self.refs = refs or {}

    def __bool__(self):
        return len(self) > 0 or bool(self.refs)


def merge(*values):
    out=[]; seen=set(); refs={}
    for value in values:
        for path in value:
            origin=path[0]
            key=(origin['file'],origin['line'],origin['method'],origin['expression'])
            if key not in seen:
                seen.add(key); out.append(path)
        for ident, trails in getattr(value,'refs',{}).items():
            # Preserve a representative reference history for each object.
            refs.setdefault(ident,trails)
    return Value(out,refs)


def append(value,event):
    return Value([path+[event] for path in value],
                 {ident:trail+[event] for ident,trail in getattr(value,'refs',{}).items()})


def origins(value):
    return frozenset((p[0]['file'],p[0]['line'],p[0]['method'],p[0]['expression']) for p in value)


class MapHeap:
    def __init__(self):
        self.cells={}; self.next_id=0; self.weak_updates=False; self.observers=[]

    def new(self, default=()):
        ident=self.next_id; self.next_id+=1
        self.cells[ident]={'default':Value(default),'fields':{}}
        self.observe(ident)
        return Value(refs={ident:[]})

    def snapshot(self):
        # Cells and Values are immutable after publication; writes replace cells.
        return dict(self.cells)

    def restore(self,state):
        self.cells=dict(state)

    @staticmethod
    def union_cells(cells):
        if all(c is cells[0] for c in cells): return cells[0]
        def union(values):
            return values[0] if all(v is values[0] for v in values) else merge(*values)
        keys=set().union(*(c['fields'].keys() for c in cells))
        return {'default':union([c['default'] for c in cells]),
                'fields':{k:union([c['fields'].get(k,c['default']) for c in cells]) for k in keys}}

    def observe(self,ident):
        # Exception collectors retain every intermediate write, including writes
        # performed by callees and subsequently overwritten on normal paths.
        for state in self.observers:
            cells=[self.cells[ident]]
            if ident in state: cells.insert(0,state[ident])
            state[ident]=self.union_cells(cells)

    def join(self,*states):
        self.cells={ident:self.union_cells([s[ident] for s in states if ident in s])
                    for ident in set().union(*(s.keys() for s in states))}

    def signature(self,values):
        reachable=set(); pending=[i for v in values for i in getattr(v,'refs',{})]
        while pending:
            ident=pending.pop()
            if ident in reachable: continue
            reachable.add(ident)
            cell=self.cells[ident]
            pending.extend(i for v in [cell['default'],*cell['fields'].values()] for i in getattr(v,'refs',{}))
        return frozenset((i,k,origins(v),tuple(sorted(getattr(v,'refs',{}))))
                         for i in reachable for c in [self.cells[i]]
                         for k,v in [('DEFAULT',c['default'])]+[(('KEY',k),v) for k,v in c['fields'].items()])

    def read(self,value,key):
        results=[]
        for ident,trail in getattr(value,'refs',{}).items():
            cell=self.cells[ident]
            result=cell['fields'].get(key,cell['default']) if key is not None else merge(cell['default'],*cell['fields'].values())
            for event in trail: result=append(result,event)
            results.append(result)
        return merge(*results)

    def flatten(self,value):
        # Visit each object once: shared submaps and cycles must not enumerate
        # exponentially many alias routes. Retain a whole representative route.
        seen=set(); pending=[(value,[])]; result=Value()
        while pending:
            current,outer=pending.pop()
            result=merge(result,Value([path+outer for path in current]))
            for ident,trail in getattr(current,'refs',{}).items():
                if ident in seen: continue
                seen.add(ident)
                cell=self.cells[ident]
                pending.extend((v,trail+outer) for v in reversed([cell['default'],*cell['fields'].values()]))
        return result

    def write(self,receiver,key,value):
        refs=getattr(receiver,'refs',{})
        for ident in refs:
            old=self.cells[ident]
            cell={'default':old['default'],'fields':dict(old['fields'])}
            if key is not None and len(refs)==1 and not self.weak_updates:
                cell['fields'][key]=value
            elif key is not None:
                cell['fields'][key]=merge(cell['fields'].get(key,cell['default']),value)
            else:
                # Unknown key may overwrite any tracked slot. Never clear all keys.
                cell['default']=merge(cell['default'],value)
                cell['fields']={k:merge(v,value) for k,v in cell['fields'].items()}
            self.cells[ident]=cell
            self.observe(ident)
