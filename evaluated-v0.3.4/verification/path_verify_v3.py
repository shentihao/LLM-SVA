"""Validate evidence structure, NOT runtime feasibility or vulnerability certainty."""
from pathlib import Path


def verify_path(finding,graph,root):
    errors=[]
    path=finding.get('path',[])
    if not path or path[0].get('kind')!='SOURCE' or path[-1].get('kind')!='SINK':
        errors.append('Path must start at SOURCE and end at SINK')
    edges={(e['caller'],e['callee']) for e in graph['edges']}
    for i,event in enumerate(path):
        filename=Path(root)/event['file']
        if not filename.is_file() or not 1<=event['line']<=len(filename.read_text(encoding='utf-8').splitlines()):
            errors.append(f'Invalid source location at event {i}')
        if event['kind']=='CALL':
            if (event['method'],event['callee']) not in edges:
                errors.append(f'Call missing from graph at event {i}')
            if i+1>=len(path) or path[i+1]['kind']!='PARAMETER' or path[i+1]['method']!=event['callee']:
                errors.append(f'Call/parameter mismatch at event {i}')
        if event['kind']=='CALL_RETURN':
            if i==0 or path[i-1]['kind'] not in ('RETURN','OPAQUE_RETURN') or path[i-1]['method']!=event['callee']:
                errors.append(f'Return mismatch at event {i}')
    return dict(valid=not errors,errors=errors,runtime_feasibility='not_proven')
