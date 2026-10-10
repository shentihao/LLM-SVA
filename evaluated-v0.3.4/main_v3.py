"""Deterministic local v0.3 analysis; no API key required."""
import argparse
import json
from pathlib import Path
from analysis.scanner_v3 import scan_project_v3
from verification.path_verify_v3 import verify_path


def main():
    parser=argparse.ArgumentParser(description='LLM-SVA v0.3 Java interprocedural SQL taint analysis')
    parser.add_argument('--input',required=True,type=Path)
    parser.add_argument('--output',type=Path,default=Path('data/results-v3'))
    parser.add_argument('--max-depth',type=int,default=24)
    parser.add_argument('--max-steps',type=int,default=200000)
    args=parser.parse_args()
    if not args.input.is_dir():
        parser.error('--input must be an existing project directory')
    if args.max_steps<1:
        parser.error('--max-steps must be positive')
    if args.max_depth<1:
        parser.error('--max-depth must be positive')
    report=scan_project_v3(args.input,args.max_depth,args.max_steps)
    for finding in report['findings']:
        finding['path_check']=verify_path(finding,report['call_graph'],args.input)
    args.output.mkdir(parents=True,exist_ok=True)
    for filename,data in [('report.json',report),('findings.json',report['findings']),('call-graph.json',report['call_graph'])]:
        (args.output/filename).write_text(json.dumps(data,ensure_ascii=False,indent=2)+'\n',encoding='utf-8')
    lines=['digraph calls {']
    for edge in report['call_graph']['edges']:
        lines.append('  '+json.dumps(edge['caller'])+' -> '+json.dumps(edge['callee'])+';')
    (args.output/'call-graph.dot').write_text('\n'.join(lines+['}'])+'\n',encoding='utf-8')
    readable=['# LLM-SVA v0.3 Source–Sink paths', '',
              'Static may-taint evidence; runtime feasibility is not proven.', '']
    for i,finding in enumerate(report['findings'],1):
        readable.extend([f"## {i}. {finding['sink_kind']}", ''])
        for event in finding['path']:
            expression=' '.join(event['expression'].split())
            readable.append(f"- **{event['kind']}** `{event['file']}:{event['line']}` — `{event['method']}` — {event['detail']}")
            readable.append(f"  `{expression.replace('`', chr(39))}`")
        readable.append('')
    (args.output/'paths.md').write_text('\n'.join(readable)+'\n',encoding='utf-8')
    print(f"Findings: {len(report['findings'])}; call edges: {len(report['call_graph']['edges'])}; diagnostics: {len(report['diagnostics'])}")
    print(args.output/'report.json')


if __name__=='__main__':
    main()
