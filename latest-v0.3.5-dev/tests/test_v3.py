from pathlib import Path
import pytest
from analysis.scanner_v3 import scan_project_v3

ROOT=Path(__file__).resolve().parents[1]


def scan(tmp_path,body,extra=''):
    (tmp_path/'C.java').write_text('''import org.springframework.web.bind.annotation.*;
import org.springframework.jdbc.core.JdbcTemplate;
@RestController class C {
JdbcTemplate jdbc;
@GetMapping("/") String endpoint(@RequestParam String input) { '''+body+''' return "ok"; }
'''+extra+'}',encoding='utf-8')
    return scan_project_v3(tmp_path)


def test_legacy_examples():
    report=scan_project_v3(ROOT/'examples')
    legacy=[x for x in report['findings'] if x['source']['file'].endswith(('VulnerableSql.java','VulnerableSql2.java','SafeSql.java','SafeSql2.java'))]
    assert {x['source']['file'] for x in legacy}=={'VulnerableSql.java','VulnerableSql2.java'}
    assert len(legacy)==2


@pytest.mark.parametrize('body,expected',[
    ('jdbc.queryForObject(input, String.class);',1),
    ('jdbc.queryForObject("SELECT ?", String.class, input);',0),
    ('String sql=input; sql="SELECT 1"; jdbc.execute(sql);',0),
    ('String sql="SELECT 1"; if(input.isEmpty()){sql=input;} jdbc.execute(sql);',1),
    ('String sql=input; if(input.isEmpty()){sql="a";} else {sql="b";} jdbc.execute(sql);',0),
    ('jdbc.execute(input.trim());',1),
    ('jdbc.execute(String.valueOf(Integer.parseInt(input)));',0),
    ('String sql="SELECT 1"; sql+=input; jdbc.execute(sql);',1),
    ('String sql=input; sql="safe"; jdbc.execute(input);',1),
    ('String 中文=input; jdbc.execute(中文);',1),
    ('jdbc.execute("input");',0),
    ('if(input.isEmpty()) { return "done"; } jdbc.execute(input);',1),
    ('jdbc.execute(clean(input));',0),
    ('jdbc.execute(identity(input));',1),
])
def test_dataflow(tmp_path,body,expected):
    report=scan(tmp_path,body,'String clean(String x){ return "constant"; } String identity(String x){ return x; }')
    assert len(report['findings'])==expected


def test_context_and_return(tmp_path):
    report=scan(tmp_path,'String safe=identity("constant"); String bad=identity(input); jdbc.execute(safe); jdbc.execute(bad);','String identity(String x){ return x; }')
    assert len(report['findings'])==1
    kinds={x['kind'] for x in report['findings'][0]['path']}
    assert {'SOURCE','CALL','PARAMETER','RETURN','CALL_RETURN','ASSIGN','SINK'}<=kinds


def test_same_name_receiver(tmp_path):
    report=scan(tmp_path,'Safe safe=new Safe(); jdbc.execute(safe.pick(input));')
    (tmp_path/'Other.java').write_text('class Safe { String pick(String s){return "constant";} } class Bad {String pick(String s){return s;}}')
    report=scan_project_v3(tmp_path)
    assert report['findings']==[]
    assert any(e['callee']=='Safe#pick(String)' for e in report['call_graph']['edges'])
    assert not any(e['callee']=='Bad#pick(String)' for e in report['call_graph']['edges'])


def test_interface_dispatch(tmp_path):
    scan(tmp_path,'Api api=new Impl(); api.go(input);')
    (tmp_path/'Api.java').write_text('interface Api { void go(String x); } class Impl implements Api { JdbcTemplate jdbc; public void go(String x){jdbc.execute(x);} }')
    report=scan_project_v3(tmp_path)
    assert len(report['findings'])==1
    assert 'Impl#go(String)' in report['findings'][0]['call_chain']


def test_recursive_cutoff(tmp_path):
    report=scan(tmp_path,'jdbc.execute(rec(input));','String rec(String x){return rec(x);}')
    assert any(d['kind']=='analysis_cutoff' for d in report['diagnostics'])


def test_unknown_call_explicit(tmp_path):
    report=scan(tmp_path,'jdbc.execute(External.transform(input));')
    assert len(report['findings'])==1
    assert any(e['kind']=='UNKNOWN_CALL' for e in report['findings'][0]['path'])


def test_annotation_sources(tmp_path):
    for annotation in ('RequestParam','PathVariable','RequestBody','RequestHeader','CookieValue','ModelAttribute','RequestPart'):
        scan(tmp_path,'jdbc.execute(input);')
        p=tmp_path/'C.java';p.write_text(p.read_text().replace('@RequestParam','@'+annotation))
        assert len(scan_project_v3(tmp_path)['findings'])==1


def test_not_controller(tmp_path):
    scan(tmp_path,'jdbc.execute(input);')
    p=tmp_path/'C.java';p.write_text(p.read_text().replace('@RestController',''))
    assert scan_project_v3(tmp_path)['findings']==[]


def test_spring_demo():
    report=scan_project_v3(ROOT/'examples/spring-boot-demo/src/main')
    endpoints={x['source']['method'].split('#')[1].split('(')[0] for x in report['findings']}
    assert endpoints=={'jdbc','template','mapper','xml','preparedUnsafe','mapUnsafe','mapCatch'}
    assert len(report['findings'])==7
    for finding in report['findings']:
        assert finding['path'][0]['kind']=='SOURCE'
        assert finding['path'][-1]['kind']=='SINK'
        assert any('UserService#' in x for x in finding['call_chain'])
        assert any('UserDao#' in x or 'UserMapper#' in x for x in finding['call_chain'])
        assert any(x['kind']=='RETURN' for x in finding['path'])
        for event in finding['path']:
            path=ROOT/'examples/spring-boot-demo/src/main'/event['file']
            assert path.exists() and 0<event['line']<=len(path.read_text().splitlines())


def test_parse_error_reported(tmp_path):
    (tmp_path/'Bad.java').write_text('class Bad { void broken( }')
    assert any(x['kind']=='parse_error' for x in scan_project_v3(tmp_path)['diagnostics'])


def test_overload_resolution(tmp_path):
    report=scan(tmp_path,'jdbc.execute(pick(input));','String pick(String s){return s;} String pick(int n){return "constant";}')
    assert len(report['findings'])==1
    assert not any(e['callee']=='C#pick(int)' for e in report['call_graph']['edges'])


def test_import_receiver_disambiguation(tmp_path):
    scan(tmp_path,'Api api=new Api(); jdbc.execute(api.pick(input));')
    p=tmp_path/'C.java';p.write_text('import safe.Api;\n'+p.read_text())
    (tmp_path/'Safe.java').write_text('package safe; public class Api {public String pick(String x){return "constant";}}')
    (tmp_path/'Bad.java').write_text('package bad; public class Api {public String pick(String x){return x;}}')
    report=scan_project_v3(tmp_path)
    assert report['findings']==[]
    assert not any(e['callee'].startswith('bad.Api#') for e in report['call_graph']['edges'])


def test_dto_property_source(tmp_path):
    scan(tmp_path,'jdbc.execute(input.name);')
    p=tmp_path/'C.java';p.write_text(p.read_text().replace('@RequestParam String input','@RequestBody Payload input'))
    assert len(scan_project_v3(tmp_path)['findings'])==1


def test_myBatis_only_interpolated_parameter(tmp_path):
    scan(tmp_path,'M mapper=new M(); mapper.find("fixed", input); mapper.find(input,"fixed");')
    (tmp_path/'M.java').write_text('interface M { @Select("select ${table} where name = #{name}") int find(@Param("table") String table,@Param("name") String name); }')
    report=scan_project_v3(tmp_path)
    assert len(report['findings'])==1
    assert report['findings'][0]['path'][-2]['argument_index']==0


def test_sink_receiver_not_just_name(tmp_path):
    report=scan(tmp_path,'Logger log=new Logger(); log.execute(input);','')
    assert report['findings']==[]


def test_max_depth_diagnostic(tmp_path):
    scan(tmp_path,'helper(input);','void helper(String x){jdbc.execute(x);}')
    report=scan_project_v3(tmp_path,max_depth=1)
    assert report['findings']==[]
    assert any(x['kind']=='analysis_cutoff' for x in report['diagnostics'])


def test_legacy_v2_still_runs():
    from analysis.scanner_v2 import scan_project_v2
    findings=scan_project_v2(ROOT/'examples',cwe='CWE-89')
    legacy={Path(x['file']).name:x for x in findings if Path(x['file']).parent==ROOT/'examples'}
    assert legacy['VulnerableSql.java']['verification']['path_valid']
    assert legacy['VulnerableSql2.java']['verification']['path_valid']
    # Preserve and document v0.2.1's known false positives; v3 fixes these.
    assert legacy['SafeSql.java']['verification']['path_valid']
    assert legacy['SafeSql2.java']['verification']['path_valid']


def test_all_paths_validate_and_tampering_rejected():
    from copy import deepcopy
    from verification.path_verify_v3 import verify_path
    root=ROOT/'examples/spring-boot-demo/src/main'
    report=scan_project_v3(root)
    for finding in report['findings']:
        assert verify_path(finding,report['call_graph'],root)['valid']
    bad=deepcopy(report['findings'][0]);bad['path'][0]['line']=0
    assert not verify_path(bad,report['call_graph'],root)['valid']
    bad=deepcopy(report['findings'][0])
    next(e for e in bad['path'] if e['kind']=='CALL')['callee']='Missing#method()'
    assert not verify_path(bad,report['call_graph'],root)['valid']


def test_cli(tmp_path):
    import subprocess
    import sys
    import json
    result=subprocess.run([sys.executable,str(ROOT/'main_v3.py'),'--input',str(ROOT/'examples/spring-boot-demo/src/main'),'--output',str(tmp_path/'out')],capture_output=True,text=True)
    assert result.returncode==0,result.stderr
    assert len(json.loads((tmp_path/'out/findings.json').read_text()))==7
    assert (tmp_path/'out/call-graph.dot').read_text().startswith('digraph calls')
    invalid=subprocess.run([sys.executable,str(ROOT/'main_v3.py'),'--input',str(tmp_path/'missing')],capture_output=True)
    assert invalid.returncode==2


@pytest.mark.parametrize('body,expected',[
    ('StringBuilder b=new StringBuilder(); b.append(input); jdbc.execute(b.toString());',1),
    ('jdbc.execute("SELECT "+input);',1),
    ('return "done"; jdbc.execute(input);',0),
    ('String sql="safe"; while(input.isEmpty()){sql=input;} jdbc.execute(sql);',1),
    ('String sql=input; if(input.isEmpty()){sql="safe";} jdbc.execute(sql);',1),
])
def test_additional_regressions(tmp_path,body,expected):
    assert len(scan(tmp_path,body)['findings'])==expected


def test_unrelated_parameter_does_not_taint_return(tmp_path):
    report=scan(tmp_path,'jdbc.execute(second(input,"safe"));','String second(String a,String b){return b;}')
    assert not report['findings']


def test_multiple_independent_sources(tmp_path):
    scan(tmp_path,'jdbc.execute(input); jdbc.execute(other);')
    p=tmp_path/'C.java';p.write_text(p.read_text().replace('String input)', 'String input, @RequestHeader String other)'))
    report=scan_project_v3(tmp_path)
    assert len(report['findings'])==2
    assert {x['source']['detail'] for x in report['findings']}=={'Spring MVC input: input','Spring MVC input: other'}


def test_original_files_preserved():
    import hashlib
    import json
    hashes=json.loads((ROOT/'docs/v0.2.1-baseline-sha256.json').read_text())
    for name,digest in hashes.items():
        assert hashlib.sha256((ROOT/name).read_bytes()).hexdigest()==digest,name


def test_branch_scaling_keeps_taint_not_histories(tmp_path):
    body='String sql=input;'+''.join('if(input.isEmpty()){ sql=sql.trim(); } else { sql=sql.strip(); }' for _ in range(30))+'jdbc.execute(sql);'
    report=scan(tmp_path,body)
    assert len(report['findings'])==1
    assert report['coverage']['entry_step_cutoffs']==0
    assert report['performance']['work']['ast_steps']<10000


def test_step_budget_is_visible_and_other_entries_continue(tmp_path):
    scan(tmp_path,'jdbc.execute(input);')
    report=scan_project_v3(tmp_path,max_steps=1)
    assert report['coverage']['entry_step_cutoffs']==1
    assert report['coverage']['entries_skipped']==0
    assert any(x['kind']=='entry_step_cutoff' for x in report['diagnostics'])


def test_generic_argument_is_not_supertype(tmp_path):
    scan(tmp_path,'Api api=new Api(); jdbc.execute(api.pick(input));')
    (tmp_path/'Other.java').write_text('class Api {String pick(String x){return "fixed";}} class Container<T>{} class Wrong extends Container<Api>{String pick(String x){return x;}}')
    report=scan_project_v3(tmp_path)
    assert not report['findings']
    assert not any(e['callee']=='Wrong#pick(String)' for e in report['call_graph']['edges'])


def test_missing_explicit_import_does_not_use_unrelated_simple_name(tmp_path):
    scan(tmp_path,'Api api=new Api(); jdbc.execute(api.pick(input));')
    p=tmp_path/'C.java';p.write_text('import external.Api;\n'+p.read_text())
    (tmp_path/'Other.java').write_text('package local; class Api {String pick(String x){return "fixed";}}')
    report=scan_project_v3(tmp_path)
    assert not any(e['callee']=='local.Api#pick(String)' for e in report['call_graph']['edges'])
    assert any(d['kind']=='unresolved_call' for d in report['diagnostics'])


def test_distinct_source_origins_survive_merge(tmp_path):
    scan(tmp_path,'jdbc.execute(input+other);')
    p=tmp_path/'C.java';p.write_text(p.read_text().replace('String input)', 'String input, @RequestHeader String other)'))
    report=scan_project_v3(tmp_path)
    assert len(report['findings'])==2


def test_duplicate_class_diagnostic(tmp_path):
    scan(tmp_path,'jdbc.execute(input);')
    (tmp_path/'Duplicate.java').write_text('class C {void other(){}}')
    assert any(d['kind']=='duplicate_class' for d in scan_project_v3(tmp_path)['diagnostics'])


def test_nested_stable_loops_do_not_expand_exponentially(tmp_path):
    body='while(input.isEmpty()){'*12+'jdbc.execute(input);'+'}'*12
    report=scan(tmp_path,body)
    assert len(report['findings'])==1
    assert report['coverage']['entry_step_cutoffs']==0
    assert report['performance']['work']['ast_steps']<1000


def test_loop_needs_multiple_abstract_iterations(tmp_path):
    report=scan(tmp_path,'String a=""; String b=""; while(input.isEmpty()){jdbc.execute(a); a=b; b=input;}')
    assert len(report['findings'])==1


def test_nested_classes_have_distinct_owners(tmp_path):
    from analysis.program import Program
    (tmp_path/'Classes.java').write_text('class A {static class Item {void run(){}}} class B {static class Item {void run(){}}}')
    program=Program(tmp_path)
    assert {'A.Item#run()','B.Item#run()'}<=set(program.methods)
    assert not any(x['kind']=='duplicate_class' for x in program.diagnostics)


def test_clean_summary_never_hides_transitive_source(tmp_path):
    report=scan(tmp_path,'helper(request); helper(request);','HttpServletRequest request; String read(HttpServletRequest r){return r.getParameter("x");} void helper(HttpServletRequest r){jdbc.execute(read(r));}')
    assert report['findings']
    assert any(x['source']['detail']=='Servlet request input' for x in report['findings'])


def test_clean_summary_does_not_contaminate_tainted_call(tmp_path):
    report=scan(tmp_path,'identity("fixed"); identity("fixed"); jdbc.execute(identity(input));','String identity(String x){return x;}')
    assert len(report['findings'])==1
    assert report['performance']['work'].get('clean_summary_hits',0)>0
