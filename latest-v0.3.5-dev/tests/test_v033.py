import pytest
from analysis.scanner_v3 import scan_project_v3
from verification.path_verify_v3 import verify_path


def run(tmp_path,body,extra='',params='@RequestBody Map<String,String> map, @RequestParam String input'):
    (tmp_path/'C.java').write_text('''import java.util.*;
import org.springframework.web.bind.annotation.*;
@RestController class C { JdbcTemplate jdbc;
@PostMapping("/") void go('''+params+''') {'''+body+'''}
'''+extra+'}')
    result=scan_project_v3(tmp_path)
    for finding in result['findings']:
        assert verify_path(finding,result['call_graph'],tmp_path)['valid']
    return result


@pytest.mark.parametrize('body,expected',[
 ('jdbc.execute(map.get("sql"));',1),
 ('map.put("sql","fixed"); jdbc.execute(map.get("sql"));',0),
 ('map.put("sql","fixed"); jdbc.execute(map.get("other"));',1),
 ('Map<String,String> alias=map; alias.put("sql","fixed"); jdbc.execute(map.get("sql"));',0),
 ('Map<String,String> fresh=new HashMap<>(); fresh.put("sql",input); jdbc.execute(fresh.get("sql"));',1),
 ('Map<String,String> fresh=new HashMap<>(); fresh.put("sql",input); jdbc.execute(fresh.get("other"));',0),
 ('map.put(input,"fixed"); jdbc.execute(map.get("sql"));',1),
 ('map.put("sql","fixed"); map.put(input,input); jdbc.execute(map.get("sql"));',1),
 ('map.put("sql","fixed"); jdbc.execute(map.get(input));',1),
 ('map.remove("sql"); jdbc.execute(map.get("sql"));',0),
 ('String old=map.put("sql","fixed"); jdbc.execute(old);',1),
 ('if(input.isEmpty()) map.put("sql","fixed"); jdbc.execute(map.get("sql"));',1),
 ('if(input.isEmpty()) map.put("sql","a"); else map.put("sql","b"); jdbc.execute(map.get("sql"));',0),
 ('while(input.isEmpty()) map.put("sql","fixed"); jdbc.execute(map.get("sql"));',1),
])
def test_map_keys(tmp_path,body,expected):
    assert len(run(tmp_path,body)['findings'])==expected


def test_callee_updates_alias(tmp_path):
    assert not run(tmp_path,'clean(map); jdbc.execute(map.get("sql"));',
                   'void clean(Map<String,String> m){m.put("sql","fixed");}')['findings']


def test_callee_tainted_write(tmp_path):
    r=run(tmp_path,'Map<String,String> m=new HashMap<>(); fill(m,input); jdbc.execute(m.get("sql"));',
          'void fill(Map<String,String> m,String s){m.put("sql",s);}')
    assert len(r['findings'])==1
    assert any(e['kind']=='MAP_PUT' for e in r['findings'][0]['path'])


def test_returned_map_alias(tmp_path):
    assert not run(tmp_path,'Map<String,String> a=identity(map); a.put("sql","fixed"); jdbc.execute(map.get("sql"));',
                   'Map<String,String> identity(Map<String,String> m){return m;}')['findings']


def test_returned_map_taint(tmp_path):
    r=run(tmp_path,'Map<String,String> a=identity(map); jdbc.execute(a.get("sql"));',
          'Map<String,String> identity(Map<String,String> m){return m;}')
    assert len(r['findings'])==1


def test_return_fresh_map(tmp_path):
    assert len(run(tmp_path,'Map<String,String> a=make(input); jdbc.execute(a.get("sql"));',
                   'Map<String,String> make(String s){Map<String,String> m=new HashMap<>();m.put("sql",s);return m;}')['findings'])==1


def test_branch_alias_weak_write(tmp_path):
    r=run(tmp_path,'Map<String,String> a=new HashMap<>(); Map<String,String> b=map; Map<String,String> selected=a; if(input.isEmpty()) selected=b; selected.put("sql","fixed"); jdbc.execute(b.get("sql"));')
    assert len(r['findings'])==1


def test_nested_map(tmp_path):
    assert len(run(tmp_path,'Map<String,Object> outer=new HashMap<>(); Map<String,String> inner=new HashMap<>(); outer.put("nested",inner); inner.put("sql",input); Map<String,String> alias=(Map<String,String>)outer.get("nested"); jdbc.execute(alias.get("sql"));')['findings'])==1


def test_unknown_call_may_mutate(tmp_path):
    r=run(tmp_path,'Map<String,String> a=new HashMap<>(); external.fill(a,input); jdbc.execute(a.get("sql"));')
    assert len(r['findings'])==1
    assert any(d['kind']=='escaped_map_call' for d in r['diagnostics'])


@pytest.mark.parametrize('overwrite,expected',[(False,1),(True,0)])
def test_map_mapper_parameter(tmp_path,overwrite,expected):
    (tmp_path/'M.java').write_text('interface M {void execute(Map<String,String> params);}')
    (tmp_path/'M.xml').write_text('<mapper namespace="M"><update id="execute">${sql}</update></mapper>')
    r=run(tmp_path,('map.put("sql","fixed");' if overwrite else '')+'mapper.execute(map);','M mapper;')
    assert len(r['findings'])==expected


def test_opaque_call_may_mutate(tmp_path):
    (tmp_path/'M.java').write_text('interface M {void fill(Map<String,String> m,String s);}')
    r=run(tmp_path,'Map<String,String> a=new HashMap<>(); mapper.fill(a,input); jdbc.execute(a.get("sql"));','M mapper;')
    assert len(r['findings'])==1


def test_map_mapper_bind(tmp_path):
    (tmp_path/'M.java').write_text('interface M {void execute(Map<String,String> params);}')
    (tmp_path/'M.xml').write_text('<mapper namespace="M"><update id="execute"><bind name="v" value="sql"/>${v}</update></mapper>')
    assert len(run(tmp_path,'mapper.execute(map);','M mapper;')['findings'])==1


def test_reassigned_map(tmp_path):
    assert not run(tmp_path,'map=external.load(input); map.put("sql","fixed"); jdbc.execute(map.get("sql"));')['findings']


def test_two_clean_maps_not_summary_cached(tmp_path):
    r=run(tmp_path,'Map<String,String> a=new HashMap<>();Map<String,String> b=new HashMap<>();fill(a,input);fill(b,input);jdbc.execute(b.get("sql"));', 'void fill(Map<String,String> m,String s){m.put("sql",s);}')
    assert len(r['findings'])==1


def test_dynamic_dispatch_does_not_share_strong_update(tmp_path):
    (tmp_path/'S.java').write_text('interface S {void change(Map<String,String> m);} class A implements S {public void change(Map<String,String> m){m.put("sql","fixed");}} class B implements S {public void change(Map<String,String> m){}}')
    assert len(run(tmp_path,'service.change(map);jdbc.execute(map.get("sql"));','S service;')['findings'])==1


def test_try_does_not_prove_overwrite_on_all_paths(tmp_path):
    assert len(run(tmp_path,'try { map.put("sql","fixed"); } catch(Exception e) {} jdbc.execute(map.get("sql"));')['findings'])==1


def test_switch_does_not_clear_other_case(tmp_path):
    assert len(run(tmp_path,'switch(input) {case "a": map.put("sql","fixed");break;default:break;} jdbc.execute(map.get("sql"));')['findings'])==1


def test_clean_dynamic_write_preserves_known_overwrite(tmp_path):
    assert not run(tmp_path,'map.put("sql","fixed");map.put(input,"other");jdbc.execute(map.get("sql"));')['findings']


def test_xml_select_preserves_overwritten_parameter_key(tmp_path):
    (tmp_path/'M.java').write_text('interface M {String lookup(Map<String,String> params);}')
    (tmp_path/'M.xml').write_text('<mapper namespace="M"><select id="lookup">select name from t where id=#{id}</select></mapper>')
    r=run(tmp_path,'map.put("sql","fixed");mapper.lookup(map);jdbc.execute(map.get("sql"));','M mapper;')
    assert not r['findings']


def test_xml_select_return_is_still_conservative(tmp_path):
    (tmp_path/'M.java').write_text('interface M {String lookup(Map<String,String> params);}')
    (tmp_path/'M.xml').write_text('<mapper namespace="M"><select id="lookup">select name from t where id=#{id}</select></mapper>')
    assert len(run(tmp_path,'jdbc.execute(mapper.lookup(map));','M mapper;')['findings'])==1
