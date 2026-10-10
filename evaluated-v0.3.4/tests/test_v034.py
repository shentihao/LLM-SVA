import pytest
from test_v033 import run


@pytest.mark.parametrize('body,expected',[
 ('try {map.put("sql","fixed");jdbc.execute(map.get("sql"));} catch(Exception e) {}',0),
 ('try {jdbc.execute(map.get("sql"));map.put("sql","fixed");} catch(Exception e) {}',1),
 ('try {map.put("sql","fixed");external.fail();} catch(Exception e) {jdbc.execute(map.get("sql"));}',1),
 ('try {map.put("sql","fixed");} catch(Exception e) {map.put("sql","fixed");} jdbc.execute(map.get("sql"));',0),
 ('try {map.put("sql","fixed");} finally {} jdbc.execute(map.get("sql"));',1),
 ('try {external.fail();} finally {map.put("sql","fixed");} jdbc.execute(map.get("sql"));',0),
 ('try {map.put("sql","fixed");} finally {jdbc.execute(map.get("sql"));}',1),
 ('try {map.put("sql","fixed");} catch(Exception e) {} finally {map.put("sql",input);} jdbc.execute(map.get("sql"));',1),
 ('try {map.put("sql","fixed");throw new Exception();jdbc.execute(map.get("sql"));} catch(Exception e) {}',0),
 ('try {try {map.put("sql","fixed");jdbc.execute(map.get("sql"));} finally {}} catch(Exception e) {}',0),
 ('try (Connection c=external.open()) {map.put("sql","fixed");jdbc.execute(map.get("sql"));} catch(Exception e) {}',0),
])
def test_try_map_paths(tmp_path,body,expected):
    assert len(run(tmp_path,body)['findings'])==expected


def test_catch_observes_intermediate_write(tmp_path):
    r=run(tmp_path,'Map<String,String> m=new HashMap<>();try {m.put("sql",input);external.fail();m.put("sql","fixed");}catch(Exception e){jdbc.execute(m.get("sql"));}')
    assert len(r['findings'])==1
    assert any(e['kind']=='EXCEPTION_PATH' for e in r['findings'][0]['path'])


def test_catch_observes_callee_write(tmp_path):
    r=run(tmp_path,'Map<String,String> m=new HashMap<>();try {fill(m,input);m.put("sql","fixed");}catch(Exception e){jdbc.execute(m.get("sql"));}',
          'void fill(Map<String,String> m,String x){m.put("sql",x);external.fail();}')
    assert len(r['findings'])==1


def test_catch_observes_scalar_intermediate_state(tmp_path):
    assert len(run(tmp_path,'String sql="fixed";try {sql=input;external.fail();sql="fixed";}catch(Exception e){jdbc.execute(sql);}')['findings'])==1


def test_finally_return_overrides_tainted_return(tmp_path):
    assert not run(tmp_path,'jdbc.execute(choose(input));',
                   'String choose(String x){try{return x;}finally{return "fixed";}}')['findings']


def test_finally_tainted_return(tmp_path):
    assert len(run(tmp_path,'jdbc.execute(choose(input));',
                   'String choose(String x){try{return "fixed";}finally{return x;}}')['findings'])==1


def test_finally_throw_discards_return(tmp_path):
    assert not run(tmp_path,'jdbc.execute(choose(input));',
                   'String choose(String x){try{return x;}finally{throw new RuntimeException();}}')['findings']


def test_returned_map_modified_by_finally(tmp_path):
    assert not run(tmp_path,'jdbc.execute(choose(map).get("sql"));',
                   'Map<String,String> choose(Map<String,String> m){try{return m;}finally{m.put("sql","fixed");}}')['findings']


def test_finally_runs_after_return(tmp_path):
    assert len(run(tmp_path,'try {return;} finally {jdbc.execute(input);}')['findings'])==1


def test_catches_are_alternatives(tmp_path):
    assert len(run(tmp_path,'try {external.fail();} catch(IllegalArgumentException e){map.put("sql","fixed");}catch(Exception e){jdbc.execute(map.get("sql"));}')['findings'])==1


def test_shared_map_graph_and_cycle(tmp_path):
    body='Map<String,Object> m=new HashMap<>();m.put("sql",input);'
    for i in range(24):
        body+=f'Map<String,Object> n{i}=new HashMap<>();n{i}.put("a",m);n{i}.put("b",m);m=n{i};'
    body+='m.put("self",m);jdbc.execute(external.text(m));'
    assert len(run(tmp_path,body)['findings'])==1


def test_returned_branch_does_not_pollute_continuation(tmp_path):
    assert not run(tmp_path,'Map<String,String> m=new HashMap<>();if(input.isEmpty()){m.put("sql",input);return;}jdbc.execute(m.get("sql"));')['findings']


def test_early_return_preserves_returned_map_heap(tmp_path):
    r=run(tmp_path,'jdbc.execute(choose(input).get("sql"));',
          'Map<String,String> choose(String x){Map<String,String> m=new HashMap<>();if(x.isEmpty()){m.put("sql",x);return m;}m.put("sql","fixed");return m;}')
    assert len(r['findings'])==1


def test_finally_cleans_early_return_heap(tmp_path):
    r=run(tmp_path,'jdbc.execute(choose(input).get("sql"));',
          'Map<String,String> choose(String x){Map<String,String> m=new HashMap<>();try{if(x.isEmpty()){m.put("sql",x);return m;}return m;}finally{m.put("sql","fixed");}}')
    assert not r['findings']


def test_break_keeps_map_side_effect(tmp_path):
    assert len(run(tmp_path,'Map<String,String> m=new HashMap<>();while(input.isEmpty()){if(input.isEmpty()){m.put("sql",input);break;}}jdbc.execute(m.get("sql"));')['findings'])==1
