from pathlib import Path
import pytest
from analysis.scanner_v3 import scan_project_v3


def mapper_case(root,sql,params='@Param("name") String name',call='input',extra_xml=''):
    (root/'C.java').write_text('''import org.springframework.web.bind.annotation.*;
@RestController class C { M mapper;
@GetMapping("/") void run(@RequestParam String input) { mapper.find('''+call+'''); }}
interface M { int find('''+params+'''); }''')
    (root/'M.xml').write_text('<mapper namespace="M">'+extra_xml+'<select id="find">'+sql+'</select></mapper>')
    return scan_project_v3(root)


def test_include_fragment_taint_and_location(tmp_path):
    r=mapper_case(tmp_path,'<include refid="columns"/>',extra_xml='<sql id="columns">SELECT ${name}</sql>')
    assert len(r['findings'])==1
    assert r['findings'][0]['sink']['mapper_fragments'][0]['id']=='M.columns'


def test_cross_namespace_include(tmp_path):
    (tmp_path/'shared.xml').write_text('<mapper namespace="common"><sql id="x">${name}</sql></mapper>')
    assert len(mapper_case(tmp_path,'<include refid="common.x"/>')['findings'])==1


def test_include_property_is_constant(tmp_path):
    r=mapper_case(tmp_path,'<include refid="x"><property name="col" value="fixed"/></include>',extra_xml='<sql id="x">SELECT ${col}</sql>')
    assert r['findings']==[]


@pytest.mark.parametrize('sql,expected',[
    ('<bind name="v" value="name"/>SELECT ${v}',1),
    ('<bind name="v" value="\'fixed\'"/>SELECT ${v}',0),
    ('<bind name="v" value="name"/>SELECT #{v}',0),
    ('<foreach collection="name" item="item">${item}</foreach>',1),
    ('<foreach collection="name" item="item">#{item}</foreach>',0),
    ('<foreach collection="other" item="name">${name}</foreach>',0),
    ('<foreach collection="name" item="x">${x}</foreach> ${x}',1),
])
def test_xml_aliases(tmp_path,sql,expected):
    assert len(mapper_case(tmp_path,sql)['findings'])==expected


def test_recursive_include_diagnostic(tmp_path):
    r=mapper_case(tmp_path,'<include refid="loop"/>',extra_xml='<sql id="loop"><include refid="loop"/></sql>')
    assert any(x['kind']=='mapper_include_cutoff' for x in r['diagnostics'])


def test_missing_include_diagnostic(tmp_path):
    r=mapper_case(tmp_path,'<include refid="missing"/>')
    assert any(x['kind']=='unresolved_mapper_include' for x in r['diagnostics'])


def inherited_case(root,classes,expression='service.go(input)'):
    (root/'C.java').write_text('''import org.springframework.web.bind.annotation.*;
@RestController class C { Service service;
@GetMapping("/") void run(@RequestParam String input) { '''+expression+'''; }}
'''+classes)
    return scan_project_v3(root)


def test_inherited_method_and_field(tmp_path):
    r=inherited_case(tmp_path,'class Base {JdbcTemplate jdbc; void go(String x){jdbc.execute(x);}} class Service extends Base {}')
    assert len(r['findings'])==1
    assert r['findings'][0]['sink']['inherited_from']=='Base'


def test_override_does_not_call_base_sink(tmp_path):
    r=inherited_case(tmp_path,'class Base {JdbcTemplate jdbc; void go(String x){jdbc.execute(x);}} class Service extends Base {void go(String x){}}')
    assert not r['findings']


def test_super_call_is_nonvirtual(tmp_path):
    r=inherited_case(tmp_path,'class Base {JdbcTemplate jdbc; void go(String x){jdbc.execute(x);}} class Service extends Base {void go(String x){super.go(x);}}')
    assert len(r['findings'])==1
    assert not any(x['kind']=='analysis_cutoff' for x in r['diagnostics'])


def test_extends_and_implements_together(tmp_path):
    r=inherited_case(tmp_path,'interface Api {void go(String x);} class Base {JdbcTemplate jdbc; public void go(String x){jdbc.execute(x);}} class Service extends Base implements Api {}')
    assert r['findings']
    assert not any(x['kind']=='unresolved_parent_type' for x in r['diagnostics'])


def test_generic_mapper_field_inherited_method(tmp_path):
    r=inherited_case(tmp_path,'interface M { @Select("select ${x}") int query(@Param("x") String x); } class Base<T> {T mapper; void go(String x){mapper.query(x);}} class Service extends Base<M> {}')
    assert len(r['findings'])==1
    assert any('Service#go' in e['method'] for e in r['findings'][0]['path'])


def test_generic_formal_and_return_substitution(tmp_path):
    r=inherited_case(tmp_path,'class Base<T> {T go(T x){return x;}} class Service extends Base<String>{} class Sink {static JdbcTemplate jdbc; static void use(String x){jdbc.execute(x);}}','Sink.use(service.go(input))')
    assert len(r['findings'])==1
    assert any(e['kind']=='CALL_RETURN' for e in r['findings'][0]['path'])


def test_missing_parent_is_diagnosed_not_invented(tmp_path):
    r=inherited_case(tmp_path,'class Service extends Missing {}')
    assert not r['findings']
    assert any(x['kind']=='unresolved_parent_type' for x in r['diagnostics'])


def test_inherited_mapper_xml_fallback(tmp_path):
    (tmp_path/'base.xml').write_text('<mapper namespace="BaseMapper"><select id="go">SELECT ${x}</select></mapper>')
    r=inherited_case(tmp_path,'interface BaseMapper {void go(@Param("x") String x);} interface Service extends BaseMapper {}')
    assert len(r['findings'])==1
    assert r['findings'][0]['sink']['file']=='base.xml'


def test_opaque_interface_return_is_not_silently_clean(tmp_path):
    r=inherited_case(tmp_path,'interface Service {String go(String x);} class Sink {static JdbcTemplate jdbc; static void use(String x){jdbc.execute(x);}}','Sink.use(service.go(input))')
    assert len(r['findings'])==1
    assert any(e['kind']=='OPAQUE_RETURN' for e in r['findings'][0]['path'])
    from verification.path_verify_v3 import verify_path
    assert verify_path(r['findings'][0],r['call_graph'],tmp_path)['valid']


def test_concrete_constant_return_beats_abstract_declaration(tmp_path):
    r=inherited_case(tmp_path,'interface Service {String go(String x);} class Impl implements Service {public String go(String x){return "constant";}} class Sink {static JdbcTemplate jdbc; static void use(String x){jdbc.execute(x);}}','Sink.use(service.go(input))')
    assert not r['findings']


def test_missing_fully_qualified_parent_never_self_links(tmp_path):
    r=inherited_case(tmp_path,'class Service extends external.Service {}')
    assert any(x['kind']=='unresolved_parent_type' for x in r['diagnostics'])
    assert not any(x['kind']=='inheritance_cycle' for x in r['diagnostics'])


def test_abstract_declarations_are_not_executable_entries(tmp_path):
    (tmp_path/'S.java').write_text('interface S {String read(HttpServletRequest r);}')
    r=scan_project_v3(tmp_path)
    assert r['coverage']['entries_total']==0
    assert r['coverage']['non_executable_declarations']==1


def test_inherited_body_retains_lexical_private_call(tmp_path):
    r=inherited_case(tmp_path,'class Base {JdbcTemplate jdbc; public void go(String x){hidden(x);} private void hidden(String x){jdbc.execute(x);}} class Service extends Base {public void hidden(String x){}}')
    assert len(r['findings'])==1
    assert any(e['method']=='Base#hidden(String)' for e in r['findings'][0]['path'])


def test_multilevel_generic_binding(tmp_path):
    r=inherited_case(tmp_path,'interface M {@Select("${x}") int query(@Param("x") String x);} class Base<T> {T mapper; void go(String x){mapper.query(x);}} class Middle<U> extends Base<U>{} class Service extends Middle<M>{}')
    assert len(r['findings'])==1


def test_conditional_bind_scope_is_diagnosed(tmp_path):
    r=mapper_case(tmp_path,'<if test="name != null"><bind name="v" value="name"/></if>SELECT ${v}')
    assert any(x['kind']=='conditional_bind_scope' for x in r['diagnostics'])


def test_nested_cross_namespace_include_uses_statement_namespace(tmp_path):
    (tmp_path/'shared.xml').write_text('<mapper namespace="common"><sql id="outer"><include refid="inner"/></sql><sql id="inner">fixed</sql></mapper>')
    r=mapper_case(tmp_path,'<include refid="common.outer"/>',extra_xml='<sql id="inner">${name}</sql>')
    assert len(r['findings'])==1
    assert [x['id'] for x in r['findings'][0]['sink']['mapper_fragments']]==['common.outer','M.inner']


def test_bind_inside_include_visible_to_following_sql(tmp_path):
    r=mapper_case(tmp_path,'<include refid="aliases"/>SELECT ${v}',extra_xml='<sql id="aliases"><bind name="v" value="name"/></sql>')
    assert len(r['findings'])==1
