import pytest
from analysis.scanner_v3 import scan_project_v3
from verification.path_verify_v3 import verify_path


def scan(tmp_path, expression, safe=False, receiver='HttpServletRequest', sink='jdbc'):
    sql='"select ?", '+expression if safe else expression
    (tmp_path/'Example.java').write_text('''
import jakarta.servlet.http.*;
import jakarta.servlet.ServletRequest;
import org.springframework.jdbc.core.JdbcTemplate;
class Holder { static JdbcTemplate jdbc; }
class Wrapper { Holder holder; }
class Example {
  JdbcTemplate jdbc; Wrapper wrapper;
  void route('''+receiver+''' request) { '''+sink+'.queryForList('+sql+'''); }
}
class LocalRequest { String getHeaders(String key) { return "fixed"; } }
''')
    report=scan_project_v3(tmp_path)
    assert all(verify_path(f,report['call_graph'],tmp_path)['valid'] for f in report['findings'])
    return report


@pytest.mark.parametrize('expression',[
 'request.getHeaders("x").nextElement()',
 'request.getParameterValues("x")[0]',
 'request.getCookies()[0].getValue()',
 'request.getParameterMap().get("x")[0]',
 'request.getHeader("x")',
 'request.getParameter("x")',
 'request.getQueryString()',
])
@pytest.mark.parametrize('safe',[False,True])
def test_servlet_sources_and_bindings(tmp_path,expression,safe):
    assert bool(scan(tmp_path,expression,safe)['findings']) is not safe


@pytest.mark.parametrize('sink',['Holder.jdbc','wrapper.holder.jdbc','this.jdbc'])
def test_field_receiver(tmp_path,sink):
    assert scan(tmp_path,'request.getParameter("x")',sink=sink)['findings']
    assert not scan(tmp_path,'request.getParameter("x")',safe=True,sink=sink)['findings']


def test_non_servlet_same_method_name(tmp_path):
    assert not scan(tmp_path,'request.getHeaders("x")',receiver='LocalRequest')['findings']


def test_servlet_request_parameter_map(tmp_path):
    assert scan(tmp_path,'request.getParameterMap().get("x")[0]',receiver='ServletRequest')['findings']


def test_field_receiver_method_chain(tmp_path):
    (tmp_path/'C.java').write_text('''
import org.springframework.jdbc.core.JdbcTemplate;
import jakarta.servlet.http.HttpServletRequest;
class DAO { JdbcTemplate jdbc; void execute(String s) { jdbc.execute(s); } }
class Holder { static DAO dao; }
class C { void route(HttpServletRequest r) { Holder.dao.execute(r.getParameter("x")); } }
''')
    report=scan_project_v3(tmp_path)
    assert len(report['findings'])==1
    assert any(e['kind']=='CALL' for e in report['findings'][0]['path'])
