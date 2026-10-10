import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class VulnerableSql2 {
    public ResultSet getUser(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        String prefix = "SELECT * FROM users WHERE id = '";
        String sql = prefix + id + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
