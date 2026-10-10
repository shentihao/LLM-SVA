import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.ResultSet;
import java.sql.Statement;

public class VulnerableSql {
    public ResultSet getUser(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        String sql = "SELECT * FROM users WHERE id = '" + id + "'";
        Statement stmt = conn.createStatement();
        return stmt.executeQuery(sql);
    }
}
