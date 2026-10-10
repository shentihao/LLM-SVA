import javax.servlet.http.HttpServletRequest;
import java.sql.Connection;
import java.sql.PreparedStatement;
import java.sql.ResultSet;

public class SafeSql2 {
    public ResultSet getUser(HttpServletRequest request, Connection conn) throws Exception {
        String id = request.getParameter("id");
        String normalized = id.trim();

        PreparedStatement stmt = conn.prepareStatement(
            "SELECT * FROM users WHERE id = ?"
        );
        stmt.setString(1, normalized);
        return stmt.executeQuery();
    }
}
