package demo;
import org.springframework.stereotype.Repository;
import org.springframework.jdbc.core.JdbcTemplate;
import javax.sql.DataSource;
import java.sql.*;
@Repository
public class UserDao {
    private final JdbcTemplate jdbc;
    private final DataSource dataSource;
    public UserDao(JdbcTemplate jdbc, DataSource dataSource) { this.jdbc = jdbc; this.dataSource = dataSource; }
    public int template(String name) {
        String sql = "SELECT COUNT(*) FROM users WHERE name = '" + name + "'";
        return jdbc.queryForObject(sql, Integer.class);
    }
    public int safeTemplate(String name) {
        return jdbc.queryForObject("SELECT COUNT(*) FROM users WHERE name = ?", Integer.class, name);
    }
    public int jdbc(String name) throws Exception {
        try (Connection conn = dataSource.getConnection(); Statement stmt = conn.createStatement()) {
            ResultSet rs = stmt.executeQuery("SELECT COUNT(*) FROM users WHERE name = '" + name + "'");
            rs.next(); return rs.getInt(1);
        }
    }
    public int preparedUnsafe(String name) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT COUNT(*) FROM users WHERE name = '" + name + "'")) {
            ResultSet rs = stmt.executeQuery(); rs.next(); return rs.getInt(1);
        }
    }
    public int safeJdbc(String name) throws Exception {
        try (Connection conn = dataSource.getConnection();
             PreparedStatement stmt = conn.prepareStatement("SELECT COUNT(*) FROM users WHERE name = ?")) {
            stmt.setString(1, name);
            ResultSet rs = stmt.executeQuery(); rs.next(); return rs.getInt(1);
        }
    }
}
