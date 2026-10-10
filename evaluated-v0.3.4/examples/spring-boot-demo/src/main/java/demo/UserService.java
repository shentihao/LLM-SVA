package demo;
import org.springframework.stereotype.Service;
@Service
public class UserService {
    private final UserDao dao;
    private final UserMapper mapper;
    public UserService(UserDao dao, UserMapper mapper) { this.dao = dao; this.mapper = mapper; }
    public String normalize(String value) { return value.trim(); }
    public int jdbc(String name) throws Exception { return dao.jdbc(normalize(name)); }
    public int template(String name) { return dao.template(normalize(name)); }
    public int mapper(String name) { return mapper.unsafe(normalize(name)); }
    public int xml(String name) { return mapper.xmlUnsafe(normalize(name)); }
    public int preparedUnsafe(String name) throws Exception { return dao.preparedUnsafe(normalize(name)); }
    public int safeTemplate(String name) { return dao.safeTemplate(normalize(name)); }
    public int safeJdbc(String name) throws Exception { return dao.safeJdbc(normalize(name)); }
    public int safeMapper(String name) { return mapper.safe(normalize(name)); }
    public int safeXml(String name) { return mapper.xmlSafe(normalize(name)); }
}
