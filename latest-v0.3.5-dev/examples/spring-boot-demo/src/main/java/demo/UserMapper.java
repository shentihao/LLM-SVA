package demo;
import org.apache.ibatis.annotations.*;
@Mapper
public interface UserMapper {
    @Select("SELECT COUNT(*) FROM users WHERE name = '${name}'")
    int unsafe(@Param("name") String name);
    @Select("SELECT COUNT(*) FROM users WHERE name = #{name}")
    int safe(@Param("name") String name);
    int xmlUnsafe(@Param("name") String name);
    int xmlSafe(@Param("name") String name);
    int foreachUnsafe(@Param("names") java.util.List<String> names);
    int foreachSafe(@Param("names") java.util.List<String> names);
    int bindUnsafe(@Param("name") String name);
    int bindSafe(@Param("name") String name);
}
