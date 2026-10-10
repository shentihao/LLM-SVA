package demo;
import org.springframework.web.bind.annotation.*;
@RestController
@RequestMapping("/users")
public class UserController {
    private final UserService service;
    public UserController(UserService service) { this.service = service; }
    @GetMapping("/jdbc")
    public int jdbc(@RequestParam("name") String name) throws Exception { return service.jdbc(name); }
    @GetMapping("/template")
    public int template(@RequestParam("name") String name) { return service.template(name); }
    @GetMapping("/mapper")
    public int mapper(@RequestParam("name") String name) { return service.mapper(name); }
    @GetMapping("/xml")
    public int xml(@RequestParam("name") String name) { return service.xml(name); }
    @GetMapping("/prepared-unsafe")
    public int preparedUnsafe(@RequestParam("name") String name) throws Exception { return service.preparedUnsafe(name); }
    @GetMapping("/safe-template")
    public int safeTemplate(@RequestParam("name") String name) { return service.safeTemplate(name); }
    @GetMapping("/safe-jdbc")
    public int safeJdbc(@RequestParam("name") String name) throws Exception { return service.safeJdbc(name); }
    @GetMapping("/safe-mapper")
    public int safeMapper(@RequestParam("name") String name) { return service.safeMapper(name); }
    @GetMapping("/safe-xml")
    public int safeXml(@RequestParam("name") String name) { return service.safeXml(name); }
    @PostMapping("/map-unsafe")
    public int mapUnsafe(@RequestBody java.util.Map<String,String> input) {
        return service.template(input.get("name"));
    }
    @PostMapping("/map-overwritten")
    public int mapOverwritten(@RequestBody java.util.Map<String,String> input) {
        java.util.Map<String,String> alias = input;
        alias.put("name", "alice");
        return service.template(input.get("name"));
    }
    @PostMapping("/map-try-overwritten")
    public int mapTryOverwritten(@RequestBody java.util.Map<String,String> input) {
        try {
            input.put("name", "alice");
            return service.template(input.get("name"));
        } catch (IllegalArgumentException e) {
            return 0;
        }
    }
    @PostMapping("/map-catch")
    public int mapCatch(@RequestBody java.util.Map<String,String> input) {
        try {
            if (input.containsKey("fail")) throw new IllegalArgumentException("demo failure");
            input.put("name", "alice");
        } catch (IllegalArgumentException e) {
            return service.template(input.get("name"));
        }
        return 1;
    }
}
