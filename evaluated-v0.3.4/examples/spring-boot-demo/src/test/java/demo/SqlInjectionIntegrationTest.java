package demo;
import org.junit.jupiter.params.ParameterizedTest;
import org.junit.jupiter.params.provider.ValueSource;
import org.springframework.beans.factory.annotation.Autowired;
import org.springframework.boot.test.context.SpringBootTest;
import org.springframework.boot.test.autoconfigure.web.servlet.AutoConfigureMockMvc;
import org.springframework.test.web.servlet.MockMvc;
import static org.springframework.test.web.servlet.request.MockMvcRequestBuilders.get;
import static org.springframework.test.web.servlet.result.MockMvcResultMatchers.*;

@SpringBootTest(webEnvironment = SpringBootTest.WebEnvironment.RANDOM_PORT)
@AutoConfigureMockMvc
class SqlInjectionIntegrationTest {
    @Autowired MockMvc mvc;
    @Autowired UserMapper mapper;

    @org.junit.jupiter.api.Test
    void foreachTextSubstitutionIsSql() {
        org.junit.jupiter.api.Assertions.assertEquals(1, mapper.foreachUnsafe(java.util.List.of("alice")));
        org.junit.jupiter.api.Assertions.assertEquals(2, mapper.foreachUnsafe(java.util.List.of("alice') OR 1=1 -- ")));
    }
    @org.junit.jupiter.api.Test
    void foreachParametersRemainData() {
        org.junit.jupiter.api.Assertions.assertEquals(1, mapper.foreachSafe(java.util.List.of("alice")));
        org.junit.jupiter.api.Assertions.assertEquals(0, mapper.foreachSafe(java.util.List.of("alice') OR 1=1 -- ")));
    }
    @org.junit.jupiter.api.Test
    void bindTextSubstitutionIsSql() {
        org.junit.jupiter.api.Assertions.assertEquals(1, mapper.bindUnsafe("alice"));
        org.junit.jupiter.api.Assertions.assertEquals(2, mapper.bindUnsafe("' OR '1'='1"));
    }
    @org.junit.jupiter.api.Test
    void bindParametersRemainData() {
        org.junit.jupiter.api.Assertions.assertEquals(1, mapper.bindSafe("alice"));
        org.junit.jupiter.api.Assertions.assertEquals(0, mapper.bindSafe("' OR '1'='1"));
    }
    @Autowired org.springframework.boot.test.web.client.TestRestTemplate http;

    @org.junit.jupiter.api.Test
    void realHttpUnsafeEndpoint() {
        var response = http.getForEntity("/users/template?name={name}", Integer.class, "' OR '1'='1");
        org.junit.jupiter.api.Assertions.assertEquals(200, response.getStatusCode().value());
        org.junit.jupiter.api.Assertions.assertEquals(2, response.getBody());
    }

    @org.junit.jupiter.api.Test
    void realHttpSafeEndpoint() {
        var response = http.getForEntity("/users/safe-template?name={name}", Integer.class, "' OR '1'='1");
        org.junit.jupiter.api.Assertions.assertEquals(200, response.getStatusCode().value());
        org.junit.jupiter.api.Assertions.assertEquals(0, response.getBody());
    }
    @ParameterizedTest
    @ValueSource(strings={"jdbc","template","mapper","xml","prepared-unsafe"})
    void unsafeSqlIsActuallyExploitable(String endpoint) throws Exception {
        mvc.perform(get("/users/"+endpoint).param("name", "alice")).andExpect(status().isOk()).andExpect(content().string("1"));
        mvc.perform(get("/users/"+endpoint).param("name", "' OR '1'='1")).andExpect(status().isOk()).andExpect(content().string("2"));
    }
    @ParameterizedTest
    @ValueSource(strings={"safe-jdbc","safe-template","safe-mapper","safe-xml"})
    void boundParametersStayData(String endpoint) throws Exception {
        mvc.perform(get("/users/"+endpoint).param("name", "alice")).andExpect(status().isOk()).andExpect(content().string("1"));
        mvc.perform(get("/users/"+endpoint).param("name", "' OR '1'='1")).andExpect(status().isOk()).andExpect(content().string("0"));
    }
    @org.junit.jupiter.api.Test
    void realHttpMapInputReachesSql() {
        var response = http.postForEntity("/users/map-unsafe", java.util.Map.of("name", "' OR '1'='1"), Integer.class);
        org.junit.jupiter.api.Assertions.assertEquals(200, response.getStatusCode().value());
        org.junit.jupiter.api.Assertions.assertEquals(2, response.getBody());
    }
    @org.junit.jupiter.api.Test
    void realHttpMapOverwriteReplacesInput() {
        var response = http.postForEntity("/users/map-overwritten", java.util.Map.of("name", "' OR '1'='1"), Integer.class);
        org.junit.jupiter.api.Assertions.assertEquals(200, response.getStatusCode().value());
        org.junit.jupiter.api.Assertions.assertEquals(1, response.getBody());
    }
    @org.junit.jupiter.api.Test
    void realHttpTryOverwriteUsesFixedValue() {
        var response = http.postForEntity("/users/map-try-overwritten", java.util.Map.of("name", "' OR '1'='1"), Integer.class);
        org.junit.jupiter.api.Assertions.assertEquals(200, response.getStatusCode().value());
        org.junit.jupiter.api.Assertions.assertEquals(1, response.getBody());
    }
    @org.junit.jupiter.api.Test
    void realHttpCatchBeforeOverwriteRetainsInput() {
        var response = http.postForEntity("/users/map-catch", java.util.Map.of("name", "' OR '1'='1", "fail", "yes"), Integer.class);
        org.junit.jupiter.api.Assertions.assertEquals(200, response.getStatusCode().value());
        org.junit.jupiter.api.Assertions.assertEquals(2, response.getBody());
    }
}
