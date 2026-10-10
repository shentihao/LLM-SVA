# Four-minute demonstration

1. Run the README scan command in evaluated-v0.3.4. Open data/demo/paths.md. Follow a request through Controller, Service, helper return and DAO. Cross-check source locations and call-graph.json.
2. Inspect JdbcTemplate concatenation versus parameter binding, then MyBatis XML replacement versus binding. Compare Map-key overwrite paths. The included tests exercise these distinctions.
3. Optionally run the synthetic Spring Boot application with Maven. These documented local requests distinguish concatenation and binding:

```sh
curl -G --data-urlencode 'name=alice' http://127.0.0.1:8080/users/template
curl -G --data-urlencode "name=' OR '1'='1" http://127.0.0.1:8080/users/template
curl -G --data-urlencode "name=' OR '1'='1" http://127.0.0.1:8080/users/safe-template
```

The example's documented results are 1, 2, 0. They are not new measurements from package preparation; consult VALIDATION.md for checks actually rerun.

4. From the bundle root, run `python3 llm-replay/replay.py --case BenchmarkTest01630`. Show the stored hybrid safe response against the positive benchmark label. Explain the encode/decode round trip and the incorrect quotation argument. This is archived replay, not live inference. Finish by showing approximation diagnostics and explaining that path structure does not establish runtime exploitability.
