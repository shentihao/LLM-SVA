# Dependencies and benchmark provenance

Dependencies are declared rather than redistributed as binaries or source:
- Tree-sitter Python bindings: https://github.com/tree-sitter/py-tree-sitter
- Tree-sitter Java grammar: https://github.com/tree-sitter/tree-sitter-java
- pytest: https://github.com/pytest-dev/pytest
- Spring Boot: https://github.com/spring-projects/spring-boot
- MyBatis Spring Boot starter: https://github.com/mybatis/spring-boot-starter
- H2: https://github.com/h2database/h2database

Python versions are specified in requirements-v3.txt; Java dependencies and versions are in the example pom.xml. Consult upstream licenses before redistributing dependencies.

Historical result identifiers refer to OWASP Benchmark Java:
https://github.com/OWASP-Benchmark/BenchmarkJava
Commit: 20cbf3d11123347e47ed89541e6942836def53f7.
The benchmark's Java sources, request prompts and helper classes are not included. Retrieve the exact upstream revision separately to inspect case source under its upstream license. Responses may contain brief code expressions as model-generated evidence; they are historical outputs, not authoritative source or ground truth.

Historical model: qwen-plus-2025-07-28; temperature 0, thinking disabled, max output 1200 tokens. One call per condition, no automatic retries. Only public benchmark code was submitted. Provider IDs, endpoint and usage metadata are omitted from the replay projection. Original experiments are preserved privately without modification.
