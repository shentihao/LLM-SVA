# LLM-SVA — public release review bundle

A command-line research prototype for Java SQL injection candidate analysis.
It exports inspectable source-to-sink paths, call graphs and approximation diagnostics.
**MIT-licensed local release candidate; not yet published.**

## Contents and versions

- `evaluated-v0.3.4/`: the frozen static engine used in the SANER Tool Demo paper's main experiments.
- `latest-v0.3.5-dev/`: later development source; includes Servlet-source and receiver-resolution fixes. Do not attribute its results to the frozen experiment.
- `llm-replay/`: projected historical public-benchmark decisions and explanations, plus offline scoring. No remote API is invoked.
- `SOURCE_SHA256.json`: hashes of copied implementation, test and example files; each matches its source snapshot byte for byte.
- `VALIDATION.md`: checks actually run for this bundle.

The original working project and historical archives remain intact. This bundle intentionally contains the v3 scanner, required local modules, tests and synthetic examples rather than the full historical workspace. The original 27 baseline files are also preserved to satisfy the existing integrity regression test; per-version README.md and main.py describe the legacy v0.2 interface, not the v3 paper workflow. Use this top-level README and main_v3.py. Business code, internal annotation records, credentials, machine paths, caches and build outputs are excluded. Account-specific experiment runners are excluded.

## Quick start (macOS/Linux)

Python 3.10+ is required. From this bundle's root:

```sh
python3 -m venv .venv
. .venv/bin/activate
python -m pip install -r evaluated-v0.3.4/requirements-v3.txt
cd evaluated-v0.3.4
python main_v3.py --input examples/spring-boot-demo/src/main --output data/demo
python -m pytest -q
```

For the latest development version, change into `latest-v0.3.5-dev` and use the same commands. Installation downloads dependencies; scanning itself is local and needs no API key, JVM or target application build.

Outputs: `report.json`, `findings.json`, `paths.md`, `call-graph.json`, and `call-graph.dot`. Open `paths.md` in an editor and follow file/line, method, parameter and return events. Inspect diagnostics in `report.json`. `path_check.valid` checks evidence structure, not exploitability. Absence of a finding does not establish safety.

To scan another authorized module, use `--input /path/to/module/src/main` so Java and Mapper XML are included. Scan independent modules separately. Defaults: `--max-depth 24 --max-steps 200000`.

## Runnable Spring Boot example

The example is locally developed synthetic code, not an independent benchmark. Requires Java 17 and Maven; initial dependency resolution requires network access. From either version directory:

```sh
mvn -f examples/spring-boot-demo/pom.xml test
mvn -f examples/spring-boot-demo/pom.xml spring-boot:run
```

The application uses a local in-memory H2 database and loopback binding. Compare `/users/template` with `/users/safe-template`, MyBatis `${name}` with `#{name}`, and the Map-overwrite examples. See `DEMO.md` for steps. Keep the intentionally vulnerable demo local.

## Offline LLM evidence replay

From the bundle root:

```sh
python3 llm-replay/replay.py
python3 llm-replay/replay.py --case BenchmarkTest01630
```

This recomputes historical metrics and displays stored decisions; it does not run inference. The scanner's `main_v3.py` has no integrated LLM switch. The original online runner is not included because it is tied to an account-specific endpoint and experiment layout. Live reruns require a separately configured runner and may incur charges; this bundle makes no claim of providing one.

## Interpretation

This is bounded source-level analysis, not complete Java type resolution or a sound whole-program solver. Reflection, dependency injection, dynamic mapping, opaque returns and approximate control flow limit coverage. A row selected by input does not prove control of all returned database fields. Model explanations can contradict decisions; retaining unknown/failure responses does not prevent false safe decisions.

The paper's frozen 504-case benchmark results are TP=78, FP=35, TN=197, FN=194. Historical hybrid filtering yields TP=75, FP=12, TN=220, FN=197. No production runtime vulnerability verification is claimed. No private production labels or source are redistributed here.

## Rights and publication status

LLM-SVA project code and its associated documentation are licensed under the MIT License; see `LICENSE`. The root license covers both included source versions. Dependencies and third-party material retain their respective terms; see `LICENSE-STATUS.md` and `THIRD-PARTY.md`. No public repository URL or DOI has been assigned. Establish a public download location before submitting the paper's availability statement.
