# Release-bundle validation — 2026-10-10

Checks were performed on the copied release directories, using the existing Python 3.12 environment with installed dependencies. A clean network installation was not tested.

| Check | Observed result |
|---|---|
| evaluated-v0.3.4: python -m pytest -q | 140 passed |
| latest-v0.3.5-dev: python -m pytest -q | 160 passed |
| evaluated-v0.3.4: main_v3.py, included src/main | 7 findings, 31 call edges, 20 diagnostics |
| latest-v0.3.5-dev: same scan | 7 findings, 31 call edges, 20 diagnostics |
| Offline response/CSV consistency | 617 response records, 504 cases; decision fields and filtering policies agree |
| Recomputed static TP/FP/TN/FN | 78 / 35 / 197 / 194 |
| Recomputed hybrid TP/FP/TN/FN | 75 / 12 / 220 / 197 |
| Recomputed standalone LLM decided subset | 472 cases: 247 / 92 / 131 / 2 |

Initial packaging omitted the historical integrity manifest and its baseline files; one existing test failed in each version. The allowlist was expanded to include those original files byte for byte, and both complete suites then passed. No test was removed or skipped to obtain these results.

104 implementation/test/example/baseline files match their source snapshots in SOURCE_SHA256.json. Historical LLM results were intentionally projected to id, case_id, arm, status and parsed fields; provider request IDs, usage data and account configuration are not distributed. The original experimental archives were not modified.

A filename/content audit checked for home-directory paths, credential-like tokens/private keys, account-specific endpoints and known internal project identifiers. No matches were found in distributed text. The ZIP excludes caches, target directories and generated local scan reports. This is a bounded automated audit, not a guarantee against every possible secret format.

Java 17 is available, but Maven is not on the current PATH. Java integration tests and HTTP demonstrations were **not rerun during package preparation**. The paper's 19 passing integration tests belong to the earlier frozen archive. No new remote LLM calls, paid requests, production runtime validation or fresh 504-case static benchmark execution occurred in this step.

MIT was selected on 2026-10-10 and added at the bundle root. License documentation was updated and the archive and hash manifests were regenerated. Implementation files were unchanged; the test results above remain those of package preparation. Public hosting is still pending.
