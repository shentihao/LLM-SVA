def build_prompt(item):
    return f"""
You are a source-code security auditing agent.

Analyze the following Java method.

Vulnerability Type:
{item["vulnerability"]["type"]} ({item["vulnerability"]["cwe"]})

Candidate Source:
{item["source"]["function"]}

Candidate Sink:
{item["sink"]["function"]}

Program-analysis verification:
{item["verification"]}

Code:
```java
{item["context"]}
```

Rules:
1. Do not report a vulnerability only because a dangerous API appears.
2. The source must be externally controllable.
3. The source must reach the sink through a plausible data-flow path.
4. Consider sanitization or validation.
5. Distinguish a real vulnerability from a merely suspicious pattern.

Return JSON only:
{{
  "is_vulnerable": true,
  "cwe": "{item["vulnerability"]["cwe"]}",
  "source": "...",
  "sink": "...",
  "path_valid": true,
  "sanitization": false,
  "confidence": 0.0,
  "reason": "...",
  "repair": "..."
}}
""".strip()
