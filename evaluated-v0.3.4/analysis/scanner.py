import re
from pathlib import Path

from parser.java_parser import JavaParser
from analysis.rules import RULES
from verification.path_verify import verify_method


def _line_of(text: str, offset: int) -> int:
    return text[:offset].count("\n") + 1


def _find_first(text, terms):
    for term in terms:
        pos = text.find(term)
        if pos >= 0:
            return term, pos
    return None, -1


def scan_project(project: Path, cwe=None):
    parser = JavaParser()
    findings = []

    rules = {cwe: RULES[cwe]} if cwe and cwe in RULES else RULES

    for path in project.rglob("*.java"):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        if len(source.encode("utf-8")) > 512 * 1024:
            continue

        methods = parser.methods(source)

        for method in methods:
            code = method["source"]

            for rule_cwe, rule in rules.items():
                source_name, source_pos = _find_first(code, rule["sources"])
                sink_name, sink_pos = _find_first(code, rule["sinks"])

                if source_pos < 0 or sink_pos < 0:
                    continue

                verification = verify_method(
                    code,
                    rule["sources"],
                    rule["sinks"],
                    rule["sanitizers"]
                )

                findings.append({
                    "file": str(path),
                    "method": method["name"],
                    "language": "java",
                    "vulnerability": {
                        "type": rule["name"],
                        "cwe": rule_cwe,
                        "severity": "HIGH"
                    },
                    "source": {
                        "function": source_name,
                        "line": method["start_line"] + _line_of(code, source_pos) - 1
                    },
                    "sink": {
                        "function": sink_name,
                        "line": method["start_line"] + _line_of(code, sink_pos) - 1
                    },
                    "dataflow": [source_name, "local_variables", sink_name],
                    "verification": verification,
                    "rule": rule,
                    "context": code
                })

    return findings
