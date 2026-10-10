from pathlib import Path

from parser.java_parser import JavaParser
from analysis.rules import RULES
from analysis.taint import analyze_method
from analysis.cfg import build_linear_cfg


def scan_project_v2(project: Path, cwe=None):
    parser = JavaParser()
    rules = {cwe: RULES[cwe]} if cwe in RULES else RULES
    findings = []

    for path in project.rglob("*.java"):
        try:
            source = path.read_text(encoding="utf-8", errors="ignore")
        except OSError:
            continue

        tree = parser.parse(source)

        method_nodes = []

        def walk(node):
            if node.type == "method_declaration":
                method_nodes.append(node)
            for child in node.children:
                walk(child)

        walk(tree.root_node)

        for method_node in method_nodes:
            name_node = method_node.child_by_field_name("name")
            method_name = (
                source[name_node.start_byte:name_node.end_byte]
                if name_node else "<anonymous>"
            )

            for cwe, rule in rules.items():
                taint = analyze_method(tree, method_node, source, rule)

                if not (taint.source_found and taint.sink_found):
                    continue

                cfg = build_linear_cfg(method_node, source)

                findings.append({
                    "file": str(path),
                    "method": method_name,
                    "language": "java",
                    "vulnerability": {
                        "type": rule["name"],
                        "cwe": cwe,
                        "severity": "HIGH"
                    },
                    "source": {
                        "function": taint.source_expression or "unknown",
                        "line": method_node.start_point[0] + 1
                    },
                    "sink": {
                        "function": taint.sink_expression or "unknown",
                        "line": method_node.start_point[0] + 1
                    },
                    "dataflow": [
                        {
                            "variable": e.variable,
                            "line": e.line,
                            "kind": e.kind,
                            "expression": e.expression
                        }
                        for e in taint.events
                    ],
                    "verification": {
                        "source_valid": taint.source_found,
                        "path_valid": taint.path_valid,
                        "sink_valid": taint.sink_found,
                        "sanitization_absent": not taint.sanitized
                    },
                    "cfg": {
                        "node_count": len(cfg.nodes),
                        "edge_count": len(cfg.edges),
                        "edges": cfg.edges
                    },
                    "context": source[
                        method_node.start_byte:method_node.end_byte
                    ],
                    "rule": rule
                })

    return findings
