"""
AST-backed, intra-procedural taint analysis for Java.

V0.2 deliberately focuses on a small, explainable subset:
- source method invocations taint their assignment target;
- taint propagates through assignments;
- string concatenation propagates taint;
- taint reaches a sink invocation when a sink argument contains a tainted variable;
- sanitizer calls can clear taint for the returned/assigned value.

This is not yet a whole-program Java data-flow engine. It is the next
experimental step beyond lexical Source/Sink matching.
"""

from dataclasses import dataclass, field
from typing import Dict, List, Optional, Set


@dataclass
class TaintEvent:
    variable: str
    line: int
    kind: str
    expression: str


@dataclass
class TaintResult:
    source_found: bool = False
    sink_found: bool = False
    path_valid: bool = False
    sanitized: bool = False
    tainted_variables: Set[str] = field(default_factory=set)
    events: List[TaintEvent] = field(default_factory=list)
    source_expression: Optional[str] = None
    sink_expression: Optional[str] = None


def _node_text(node, source_bytes: bytes) -> str:
    return source_bytes[node.start_byte:node.end_byte].decode(
        "utf-8", errors="ignore"
    )


def _walk(node):
    yield node
    for child in node.children:
        yield from _walk(child)


def _identifier_children(node):
    return [
        child for child in node.children
        if child.type == "identifier"
    ]


def _call_name(node, source_bytes):
    """
    Extract a Java method invocation name from:
      request.getParameter("id")
      stmt.executeQuery(sql)
    """
    if node.type != "method_invocation":
        return None

    name = node.child_by_field_name("name")
    if name is not None:
        return _node_text(name, source_bytes)

    ids = _identifier_children(node)
    return _node_text(ids[-1], source_bytes) if ids else None


def _arguments(node):
    args = node.child_by_field_name("arguments")
    if args is None:
        return []
    return list(args.named_children)


def _expr_contains_variable(expr_text: str, variable: str) -> bool:
    import re
    return re.search(r"\b" + re.escape(variable) + r"\b", expr_text) is not None


def analyze_method(tree, method_node, source: str, rule):
    """
    Perform a conservative AST-backed taint propagation inside one method.
    """
    source_bytes = source.encode("utf-8")
    result = TaintResult()

    source_names = set(rule.get("sources", []))
    sink_names = set(rule.get("sinks", []))
    sanitizer_names = set(rule.get("sanitizers", []))

    tainted: Set[str] = set()
    source_expr = None

    # Process statements in source order. This is intra-procedural and
    # conservative: the AST supplies structural boundaries, while the
    # propagation engine tracks variables.
    nodes = [
        n for n in _walk(method_node)
        if n.type in {
            "local_variable_declaration",
            "expression_statement",
            "method_invocation",
            "assignment_expression",
            "variable_declarator",
        }
    ]
    nodes.sort(key=lambda n: n.start_byte)

    for node in nodes:
        text = _node_text(node, source_bytes)
        line = node.start_point[0] + 1

        # Source invocation.
        if node.type == "method_invocation":
            call_name = _call_name(node, source_bytes)
            if call_name in source_names or any(s in text for s in source_names):
                result.source_found = True
                source_expr = text
                result.source_expression = text

        # Variable declaration:
        #   String id = request.getParameter("id");
        if node.type == "variable_declarator":
            name_node = node.child_by_field_name("name")
            value_node = node.child_by_field_name("value")
            if name_node is not None and value_node is not None:
                var = _node_text(name_node, source_bytes)
                expr = _node_text(value_node, source_bytes)

                has_source = any(
                    s in expr for s in source_names
                )
                inherited = any(
                    _expr_contains_variable(expr, v) for v in tainted
                )
                sanitized = any(s in expr for s in sanitizer_names)

                if has_source or inherited:
                    if sanitized:
                        result.sanitized = True
                        tainted.discard(var)
                    else:
                        tainted.add(var)
                        result.events.append(
                            TaintEvent(var, line, "TAINT", expr)
                        )

        # Assignment:
        #   sql = "..." + id;
        if node.type == "assignment_expression":
            left = node.child_by_field_name("left")
            right = node.child_by_field_name("right")
            if left is not None and right is not None:
                var = _node_text(left, source_bytes)
                expr = _node_text(right, source_bytes)

                inherited = any(
                    _expr_contains_variable(expr, v) for v in tainted
                )
                has_source = any(s in expr for s in source_names)
                sanitized = any(s in expr for s in sanitizer_names)

                if has_source or inherited:
                    if sanitized:
                        result.sanitized = True
                        tainted.discard(var)
                    else:
                        tainted.add(var)
                        result.events.append(
                            TaintEvent(var, line, "TAINT_ASSIGN", expr)
                        )
                elif var in tainted:
                    tainted.discard(var)

        # Sink:
        #   stmt.executeQuery(sql);
        if node.type == "method_invocation":
            call_name = _call_name(node, source_bytes)
            if call_name in sink_names:
                result.sink_found = True
                result.sink_expression = text

                arg_texts = [
                    _node_text(arg, source_bytes)
                    for arg in _arguments(node)
                ]
                reaches = any(
                    any(_expr_contains_variable(arg, v) for v in tainted)
                    for arg in arg_texts
                )

                # Also allow direct source-to-sink use:
                direct_source = any(
                    s in " ".join(arg_texts) for s in source_names
                )

                sink_sanitized = any(
                    s in " ".join(arg_texts) for s in sanitizer_names
                )
                if reaches or direct_source:
                    if sink_sanitized:
                        result.sanitized = True
                    else:
                        result.path_valid = True

    result.tainted_variables = tainted
    return result
