"""
Lightweight intra-procedural CFG representation.

V0.2 creates a statement-level control-flow skeleton from the Java AST.
It is intentionally conservative and explainable. It is not a replacement
for a compiler-grade CFG and should not be described as one in the paper
until branch/exception semantics are completed.
"""

from dataclasses import dataclass, field
from typing import List


@dataclass
class CFGNode:
    id: int
    kind: str
    line: int
    text: str


@dataclass
class CFG:
    nodes: List[CFGNode] = field(default_factory=list)
    edges: List[tuple] = field(default_factory=list)


STATEMENT_TYPES = {
    "local_variable_declaration",
    "expression_statement",
    "return_statement",
    "throw_statement",
    "if_statement",
    "for_statement",
    "enhanced_for_statement",
    "while_statement",
    "do_statement",
}


def build_linear_cfg(method_node, source: str) -> CFG:
    source_bytes = source.encode("utf-8")
    nodes = []

    for node in method_node.named_children:
        if node.type in STATEMENT_TYPES:
            text = source_bytes[node.start_byte:node.end_byte].decode(
                "utf-8", errors="ignore"
            )
            nodes.append(
                CFGNode(
                    id=len(nodes),
                    kind=node.type,
                    line=node.start_point[0] + 1,
                    text=text,
                )
            )

    edges = []
    for i in range(len(nodes) - 1):
        edges.append((nodes[i].id, nodes[i + 1].id))

    return CFG(nodes=nodes, edges=edges)
