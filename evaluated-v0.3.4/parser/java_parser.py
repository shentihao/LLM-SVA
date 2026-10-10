from pathlib import Path
from tree_sitter import Language, Parser
import tree_sitter_java as tsjava


JAVA = Language(tsjava.language())


class JavaParser:
    def __init__(self):
        self.parser = Parser(JAVA)

    def parse(self, source: str):
        return self.parser.parse(source.encode("utf-8"))

    def methods(self, source: str):
        tree = self.parse(source)
        result = []
        stack = [tree.root_node]

        while stack:
            node = stack.pop()
            if node.type == "method_declaration":
                name = node.child_by_field_name("name")
                body = node.child_by_field_name("body")
                if name is not None:
                    result.append({
                        "name": source[name.start_byte:name.end_byte],
                        "start_line": node.start_point[0] + 1,
                        "end_line": node.end_point[0] + 1,
                        "source": source[node.start_byte:node.end_byte],
                        "body": source[body.start_byte:body.end_byte] if body else ""
                    })
            stack.extend(reversed(node.children))

        return result
