"""JavaScript syntax trees (tree-sitter) and a function index per file.

Code is only parsed, never run. If tree-sitter is not installed, or a file does
not parse, callers fall back to the regex scanner and mark results "unknown".

Function model
- Every file has a pseudo-function "<top>" for its top-level code.
- A function declaration, or a function expression bound directly to a name
  (`const f = () => {}`, `f = function () {}`), is "named": it is reached only
  when some reachable code mentions that name.
- Any other function expression (a callback argument, an object/array value, a
  class method, an IIFE) is "inline": it is reached when the function that
  contains it is reached. This over-approximates the call graph on purpose, so
  dynamic dispatch (`obj[k]()`, bundler module maps) never hides code.
"""

import os
import re

try:
    import tree_sitter_javascript as _tsjs
    from tree_sitter import Language, Parser
    _LANG = Language(_tsjs.language())
except Exception:  # pragma: no cover - missing optional dependency
    _LANG = None

FUNC_TYPES = {"function_declaration", "generator_function_declaration", "function_expression",
              "function", "generator_function", "arrow_function", "method_definition"}
DECL_TYPES = {"function_declaration", "generator_function_declaration"}
NAME_TYPES = {"identifier", "property_identifier", "shorthand_property_identifier",
              "shorthand_property_identifier_pattern"}
STRING_TYPES = {"string", "template_string"}
MAX_PARSE_BYTES = 8 * 1024 * 1024

SCRIPT_RE = re.compile(r"<script\b([^>]*)>(.*?)</script\s*>", re.I | re.S)
SRC_RE = re.compile(r"""\bsrc\s*=\s*["']([^"']+)["']""", re.I)


def available():
    return _LANG is not None


def parser():
    return Parser(_LANG)


def text_of(node, src):
    return src[node.start_byte:node.end_byte].decode("utf-8", "replace")


def string_value(node, src):
    """Literal value of a string/template node (templates: only if no ${...})."""
    if node.type == "string":
        return text_of(node, src)[1:-1]
    if node.type == "template_string":
        if any(c.type == "template_substitution" for c in node.children):
            return None
        return text_of(node, src)[1:-1]
    return None


class Func:
    __slots__ = ("id", "file", "name", "kind", "node", "start_line", "end_line", "parent",
                 "names", "strings", "inline_children")

    def __init__(self, fid, file, name, kind, node, line_offset, parent):
        self.id, self.file, self.name, self.kind, self.node, self.parent = fid, file, name, kind, node, parent
        if node is None:
            self.start_line, self.end_line = 1, 10 ** 9
        else:
            self.start_line = node.start_point[0] + 1 + line_offset
            self.end_line = node.end_point[0] + 1 + line_offset
        self.names = set()            # identifiers / property names mentioned directly in its body
        self.strings = set()          # string literals in its body
        self.inline_children = []     # inline function ids reached with it

    def to_dict(self):
        return {"id": self.id, "name": self.name, "kind": self.kind, "file": self.file,
                "lines": [self.start_line, min(self.end_line, 10 ** 8)]}


class Unit:
    """One parsed piece of JavaScript: a .js file or an inline <script> of an HTML file."""

    def __init__(self, file, src, tree, line_offset=0):
        self.file, self.src, self.tree, self.line_offset = file, src, tree, line_offset
        self.top = None
        self.funcs = []


def _bound_name(node, src):
    """Name a function expression is bound to (`const f = ...`, `f = ...`), else None."""
    p = node.parent
    if p is None:
        return None
    if p.type == "variable_declarator" and p.child_by_field_name("value") == node:
        n = p.child_by_field_name("name")
        if n is not None and n.type == "identifier":
            return text_of(n, src)
    if p.type == "assignment_expression" and p.child_by_field_name("right") == node:
        left = p.child_by_field_name("left")
        if left is not None and left.type == "identifier":
            return text_of(left, src)
    return None


def _func_name(node, src):
    n = node.child_by_field_name("name")
    if n is not None:
        return text_of(n, src)
    return _bound_name(node, src)


def index_unit(unit, uid_prefix):
    """Walk the tree once: create Func records and attach names/strings to the innermost one."""
    src = unit.src
    top = Func(f"{uid_prefix}:<top>", unit.file, "<top>", "top", None, unit.line_offset, None)
    unit.top = top
    unit.funcs.append(top)
    stack = [(unit.tree.root_node, top)]
    n_funcs = 0
    while stack:
        node, owner = stack.pop()
        cur = owner
        if node.type in FUNC_TYPES and node.is_named:   # the bare `function` keyword token is not a function
            n_funcs += 1
            name = _func_name(node, src)
            if node.type in DECL_TYPES or (name and _bound_name(node, src)):
                kind = "named"
            else:
                kind = "inline"
            cur = Func(f"{uid_prefix}:{node.start_byte}", unit.file, name or "<anonymous>", kind, node,
                       unit.line_offset, owner.id)
            unit.funcs.append(cur)
            if kind == "inline":
                owner.inline_children.append(cur.id)
        elif node.type in NAME_TYPES:
            cur.names.add(text_of(node, src))
        elif node.type in STRING_TYPES:
            v = string_value(node, src)
            if v:
                cur.strings.add(v)
        for ch in reversed(node.children):
            stack.append((ch, cur))
    return unit


def parse_text(file, text, line_offset=0):
    """Parse JS text. Returns a Unit, or None if tree-sitter is missing or the parse is broken."""
    if _LANG is None:
        return None
    data = text.encode("utf-8", "replace")
    if len(data) > MAX_PARSE_BYTES:
        return None
    tree = parser().parse(data)
    root = tree.root_node
    # Tolerate small local errors, reject files that are mostly unparsable.
    if root.has_error:
        bad = _error_bytes(root)
        if bad > max(200, len(data) // 10):
            return None
    return Unit(file, data, tree, line_offset)


def _error_bytes(root):
    total, stack = 0, [root]
    while stack:
        n = stack.pop()
        if n.type == "ERROR" or n.is_missing:
            total += max(1, n.end_byte - n.start_byte)
            continue
        if n.has_error:
            stack.extend(n.children)
    return total


def html_scripts(text):
    """(srcs, [(inline_text, line_offset)]) from an HTML page."""
    srcs, inline = [], []
    for m in SCRIPT_RE.finditer(text):
        s = SRC_RE.search(m.group(1))
        if s:
            srcs.append(s.group(1))
        elif m.group(2).strip():
            inline.append((m.group(2), text.count("\n", 0, m.start(2))))
    return srcs, inline


def norm_ref(ref, base_file=None):
    """Package-relative path a string may refer to ('./a.js', '/a.js', 'chrome-extension://id/a.js')."""
    if not ref or len(ref) > 300 or "\n" in ref:
        return None
    r = ref.split("?", 1)[0].split("#", 1)[0]
    if r.startswith("chrome-extension://"):
        r = r.split("/", 3)[3] if r.count("/") >= 3 else ""
    if "://" in r or r.startswith("data:"):
        return None
    if base_file and not r.startswith("/"):
        r = os.path.join(os.path.dirname(base_file), r)
    return os.path.normpath(r.lstrip("/"))
