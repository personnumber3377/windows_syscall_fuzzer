#!/usr/bin/env python3
"""Generate a JSON type graph from Windows C/C++ headers using libclang.

Stage 1 only: primitives, typedefs, records, enums, pointers, arrays,
function/callback signatures, and preserved Windows handle typedef names.

Example:
    python generate_type_graph.py winddi.h -I . --pretty -o type_graph.json

Dependency:
    python -m pip install clang

If libclang is not found automatically:
    python generate_type_graph.py winddi.h --libclang /path/to/libclang.so
"""
from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Optional

try:
    from clang import cindex
except ImportError as exc:
    raise SystemExit(
        "Missing Python clang bindings. Install with: python -m pip install clang"
    ) from exc

SCHEMA_VERSION = 1

PRIMITIVES = {
    cindex.TypeKind.VOID: "void",
    cindex.TypeKind.BOOL: "bool",
    cindex.TypeKind.CHAR_U: "char",
    cindex.TypeKind.UCHAR: "unsigned_char",
    cindex.TypeKind.CHAR16: "char16",
    cindex.TypeKind.CHAR32: "char32",
    cindex.TypeKind.USHORT: "unsigned_short",
    cindex.TypeKind.UINT: "unsigned_int",
    cindex.TypeKind.ULONG: "unsigned_long",
    cindex.TypeKind.ULONGLONG: "unsigned_long_long",
    cindex.TypeKind.UINT128: "unsigned_int128",
    cindex.TypeKind.CHAR_S: "signed_char",
    cindex.TypeKind.SCHAR: "signed_char",
    cindex.TypeKind.WCHAR: "wchar",
    cindex.TypeKind.SHORT: "short",
    cindex.TypeKind.INT: "int",
    cindex.TypeKind.LONG: "long",
    cindex.TypeKind.LONGLONG: "long_long",
    cindex.TypeKind.INT128: "int128",
    cindex.TypeKind.FLOAT: "float",
    cindex.TypeKind.DOUBLE: "double",
    cindex.TypeKind.LONGDOUBLE: "long_double",
    cindex.TypeKind.HALF: "half",
    cindex.TypeKind.NULLPTR: "nullptr",
}

RECORD_CURSORS = {
    cindex.CursorKind.STRUCT_DECL,
    cindex.CursorKind.UNION_DECL,
    cindex.CursorKind.CLASS_DECL,
}

GENERIC_HANDLES = {
    "HANDLE", "HGDIOBJ", "HDC", "HWND", "HMODULE", "HINSTANCE",
    "HGLOBAL", "HLOCAL", "HRSRC", "HFILE",
}


def compact(value: str) -> str:
    return " ".join(value.split())


def sizeof(t: cindex.Type) -> Optional[int]:
    try:
        n = t.get_size()
        return n if n >= 0 else None
    except Exception:
        return None


def alignof(t: cindex.Type) -> Optional[int]:
    try:
        n = t.get_align()
        return n if n >= 0 else None
    except Exception:
        return None


def field_offset(cursor: cindex.Cursor) -> Optional[int]:
    try:
        n = cursor.get_field_offsetof()
        return n if n >= 0 else None
    except Exception:
        return None


def location(cursor: Optional[cindex.Cursor]) -> Optional[dict[str, Any]]:
    if cursor is None or not cursor.location or not cursor.location.file:
        return None
    return {
        "file": str(Path(cursor.location.file.name).resolve()),
        "line": cursor.location.line,
        "column": cursor.location.column,
    }


def usr(cursor: Optional[cindex.Cursor]) -> Optional[str]:
    if cursor is None:
        return None
    try:
        return cursor.get_usr() or None
    except Exception:
        return None


def anonymous_name(cursor: cindex.Cursor, category: str) -> str:
    seed = usr(cursor) or json.dumps(location(cursor), sort_keys=True) or cursor.displayname
    digest = hashlib.sha1(seed.encode("utf-8", errors="replace")).hexdigest()[:12]
    return f"__anonymous_{category}_{digest}"


def decl_name(cursor: cindex.Cursor, category: str) -> str:
    return cursor.spelling or cursor.displayname or anonymous_name(cursor, category)


def canonical_spelling(t: cindex.Type) -> str:
    try:
        return compact(t.get_canonical().spelling)
    except Exception:
        return compact(t.spelling)


def declaration_type_name(t: cindex.Type) -> Optional[str]:
    try:
        declaration = t.get_declaration()
    except Exception:
        return None
    if not declaration or declaration.kind == cindex.CursorKind.NO_DECL_FOUND:
        return None
    if declaration.spelling:
        return declaration.spelling
    if declaration.kind in RECORD_CURSORS:
        category = "union" if declaration.kind == cindex.CursorKind.UNION_DECL else "struct"
        return anonymous_name(declaration, category)
    return None


def looks_like_handle(name: str) -> bool:
    if name in GENERIC_HANDLES:
        return True
    return bool(
        re.fullmatch(r"H[A-Z][A-Z0-9_]*", name)
        or re.fullmatch(r"DH[A-Z][A-Z0-9_]*", name)
    )


def points_to_declared_handle(t: cindex.Type) -> bool:
    try:
        canonical = t.get_canonical()
        if canonical.kind != cindex.TypeKind.POINTER:
            return False
        declaration = canonical.get_pointee().get_declaration()
        tag = declaration.spelling if declaration else ""
        return bool(tag and (tag.endswith("__") or tag.endswith("_HANDLE")))
    except Exception:
        return False


@dataclass
class Graph:
    types: dict[str, dict[str, Any]] = field(default_factory=dict)
    declarations: dict[str, dict[str, Any]] = field(default_factory=dict)
    aliases: dict[str, str] = field(default_factory=dict)
    diagnostics: list[dict[str, Any]] = field(default_factory=list)
    active: set[str] = field(default_factory=set)

    def store_type(self, key: str, node: dict[str, Any]) -> None:
        old = self.types.get(key)
        if old is None or (node.get("complete") and not old.get("complete")):
            self.types[key] = node


class Builder:
    def __init__(self, graph: Graph, roots: list[Path], include_system: bool) -> None:
        self.graph = graph
        self.root_files = {str(path.resolve()) for path in roots}
        self.include_system = include_system

    def is_root_declaration(self, cursor: cindex.Cursor) -> bool:
        if self.include_system:
            return True
        loc = location(cursor)
        return bool(loc and loc["file"] in self.root_files)

    def key_for(self, t: cindex.Type, preferred: Optional[str] = None) -> str:
        if preferred:
            return preferred
        if t.kind in {
            cindex.TypeKind.TYPEDEF,
            cindex.TypeKind.RECORD,
            cindex.TypeKind.ENUM,
            cindex.TypeKind.ELABORATED,
        }:
            named = declaration_type_name(t)
            if named:
                return named
        return compact(t.spelling) or canonical_spelling(t) or f"__clang_type_{int(t.kind)}"

    def ensure(self, t: cindex.Type, preferred: Optional[str] = None,
               source: Optional[cindex.Cursor] = None) -> str:
        key = self.key_for(t, preferred)
        if key in self.graph.types or key in self.graph.active:
            return key
        self.graph.active.add(key)
        try:
            self.graph.store_type(key, self.describe(t, key, source))
        finally:
            self.graph.active.discard(key)
        return key

    def base_node(self, t: cindex.Type, key: str,
                  source: Optional[cindex.Cursor]) -> dict[str, Any]:
        return {
            "name": key,
            "clang_kind": str(t.kind).split(".")[-1],
            "spelling": compact(t.spelling),
            "canonical_spelling": canonical_spelling(t),
            "size": sizeof(t),
            "alignment": alignof(t),
            "location": location(source),
            "usr": usr(source),
        }

    def describe(self, t: cindex.Type, key: str,
                 source: Optional[cindex.Cursor]) -> dict[str, Any]:
        node = self.base_node(t, key, source)
        kind = t.kind

        if kind in PRIMITIVES:
            node.update(kind="primitive", primitive=PRIMITIVES[kind])
            return node

        if kind == cindex.TypeKind.TYPEDEF:
            declaration = t.get_declaration()
            public_name = declaration.spelling or key
            underlying = declaration.underlying_typedef_type
            target = self.ensure(underlying)
            if looks_like_handle(public_name) or points_to_declared_handle(underlying):
                node.update(kind="handle", handle_type=public_name, underlying=target)
            else:
                node.update(kind="typedef", target=target)
            self.graph.aliases[public_name] = key
            return node

        if kind == cindex.TypeKind.ELABORATED:
            try:
                target_type = t.get_named_type()
            except Exception:
                target_type = t.get_canonical()
            node.update(kind="elaborated", target=self.ensure(target_type))
            return node

        if kind == cindex.TypeKind.POINTER:
            pointee = t.get_pointee()
            node.update(
                kind="pointer",
                pointee=self.ensure(pointee),
                const=pointee.is_const_qualified(),
                volatile=pointee.is_volatile_qualified(),
                restrict=pointee.is_restrict_qualified(),
            )
            return node

        if kind in {
            cindex.TypeKind.CONSTANTARRAY,
            cindex.TypeKind.INCOMPLETEARRAY,
            cindex.TypeKind.VARIABLEARRAY,
            cindex.TypeKind.DEPENDENTSIZEDARRAY,
        }:
            count = None
            try:
                if t.element_count >= 0:
                    count = t.element_count
            except Exception:
                pass
            node.update(
                kind="array",
                element=self.ensure(t.element_type),
                count=count,
                array_kind=str(kind).split(".")[-1].lower(),
            )
            return node

        if kind in {cindex.TypeKind.FUNCTIONPROTO, cindex.TypeKind.FUNCTIONNOPROTO}:
            try:
                argument_types = list(t.argument_types())
            except Exception:
                argument_types = []
            node.update(
                kind="function_type",
                return_type=self.ensure(t.get_result()),
                arguments=[
                    {"index": i, "type": self.ensure(arg)}
                    for i, arg in enumerate(argument_types)
                ],
                variadic=t.is_function_variadic(),
            )
            return node

        if kind == cindex.TypeKind.RECORD:
            return self.describe_record(t, node)

        if kind == cindex.TypeKind.ENUM:
            return self.describe_enum(t, node)

        canonical = t.get_canonical()
        if canonical.kind != kind or canonical.spelling != t.spelling:
            node.update(kind="canonical_alias", target=self.ensure(canonical))
        else:
            node.update(kind="unsupported_type_form")
        return node

    def describe_record(self, t: cindex.Type, node: dict[str, Any]) -> dict[str, Any]:
        declaration = t.get_declaration()
        if declaration.kind == cindex.CursorKind.UNION_DECL:
            record_kind = "union"
        elif declaration.kind == cindex.CursorKind.CLASS_DECL:
            record_kind = "class"
        else:
            record_kind = "struct"

        fields = []
        for child in declaration.get_children():
            if child.kind != cindex.CursorKind.FIELD_DECL:
                continue
            bit_width = None
            try:
                if child.is_bitfield():
                    bit_width = child.get_bitfield_width()
            except Exception:
                pass
            fields.append({
                "name": child.spelling or anonymous_name(child, "field"),
                "type": self.ensure(child.type),
                "offset_bits": field_offset(child),
                "bit_width": bit_width,
                "location": location(child),
            })

        node.update(
            kind=record_kind,
            complete=bool(fields) or sizeof(t) == 0,
            fields=fields,
            location=location(declaration),
            usr=usr(declaration),
        )
        return node

    def describe_enum(self, t: cindex.Type, node: dict[str, Any]) -> dict[str, Any]:
        declaration = t.get_declaration()
        try:
            integer_type = self.ensure(declaration.enum_type)
        except Exception:
            integer_type = None
        values = []
        for child in declaration.get_children():
            if child.kind == cindex.CursorKind.ENUM_CONSTANT_DECL:
                values.append({
                    "name": child.spelling,
                    "value": child.enum_value,
                    "unsigned_value": child.enum_value & ((1 << 64) - 1),
                    "location": location(child),
                })
        node.update(
            kind="enum",
            integer_type=integer_type,
            values=values,
            complete=bool(values),
            location=location(declaration),
            usr=usr(declaration),
        )
        return node

    def add_function(self, cursor: cindex.Cursor) -> None:
        name = cursor.spelling or cursor.displayname
        if not name:
            return
        args = []
        for index, argument in enumerate(cursor.get_arguments() or []):
            args.append({
                "index": index,
                "name": argument.spelling or f"arg{index}",
                "type": self.ensure(argument.type),
                "location": location(argument),
            })
        self.graph.declarations[name] = {
            "kind": "function",
            "name": name,
            "return_type": self.ensure(cursor.result_type),
            "arguments": args,
            "variadic": cursor.type.is_function_variadic(),
            "prototype_spelling": compact(cursor.type.spelling),
            "location": location(cursor),
            "usr": usr(cursor),
        }

    def visit(self, cursor: cindex.Cursor) -> None:
        if cursor.kind == cindex.CursorKind.TYPEDEF_DECL:
            self.ensure(cursor.type, cursor.spelling, cursor)
        elif cursor.kind in RECORD_CURSORS:
            category = "union" if cursor.kind == cindex.CursorKind.UNION_DECL else "struct"
            self.ensure(cursor.type, decl_name(cursor, category), cursor)
        elif cursor.kind == cindex.CursorKind.ENUM_DECL:
            self.ensure(cursor.type, decl_name(cursor, "enum"), cursor)
        elif cursor.kind in {cindex.CursorKind.FUNCTION_DECL, cindex.CursorKind.FUNCTION_TEMPLATE}:
            self.add_function(cursor)
        elif cursor.kind == cindex.CursorKind.VAR_DECL and cursor.spelling:
            self.graph.declarations[f"__variable__::{cursor.spelling}"] = {
                "kind": "variable",
                "name": cursor.spelling,
                "type": self.ensure(cursor.type),
                "location": location(cursor),
                "usr": usr(cursor),
            }

    def walk(self, cursor: cindex.Cursor) -> None:
        for child in cursor.get_children():
            if self.is_root_declaration(child):
                self.visit(child)
            self.walk(child)


def configure_libclang(path_value: Optional[str]) -> None:
    value = path_value or os.environ.get("LIBCLANG_PATH")
    if not value:
        return
    path = Path(value)
    if path.is_dir():
        cindex.Config.set_library_path(str(path))
    else:
        cindex.Config.set_library_file(str(path))


def diagnostic_json(diagnostic: cindex.Diagnostic) -> dict[str, Any]:
    names = {
        cindex.Diagnostic.Ignored: "ignored",
        cindex.Diagnostic.Note: "note",
        cindex.Diagnostic.Warning: "warning",
        cindex.Diagnostic.Error: "error",
        cindex.Diagnostic.Fatal: "fatal",
    }
    loc = None
    if diagnostic.location and diagnostic.location.file:
        loc = {
            "file": str(Path(diagnostic.location.file.name).resolve()),
            "line": diagnostic.location.line,
            "column": diagnostic.location.column,
        }
    return {
        "severity": names.get(diagnostic.severity, str(diagnostic.severity)),
        "message": diagnostic.spelling,
        "location": loc,
        "category": diagnostic.category_name or None,
    }


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(
        description="Generate a JSON type graph from Windows headers using libclang."
    )
    parser.add_argument("headers", nargs="+", type=Path)
    parser.add_argument("-o", "--output", type=Path, default=Path("type_graph.json"))
    parser.add_argument("-I", "--include", action="append", default=[], metavar="DIR")
    parser.add_argument("-D", "--define", action="append", default=[], metavar="NAME[=VALUE]")
    parser.add_argument("--clang-arg", action="append", default=[])
    parser.add_argument("--target", default="x86_64-pc-windows-msvc")
    parser.add_argument("--language", choices=("c", "c++"), default="c++")
    parser.add_argument("--std", default="c++17")
    parser.add_argument("--libclang")
    parser.add_argument("--include-system-declarations", action="store_true")
    parser.add_argument("--allow-errors", action="store_true")
    parser.add_argument("--pretty", action="store_true")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    headers = [header.resolve() for header in args.headers]
    missing = [str(header) for header in headers if not header.is_file()]
    if missing:
        print("Missing header(s): " + ", ".join(missing), file=sys.stderr)
        return 2

    configure_libclang(args.libclang)

    clang_args = [
        f"--target={args.target}",
        "-x", args.language,
        f"-std={args.std}",
        "-fms-extensions",
        "-fms-compatibility",
        "-Wno-pragma-pack",
        "-Wno-ignored-attributes",
        "-D_WIN64=1",
        "-D_AMD64_=1",
        "-D_M_AMD64=100",
        "-D_M_X64=100",
    ]
    for include in args.include:
        clang_args.extend(["-I", str(Path(include).resolve())])
    clang_args.extend(f"-D{definition}" for definition in args.define)
    clang_args.extend(args.clang_arg)

    wrapper = "\n".join(
        f'#include "{str(header).replace(chr(92), chr(92) * 2).replace(chr(34), chr(92) + chr(34))}"'
        for header in headers
    ) + "\n"

    try:
        index = cindex.Index.create()
        translation_unit = index.parse(
            "__type_graph_wrapper__.cpp",
            args=clang_args,
            unsaved_files=[("__type_graph_wrapper__.cpp", wrapper)],
            options=cindex.TranslationUnit.PARSE_DETAILED_PROCESSING_RECORD,
        )
    except cindex.LibclangError as exc:
        print(f"libclang error: {exc}", file=sys.stderr)
        print("Use --libclang or set LIBCLANG_PATH.", file=sys.stderr)
        return 2
    except cindex.TranslationUnitLoadError as exc:
        print(f"Unable to parse translation unit: {exc}", file=sys.stderr)
        return 2

    graph = Graph()
    graph.diagnostics = [diagnostic_json(d) for d in translation_unit.diagnostics]
    for item in graph.diagnostics:
        prefix = ""
        if item["location"]:
            loc = item["location"]
            prefix = f'{loc["file"]}:{loc["line"]}:{loc["column"]}: '
        print(f'{prefix}{item["severity"]}: {item["message"]}', file=sys.stderr)

    parse_failed = any(d["severity"] in {"error", "fatal"} for d in graph.diagnostics)
    if parse_failed and not args.allow_errors:
        print(
            "Clang reported errors; no JSON written. Add include paths/defines, "
            "or pass --allow-errors to emit a partial graph.",
            file=sys.stderr,
        )
        return 1

    builder = Builder(graph, headers, args.include_system_declarations)
    builder.walk(translation_unit.cursor)

    function_count = sum(
        declaration["kind"] == "function"
        for declaration in graph.declarations.values()
    )
    variable_count = sum(
        declaration["kind"] == "variable"
        for declaration in graph.declarations.values()
    )

    document = {
        "schema_version": SCHEMA_VERSION,
        "generator": "generate_type_graph.py",
        "inputs": {
            "headers": [str(header) for header in headers],
            "clang_arguments": clang_args,
        },
        "statistics": {
            "type_count": len(graph.types),
            "function_count": function_count,
            "variable_count": variable_count,
            "diagnostic_count": len(graph.diagnostics),
        },
        "aliases": dict(sorted(graph.aliases.items())),
        "types": dict(sorted(graph.types.items())),
        "declarations": dict(sorted(graph.declarations.items())),
        "diagnostics": graph.diagnostics,
    }

    args.output.parent.mkdir(parents=True, exist_ok=True)
    with args.output.open("w", encoding="utf-8", newline="\n") as output:
        json.dump(document, output, indent=2 if args.pretty else None, ensure_ascii=False)
        output.write("\n")

    print(
        f"Wrote {len(graph.types)} types, {function_count} functions, and "
        f"{variable_count} variables to {args.output}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
