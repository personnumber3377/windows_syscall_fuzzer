#!/usr/bin/env python3
"""Generate a C++ NtGdi syscall decoder/harness from type_graph.json and
Table metadata in table_windows_ntgdi.c (or .cpp).

Input format
------------
The script expects the JSON emitted by the Clang-AST extractor discussed in
this project.  In particular it uses:

    declarations.records
    declarations.typedefs
    declarations.enums
    resolved.types                 (optional but useful)

The syscall table is parsed directly.  Every ``sizeof(TYPE)`` occurrence is
used as a type root.  The generated C++ contains:

* a bounded little-endian Decoder;
* one global handle pool per discovered handle type;
* recursive field-by-field structure decoders;
* one handler function per syscall table entry;
* a dispatcher whose first two input bytes select the syscall;
* a compact metadata table mapping indices to syscall names.

This generator deliberately does not serialize or restore raw pointer values.
Pointer-shaped arguments are backed by serializer-owned byte buffers when the
table provides a usable byte count; otherwise they are initialized to null.
Generated code should be compiled inside your existing Windows harness, where
``ResolveNtGdiExport`` (or the generated default resolver) can locate syscall
wrappers from win32u.dll/gdi32.dll.
"""
from __future__ import annotations

import argparse
import json
import re
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any, Iterable, Optional

DEFAULT_GRAPH = "type_graph.json"
DEFAULT_TABLE_CANDIDATES = ("table_windows_ntgdi.c", "table_windows_ntgdi.c")
DEFAULT_OUTPUT = "generated_ntgdi_harness.cpp"

# Keep this intentionally broad: Windows handle typedefs are overwhelmingly H*.
HANDLE_NAME_RE = re.compile(
    r"^(?:HANDLE|H[A-Z0-9_]+|DHSURF|DHPDEV|HDEV|HSURF|HLSURF|HUMPD)$"
)
TAG_PREFIX_RE = re.compile(r"^(?:struct|union|enum)\s+")
ARRAY_RE = re.compile(r"^(.*?)\s*\[\s*(\d*)\s*\]\s*$")
SIZEOF_RE = re.compile(r"\bsizeof\s*\(\s*([^()]+?)\s*\)")
INTEGER_RE = re.compile(
    r"^(?:_Bool|bool|char|signed char|unsigned char|short|short int|"
    r"signed short|signed short int|unsigned short|unsigned short int|"
    r"int|signed|signed int|unsigned|unsigned int|long|long int|"
    r"signed long|signed long int|unsigned long|unsigned long int|"
    r"long long|long long int|signed long long|signed long long int|"
    r"unsigned long long|unsigned long long int|__int8|unsigned __int8|"
    r"__int16|unsigned __int16|__int32|unsigned __int32|__int64|"
    r"unsigned __int64)$"
)
FLOAT_RE = re.compile(r"^(?:float|double)$")

INTEGER_INFO: dict[str, tuple[int, bool]] = {
    "_Bool": (1, False), "bool": (1, False),
    "char": (1, True), "signed char": (1, True), "unsigned char": (1, False),
    "short": (2, True), "short int": (2, True),
    "signed short": (2, True), "signed short int": (2, True),
    "unsigned short": (2, False), "unsigned short int": (2, False),
    "int": (4, True), "signed": (4, True), "signed int": (4, True),
    "unsigned": (4, False), "unsigned int": (4, False),
    "long": (4, True), "long int": (4, True),
    "signed long": (4, True), "signed long int": (4, True),
    "unsigned long": (4, False), "unsigned long int": (4, False),
    "long long": (8, True), "long long int": (8, True),
    "signed long long": (8, True), "signed long long int": (8, True),
    "unsigned long long": (8, False), "unsigned long long int": (8, False),
    "__int8": (1, True), "unsigned __int8": (1, False),
    "__int16": (2, True), "unsigned __int16": (2, False),
    "__int32": (4, True), "unsigned __int32": (4, False),
    "__int64": (8, True), "unsigned __int64": (8, False),
}

RETURN_TYPE_MAP = {
    "DRSYS_TYPE_VOID": "void",
    "DRSYS_TYPE_HANDLE": "HANDLE",
    "DRSYS_TYPE_POINTER": "void *",
    "DRSYS_TYPE_BOOL": "BOOL",
    "SYSARG_TYPE_BOOL32": "BOOL",
    "SYSARG_TYPE_UINT32": "uint32_t",
    "SYSARG_TYPE_SINT32": "int32_t",
    "DRSYS_TYPE_UNSIGNED_INT": "uintptr_t",
    "DRSYS_TYPE_SIGNED_INT": "intptr_t",
    "RNTST": "NTSTATUS",
}


def clean_type(value: str) -> str:
    value = re.sub(r"\b(?:const|volatile|restrict|__restrict|__restrict__)\b", " ", value)
    value = re.sub(r"\s+", " ", value).strip()
    value = value.replace(" *", "*").replace("*", " * ")
    return re.sub(r"\s+", " ", value).strip()


def bare_type(value: str) -> str:
    return TAG_PREFIX_RE.sub("", clean_type(value)).strip()


def cpp_identifier(value: str) -> str:
    value = re.sub(r"[^A-Za-z0-9_]", "_", value)
    if not value or value[0].isdigit():
        value = "_" + value
    return value


def strip_comments_preserve_layout(text: str) -> str:
    """Remove comments while preserving newlines and string literals."""
    out: list[str] = []
    i = 0
    state = "code"
    while i < len(text):
        ch = text[i]
        nxt = text[i + 1] if i + 1 < len(text) else ""
        if state == "code":
            if ch == "/" and nxt == "*":
                out.extend((" ", " "))
                i += 2
                state = "block"
            elif ch == "/" and nxt == "/":
                out.extend((" ", " "))
                i += 2
                state = "line"
            elif ch == '"':
                out.append(ch); i += 1; state = "string"
            elif ch == "'":
                out.append(ch); i += 1; state = "char"
            else:
                out.append(ch); i += 1
        elif state == "block":
            if ch == "*" and nxt == "/":
                out.extend((" ", " ")); i += 2; state = "code"
            else:
                out.append("\n" if ch == "\n" else " "); i += 1
        elif state == "line":
            if ch == "\n":
                out.append("\n"); state = "code"
            else:
                out.append(" ")
            i += 1
        else:  # string or char
            out.append(ch)
            if ch == "\\" and i + 1 < len(text):
                out.append(text[i + 1]); i += 2
            else:
                i += 1
                if (state == "string" and ch == '"') or (state == "char" and ch == "'"):
                    state = "code"
    return "".join(out)


def split_top_level(text: str, delimiter: str = ",") -> list[str]:
    parts: list[str] = []
    start = 0
    paren = brace = bracket = 0
    in_string = False
    escape = False
    for i, ch in enumerate(text):
        if in_string:
            if escape:
                escape = False
            elif ch == "\\":
                escape = True
            elif ch == '"':
                in_string = False
            continue
        if ch == '"': in_string = True
        elif ch == "(": paren += 1
        elif ch == ")": paren = max(0, paren - 1)
        elif ch == "{": brace += 1
        elif ch == "}": brace = max(0, brace - 1)
        elif ch == "[": bracket += 1
        elif ch == "]": bracket = max(0, bracket - 1)
        elif ch == delimiter and paren == brace == bracket == 0:
            parts.append(text[start:i].strip()); start = i + 1
    parts.append(text[start:].strip())
    return parts


def find_matching(text: str, start: int, opening: str, closing: str) -> int:
    depth = 0
    in_string = False
    escape = False
    for i in range(start, len(text)):
        ch = text[i]
        if in_string:
            if escape: escape = False
            elif ch == "\\": escape = True
            elif ch == '"': in_string = False
            continue
        if ch == '"': in_string = True
        elif ch == opening: depth += 1
        elif ch == closing:
            depth -= 1
            if depth == 0: return i
    raise ValueError(f"unbalanced {opening}{closing} starting at byte {start}")


@dataclass
class ArgSpec:
    index: int
    size_expr: str
    flags: str
    drsys_type: str
    extra: list[str] = field(default_factory=list)
    sizeof_types: list[str] = field(default_factory=list)

    @property
    def inlined(self) -> bool:
        return "SYSARG_INLINED" in self.flags

    @property
    def readable(self) -> bool:
        return bool(re.search(r"(?:^|\|)R(?:\||$)", self.flags))

    @property
    def writable(self) -> bool:
        return bool(re.search(r"(?:^|\|)W(?:\||$)", self.flags))


@dataclass
class SyscallSpec:
    index: int
    name: str
    status: str
    return_token: str
    declared_argc: int
    args: list[ArgSpec]
    source_offset: int


class TableParser:
    ENTRY_RE = re.compile(
        r'\{\s*\{\s*0\s*,\s*0\s*\}\s*,\s*"(?P<name>NtGdi[^"]+)"'
    )

    def parse(self, path: Path) -> list[SyscallSpec]:
        original = path.read_text(encoding="utf-8", errors="replace")
        text = strip_comments_preserve_layout(original)
        specs: list[SyscallSpec] = []
        pos = 0
        while True:
            match = self.ENTRY_RE.search(text, pos)
            if not match: break
            start = match.start()
            end = find_matching(text, start, "{", "}")
            entry = text[start:end + 1]
            try:
                spec = self._parse_entry(entry, len(specs), start)
            except Exception as exc:
                print(f"warning: skipped malformed entry near byte {start}: {exc}", file=sys.stderr)
            else:
                specs.append(spec)
            pos = end + 1
        return specs

    def _parse_entry(self, entry: str, index: int, source_offset: int) -> SyscallSpec:
        name_match = re.search(r'"(NtGdi[^"]+)"', entry)
        if not name_match: raise ValueError("missing syscall name")
        name = name_match.group(1)

        # Remove the outer braces and split only the fixed prefix.  The argument
        # block remains one top-level item because split_top_level tracks braces.
        content = entry.strip()[1:-1].strip()
        parts = split_top_level(content)
        if len(parts) < 5:
            raise ValueError(f"entry has only {len(parts)} top-level fields")
        status = parts[2].strip()
        return_token = parts[3].strip()
        argc_text = parts[4].strip()
        try:
            argc = int(argc_text, 0)
        except ValueError:
            # The table has a tail of explicitly UNKNOWN entries with no known
            # argument count.  Preserve them as zero-argument unresolved stubs
            # instead of silently dropping their syscall indices.
            argc = 0

        args: list[ArgSpec] = []
        # The sixth top-level initializer field, when present, is the argument
        # descriptor block.  Using it directly avoids confusing the leading
        # {{0,0}} syscall-number initializer with argument zero.
        if len(parts) >= 6 and parts[5].strip().startswith("{"):
            raw_block = parts[5].strip()
            block = raw_block[1:-1] if raw_block.endswith("}") else raw_block[1:]
            cursor = 0
            while True:
                m = re.search(r"\{\s*([-+]?\d+)\s*,", block[cursor:])
                if not m: break
                astart = cursor + m.start()
                aend = find_matching(block, astart, "{", "}")
                descriptor = block[astart + 1:aend]
                fields = split_top_level(descriptor)
                if len(fields) >= 2:
                    try:
                        arg_index = int(fields[0], 0)
                    except ValueError:
                        cursor = aend + 1
                        continue
                    size_expr = fields[1].strip()
                    flags = fields[2].strip() if len(fields) >= 3 else ""
                    drsys_type = fields[3].strip() if len(fields) >= 4 else "DRSYS_TYPE_UNKNOWN"
                    extra = [x.strip() for x in fields[4:] if x.strip()]
                    sizeof_types = [clean_type(x) for x in SIZEOF_RE.findall(descriptor)]
                    args.append(ArgSpec(arg_index, size_expr, flags, drsys_type, extra, sizeof_types))
                cursor = aend + 1

        # Some tables omit descriptors for special-cased arguments.  Keep the
        # real descriptor list but fill holes later during generation.
        return SyscallSpec(index, name, status, return_token, argc, args, source_offset)


class TypeGraph:
    def __init__(self, data: dict[str, Any]):
        decl = data.get("declarations", {})
        self.records: dict[str, dict[str, Any]] = decl.get("records", {})
        self.typedefs: dict[str, dict[str, Any]] = decl.get("typedefs", {})
        self.enums: dict[str, dict[str, Any]] = decl.get("enums", {})
        self.resolved_types: dict[str, dict[str, Any]] = data.get("resolved", {}).get("types", {})
        self.aliases: dict[str, list[str]] = {}
        for name, td in self.typedefs.items():
            target = bare_type(td.get("target", ""))
            if target in self.records:
                self.aliases.setdefault(target, []).append(name)

    def typedef_target(self, name: str) -> Optional[str]:
        td = self.typedefs.get(name)
        if not td: return None
        return clean_type(td.get("desugared_target") or td.get("target") or "") or None

    def classify(self, spelling: str, seen: Optional[set[str]] = None) -> dict[str, Any]:
        t = clean_type(spelling)
        seen = set() if seen is None else set(seen)
        if t in seen:
            return {"kind": "recursive", "spelling": t}
        seen.add(t)

        arr = ARRAY_RE.match(t)
        if arr:
            return {
                "kind": "array",
                "spelling": t,
                "element": self.classify(arr.group(1), seen),
                "count": int(arr.group(2)) if arr.group(2) else None,
            }
        if "(" in t and "*" in t:
            return {"kind": "function_pointer", "spelling": t}
        if "*" in t:
            return {"kind": "pointer", "spelling": t, "pointee": clean_type(t.replace("*", " "))}

        bare = bare_type(t)
        if HANDLE_NAME_RE.match(bare):
            return {"kind": "handle", "spelling": t, "handle_type": bare}
        if INTEGER_RE.match(t):
            size, signed = INTEGER_INFO[t]
            return {"kind": "integer", "spelling": t, "size": size, "signed": signed}
        if FLOAT_RE.match(t):
            return {"kind": "float", "spelling": t, "size": 4 if t == "float" else 8}
        if bare == "void": return {"kind": "void", "spelling": t}
        if t in self.typedefs:
            target = self.typedef_target(t)
            if target:
                return {"kind": "typedef", "spelling": t, "target": target,
                        "resolved": self.classify(target, seen)}
        if bare in self.records:
            return {"kind": self.records[bare].get("kind", "struct"), "spelling": t,
                    "name": bare, "record": self.records[bare]}
        if bare in self.enums:
            return {"kind": "enum", "spelling": t, "name": bare}

        # Use the extractor's resolved view as a final hint.
        resolved = self.resolved_types.get(t) or self.resolved_types.get(f"struct {bare}")
        if isinstance(resolved, dict):
            return resolved
        return {"kind": "unknown", "spelling": t}

    def canonical_record(self, spelling: str) -> Optional[str]:
        info = self.classify(spelling)
        while info.get("kind") == "typedef":
            info = info.get("resolved", {})
        if info.get("kind") in {"struct", "union"}:
            return info.get("name") or bare_type(info.get("spelling", ""))
        return None

    def canonical_handle(self, spelling: str) -> Optional[str]:
        info = self.classify(spelling)
        while info.get("kind") == "typedef":
            # Preserve an H* typedef spelling as the useful pool type.
            if HANDLE_NAME_RE.match(bare_type(info.get("spelling", ""))):
                return bare_type(info["spelling"])
            info = info.get("resolved", {})
        if info.get("kind") == "handle": return info.get("handle_type")
        return None


class Reachability:
    def __init__(self, graph: TypeGraph):
        self.graph = graph
        self.typedefs: set[str] = set()
        self.records: set[str] = set()
        self.enums: set[str] = set()
        self.handles: set[str] = set()
        self.unknown: set[str] = set()

    def add(self, spelling: str, active: Optional[set[str]] = None) -> None:
        t = clean_type(spelling)
        active = set() if active is None else set(active)
        if not t or t in active: return
        active.add(t)
        info = self.graph.classify(t)
        kind = info.get("kind")
        if kind == "array":
            self.add(info.get("element", {}).get("spelling", ""), active)
        elif kind == "typedef":
            self.typedefs.add(t)
            handle = self.graph.canonical_handle(t)
            if handle: self.handles.add(handle)
            self.add(info.get("target", ""), active)
        elif kind in {"struct", "union"}:
            name = info.get("name") or bare_type(t)
            if name in self.records: return
            self.records.add(name)
            record = self.graph.records.get(name, {})
            for field_spec in record.get("fields", []):
                self.add(field_spec.get("type", ""), active)
        elif kind == "enum":
            self.enums.add(info.get("name") or bare_type(t))
        elif kind == "handle":
            self.handles.add(info.get("handle_type") or bare_type(t))
        elif kind in {"unknown", "unsupported"}:
            self.unknown.add(t)


class CppGenerator:
    def __init__(self, graph: TypeGraph, syscalls: list[SyscallSpec], max_buffer: int):
        self.graph = graph
        self.syscalls = syscalls
        self.max_buffer = max_buffer
        self.reach = Reachability(graph)
        self.warnings: list[str] = []
        self._collect_roots()

    def _collect_roots(self) -> None:
        for syscall in self.syscalls:
            for arg in syscall.args:
                for t in arg.sizeof_types:
                    self.reach.add(t)
                inferred = self.infer_arg_type(arg)
                if inferred: self.reach.add(inferred)

    def infer_arg_type(self, arg: ArgSpec) -> Optional[str]:
        # The first sizeof is usually the actual pointee/value type.  Additional
        # sizeof expressions typically describe array elements.
        if arg.sizeof_types:
            return arg.sizeof_types[0]
        token_map = {
            "DRSYS_TYPE_HANDLE": "HANDLE",
            "DRSYS_TYPE_POINTER": "PVOID",
            "DRSYS_TYPE_BOOL": "BOOL",
            "DRSYS_TYPE_UNSIGNED_INT": "ULONG_PTR",
            "DRSYS_TYPE_SIGNED_INT": "LONG_PTR",
            "SYSARG_TYPE_BOOL32": "BOOL",
            "SYSARG_TYPE_UINT32": "ULONG",
            "SYSARG_TYPE_SINT32": "LONG",
        }
        return token_map.get(arg.drsys_type)

    def arg_by_index(self, syscall: SyscallSpec) -> dict[int, ArgSpec]:
        # Prefer the richest descriptor when an index occurs multiple times.
        result: dict[int, ArgSpec] = {}
        for arg in syscall.args:
            old = result.get(arg.index)
            if old is None or len(arg.sizeof_types) > len(old.sizeof_types):
                result[arg.index] = arg
        return result

    def emit(self) -> str:
        chunks = [self.emit_preamble(), self.emit_handle_pools(), self.emit_struct_decoders(),
                  self.emit_syscall_metadata(), self.emit_syscall_handlers(), self.emit_dispatcher()]
        return "\n\n".join(x.rstrip() for x in chunks if x.strip()) + "\n"

    def emit_preamble(self) -> str:
        return f'''// Auto-generated by generate_ntgdi_harness.py.  Do not edit manually.
// Input format: [uint16 syscall_index little-endian][serialized arguments...]
// Raw pointer values are never trusted.  Decoder-owned buffers are capped at
// {self.max_buffer} bytes.

#ifndef NOMINMAX
# define NOMINMAX
#endif
#ifndef WIN32_LEAN_AND_MEAN
# define WIN32_LEAN_AND_MEAN
#endif
#include <windows.h>
#include <winternl.h>
#include <wingdi.h>
#define NT_BUILD_ENVIRONMENT 1
#include <d3dnthal.h>
#include <winddi.h>
#include <prntfont.h>
#include <ntgdi.h>
#include <dxgiformat.h>

#include <algorithm>
#include <array>
#include <cstddef>
#include <cstdint>
#include <cstring>
#include <limits>
#include <memory>
#include <type_traits>
#include <utility>
#include <vector>

namespace generated_ntgdi {{

static constexpr size_t kMaxGeneratedBuffer = {self.max_buffer}u;

class Decoder {{
public:
    Decoder(const uint8_t* data, size_t size) : cur_(data), end_(data + size) {{}}

    size_t remaining() const {{ return static_cast<size_t>(end_ - cur_); }}
    bool ok() const {{ return ok_; }}

    template <typename T>
    bool ReadScalar(T& out) {{
        static_assert(std::is_trivially_copyable_v<T>);
        if (remaining() < sizeof(T)) {{
            std::memset(&out, 0, sizeof(out));
            ok_ = false;
            return false;
        }}
        std::memcpy(&out, cur_, sizeof(T));
        cur_ += sizeof(T);
        return true;
    }}

    uint8_t ReadU8() {{ uint8_t v = 0; ReadScalar(v); return v; }}
    uint16_t ReadU16() {{ uint16_t v = 0; ReadScalar(v); return v; }}
    uint32_t ReadU32() {{ uint32_t v = 0; ReadScalar(v); return v; }}
    uint64_t ReadU64() {{ uint64_t v = 0; ReadScalar(v); return v; }}

    size_t ReadBoundedLength(size_t cap = kMaxGeneratedBuffer) {{
        const size_t requested = static_cast<size_t>(ReadU32());
        return std::min({{requested, cap, remaining()}});
    }}

    bool ReadBytes(void* destination, size_t size) {{
        if (remaining() < size) {{
            if (destination && size) std::memset(destination, 0, size);
            ok_ = false;
            return false;
        }}
        if (size) std::memcpy(destination, cur_, size);
        cur_ += size;
        return true;
    }}

private:
    const uint8_t* cur_;
    const uint8_t* end_;
    bool ok_ = true;
}};

struct OwnedBytes {{
    std::vector<uint8_t> bytes;
    void* data() {{ return bytes.empty() ? nullptr : bytes.data(); }}
    const void* data() const {{ return bytes.empty() ? nullptr : bytes.data(); }}
}};

static OwnedBytes DecodeOwnedBytes(Decoder& d, size_t maximum = kMaxGeneratedBuffer) {{
    OwnedBytes result;
    const size_t length = d.ReadBoundedLength(maximum);
    result.bytes.resize(length);
    d.ReadBytes(result.bytes.data(), result.bytes.size());
    return result;
}}

static FARPROC ResolveNtGdiExport(const char* name) {{
    static HMODULE win32u = ::LoadLibraryW(L"win32u.dll");
    static HMODULE gdi32 = ::LoadLibraryW(L"gdi32.dll");
    FARPROC proc = win32u ? ::GetProcAddress(win32u, name) : nullptr;
    if (!proc && gdi32) proc = ::GetProcAddress(gdi32, name);
    return proc;
}}
'''

    def emit_handle_pools(self) -> str:
        handles = sorted(self.reach.handles | {"HANDLE"})
        lines = ["// Serialized handles are 16-bit indices into these pools."]
        for handle in handles:
            ident = cpp_identifier(handle)
            lines.append(f"static std::vector<{handle}> g_handles_{ident};")
        lines.append("")
        lines.append("template <typename T>")
        lines.append("static T PickHandle(const std::vector<T>& pool, Decoder& d) {")
        lines.append("    if (pool.empty()) return static_cast<T>(nullptr);")
        lines.append("    const size_t index = static_cast<size_t>(d.ReadU16()) % pool.size();")
        lines.append("    return pool[index];")
        lines.append("}")
        lines.append("")
        lines.append("template <typename T>")
        lines.append("static void RememberHandle(std::vector<T>& pool, T value) {")
        lines.append("    if (value && std::find(pool.begin(), pool.end(), value) == pool.end())")
        lines.append("        pool.push_back(value);")
        lines.append("}")
        return "\n".join(lines)

    def decode_expr(self, ctype: str, target: str, decoder: str = "d", indent: str = "    ") -> list[str]:
        info = self.graph.classify(ctype)
        kind = info.get("kind")
        if kind == "typedef":
            handle = self.graph.canonical_handle(ctype)
            if handle:
                return [f"{indent}{target} = PickHandle(g_handles_{cpp_identifier(handle)}, {decoder});"]
            resolved = info.get("resolved", {})
            rkind = resolved.get("kind")
            if rkind in {"integer", "float", "enum"}:
                return [f"{indent}{decoder}.ReadScalar({target});"]
            record = self.graph.canonical_record(ctype)
            if record:
                return [f"{indent}Decode_{cpp_identifier(record)}({decoder}, {target});"]
            if rkind == "pointer":
                return [f"{indent}{target} = nullptr; // raw pointer intentionally not deserialized"]
            return [f"{indent}{decoder}.ReadScalar({target}); // typedef fallback"]
        if kind == "handle":
            handle = info.get("handle_type") or bare_type(ctype)
            return [f"{indent}{target} = PickHandle(g_handles_{cpp_identifier(handle)}, {decoder});"]
        if kind in {"integer", "float", "enum"}:
            return [f"{indent}{decoder}.ReadScalar({target});"]
        if kind == "array":
            count = info.get("count")
            if count is None:
                return [f"{indent}// Flexible array {target} requires a field-specific policy."]
            lines = [f"{indent}for (size_t i = 0; i < {count}u; ++i) {{"]
            lines += self.decode_expr(info["element"].get("spelling", "uint8_t"), f"{target}[i]", decoder, indent + "    ")
            lines.append(f"{indent}}}")
            return lines
        if kind in {"struct", "union"}:
            name = info.get("name") or bare_type(ctype)
            return [f"{indent}Decode_{cpp_identifier(name)}({decoder}, {target});"]
        if kind in {"pointer", "function_pointer"}:
            return [f"{indent}{target} = nullptr; // pointer/callback requires an explicit policy"]
        return [f"{indent}std::memset(&{target}, 0, sizeof({target})); // unknown type: {ctype}"]

    def record_dependencies(self, name: str) -> set[str]:
        deps: set[str] = set()
        record = self.graph.records.get(name, {})
        for field_spec in record.get("fields", []):
            dep = self.graph.canonical_record(field_spec.get("type", ""))
            if dep and dep != name and dep in self.reach.records:
                deps.add(dep)
        return deps

    def ordered_records(self) -> list[str]:
        remaining = set(self.reach.records)
        result: list[str] = []
        while remaining:
            progressed = False
            for name in sorted(remaining):
                if self.record_dependencies(name).issubset(set(result)):
                    result.append(name); remaining.remove(name); progressed = True; break
            if not progressed:
                # Pointer-recursive or otherwise cyclic graph: deterministic fallback.
                result.extend(sorted(remaining)); break
        return result

    def emit_struct_decoders(self) -> str:
        lines = ["// Reachable native-record decoders."]
        ordered = self.ordered_records()
        for name in ordered:
            lines.append(f"static void Decode_{cpp_identifier(name)}(Decoder& d, {name}& out);")
        lines.append("")
        for name in ordered:
            record = self.graph.records.get(name, {})
            lines.append(f"static void Decode_{cpp_identifier(name)}(Decoder& d, {name}& out) {{")
            lines.append("    std::memset(&out, 0, sizeof(out));")
            if record.get("kind") == "union":
                lines.append("    // Union policy: decode the first declared member only.")
            fields = record.get("fields", [])
            if record.get("kind") == "union" and fields:
                fields = fields[:1]
            for field_spec in fields:
                fname = field_spec.get("name")
                ftype = field_spec.get("type", "")
                if not fname: continue
                if field_spec.get("bitfield"):
                    lines.append(f"    // Bitfield {fname} is left zero; Clang layout metadata is required.")
                    continue
                # SURFOBJ's storage pointer needs the syscall handler to own the
                # allocation.  Leave it null here rather than creating a dangling buffer.
                if name in {"SURFOBJ", "_SURFOBJ"} and fname in {"pvBits", "pvScan0"}:
                    lines.append(f"    out.{fname} = nullptr; // assigned by syscall handler when applicable")
                    continue
                lines.extend(self.decode_expr(ftype, f"out.{fname}"))
            lines.append("}")
            lines.append("")
        return "\n".join(lines)

    def emit_syscall_metadata(self) -> str:
        lines = ["struct SyscallMetadata { uint16_t index; const char* name; uint16_t argument_count; };",
                 "static constexpr SyscallMetadata kSyscalls[] = {"]
        for syscall in self.syscalls:
            lines.append(f'    {{{syscall.index}u, "{syscall.name}", {syscall.declared_argc}u}},')
        lines.append("};")
        return "\n".join(lines)

    def return_cpp_type(self, token: str) -> str:
        return RETURN_TYPE_MAP.get(token.strip(), "uintptr_t")

    def emit_argument_setup(self, syscall: SyscallSpec, index: int, arg: Optional[ArgSpec]) -> tuple[list[str], str, list[str]]:
        """Return declarations/setup, call expression, and post-call actions."""
        prefix = f"arg{index}"
        if arg is None:
            return ([f"    uintptr_t {prefix} = 0; // table marks this argument special-cased"], prefix, [])
        ctype = self.infer_arg_type(arg) or "uintptr_t"
        info = self.graph.classify(ctype)
        handle = self.graph.canonical_handle(ctype)
        record = self.graph.canonical_record(ctype)
        post: list[str] = []

        if arg.inlined:
            if handle:
                return ([f"    {ctype} {prefix} = PickHandle(g_handles_{cpp_identifier(handle)}, d);"], prefix, post)
            if record:
                setup = [f"    {ctype} {prefix}{{}};"] + self.decode_expr(ctype, prefix)
                return (setup, prefix, post)
            if info.get("kind") == "pointer":
                setup = [f"    OwnedBytes {prefix}_bytes = DecodeOwnedBytes(d);",
                         f"    {ctype} {prefix} = reinterpret_cast<{ctype}>({prefix}_bytes.data());"]
                return (setup, prefix, post)
            setup = [f"    {ctype} {prefix}{{}};"] + self.decode_expr(ctype, prefix)
            return (setup, prefix, post)

        # Non-inlined handle means a pointer to handle storage.
        if handle:
            setup = [f"    {ctype} {prefix}{{}};"]
            if arg.readable:
                setup.append(f"    {prefix} = PickHandle(g_handles_{cpp_identifier(handle)}, d);")
            if arg.writable:
                post.append(f"    RememberHandle(g_handles_{cpp_identifier(handle)}, {prefix});")
            return (setup, f"&{prefix}", post)

        if record:
            setup = [f"    {ctype} {prefix}{{}};"]
            if arg.readable:
                setup += self.decode_expr(ctype, prefix)
            # Special ownership for SURFOBJ backing storage.
            if record in {"SURFOBJ", "_SURFOBJ"} and arg.readable:
                setup += [f"    OwnedBytes {prefix}_surface_bytes = DecodeOwnedBytes(d);",
                          f"    {prefix}.cjBits = static_cast<ULONG>({prefix}_surface_bytes.bytes.size());",
                          f"    {prefix}.pvBits = {prefix}_surface_bytes.data();",
                          f"    {prefix}.pvScan0 = {prefix}_surface_bytes.data();"]
            return (setup, f"&{prefix}", post)

        # Scalar output/input-output arguments are represented by native storage.
        if info.get("kind") in {"integer", "float", "enum", "typedef"}:
            setup = [f"    {ctype} {prefix}{{}};"]
            if arg.readable: setup += self.decode_expr(ctype, prefix)
            return (setup, f"&{prefix}", post)

        # Unknown variable-sized memory: decode an owned bounded byte region.
        setup = [f"    OwnedBytes {prefix}_bytes = DecodeOwnedBytes(d);"]
        return (setup, f"{prefix}_bytes.data()", post)

    def emit_syscall_handlers(self) -> str:
        lines: list[str] = ["// One generated handler per syscall table entry."]
        for syscall in self.syscalls:
            ret = self.return_cpp_type(syscall.return_token)
            lines.append(f"static void Handle_{cpp_identifier(syscall.name)}(Decoder& d) {{")
            by_index = self.arg_by_index(syscall)
            call_args: list[str] = []
            post: list[str] = []
            for i in range(syscall.declared_argc):
                setup, expression, after = self.emit_argument_setup(syscall, i, by_index.get(i))
                lines.extend(setup)
                call_args.append(expression)
                post.extend(after)
            parameter_types: list[str] = []
            for i in range(syscall.declared_argc):
                parameter_types.append(self.call_parameter_type(by_index.get(i)))
            typedef_args = ", ".join(parameter_types) if parameter_types else "void"
            lines.append(f"    using Fn = {ret} (NTAPI*)({typedef_args});")
            lines.append(f"    static Fn fn = reinterpret_cast<Fn>(ResolveNtGdiExport(\"{syscall.name}\"));")
            lines.append("    if (!fn || !d.ok()) return;")
            call = f"fn({', '.join(call_args)})" if call_args else "fn()"
            if ret == "void":
                lines.append(f"    {call};")
            else:
                lines.append(f"    {ret} result = {call};")
                if ret == "HANDLE":
                    lines.append("    RememberHandle(g_handles_HANDLE, result);")
                else:
                    lines.append("    (void)result;")
            lines.extend(post)
            lines.append("}")
            lines.append("")
        return "\n".join(lines)

    def call_parameter_type(self, arg: Optional[ArgSpec]) -> str:
        if arg is None:
            return "uintptr_t"
        ctype = self.infer_arg_type(arg) or "uintptr_t"
        info = self.graph.classify(ctype)
        if arg.inlined:
            return ctype
        if self.graph.canonical_handle(ctype) or self.graph.canonical_record(ctype):
            return f"{ctype} *"
        if info.get("kind") in {"integer", "float", "enum", "typedef"}:
            return f"{ctype} *"
        return "void *"

    def emit_dispatcher(self) -> str:
        lines = ["bool DispatchGeneratedNtGdi(const uint8_t* data, size_t size) {",
                 "    if (!data || size < sizeof(uint16_t)) return false;",
                 "    Decoder d(data, size);",
                 "    const uint16_t syscall_index = d.ReadU16();",
                 "    switch (syscall_index) {"]
        for syscall in self.syscalls:
            lines.append(f"    case {syscall.index}u:")
            lines.append(f"        Handle_{cpp_identifier(syscall.name)}(d);")
            lines.append("        return d.ok();")
        lines += ["    default:", "        return false;", "    }", "}", "", "} // namespace generated_ntgdi"]
        return "\n".join(lines)


def choose_table(explicit: Optional[Path]) -> Path:
    if explicit:
        return explicit
    for candidate in DEFAULT_TABLE_CANDIDATES:
        path = Path.cwd() / candidate
        if path.exists(): return path
    raise FileNotFoundError(
        "neither table_windows_ntgdi.c nor table_windows_ntgdi.cpp exists in the current directory"
    )


def parse_args() -> argparse.Namespace:
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--graph", type=Path, default=Path(__file__).resolve().parent / DEFAULT_GRAPH,
                        help="type graph JSON (default: type_graph.json beside this script)")
    parser.add_argument("--table", type=Path, default=None,
                        help="syscall table (default: table_windows_ntgdi.c/.cpp in current directory)")
    parser.add_argument("-o", "--output", type=Path, default=Path(DEFAULT_OUTPUT))
    parser.add_argument("--max-buffer", type=int, default=1 << 20,
                        help="maximum bytes allocated for any decoded buffer")
    parser.add_argument("--manifest", type=Path, default=None,
                        help="optional JSON manifest describing parsed syscalls and roots")
    return parser.parse_args()


def main() -> int:
    args = parse_args()
    try:
        graph_data = json.loads(args.graph.read_text(encoding="utf-8"))
        table_path = choose_table(args.table)
        syscalls = TableParser().parse(table_path)
        if not syscalls:
            raise RuntimeError(f"no NtGdi syscall entries found in {table_path}")
        generator = CppGenerator(TypeGraph(graph_data), syscalls, args.max_buffer)
        output = generator.emit()
        args.output.write_text(output, encoding="utf-8")

        if args.manifest:
            manifest = {
                "graph": str(args.graph),
                "table": str(table_path),
                "output": str(args.output),
                "syscall_count": len(syscalls),
                "roots": sorted({t for s in syscalls for a in s.args for t in a.sizeof_types}),
                "reachable": {
                    "typedefs": sorted(generator.reach.typedefs),
                    "records": sorted(generator.reach.records),
                    "enums": sorted(generator.reach.enums),
                    "handles": sorted(generator.reach.handles),
                    "unknown": sorted(generator.reach.unknown),
                },
                "syscalls": [
                    {
                        "index": s.index,
                        "name": s.name,
                        "return_token": s.return_token,
                        "declared_argc": s.declared_argc,
                        "arguments": [
                            {
                                "index": a.index,
                                "size_expr": a.size_expr,
                                "flags": a.flags,
                                "drsys_type": a.drsys_type,
                                "sizeof_types": a.sizeof_types,
                            }
                            for a in s.args
                        ],
                    }
                    for s in syscalls
                ],
            }
            args.manifest.write_text(json.dumps(manifest, indent=2) + "\n", encoding="utf-8")

        print(f"generated {args.output} with {len(syscalls)} syscall handlers", file=sys.stderr)
        print(f"reachable records: {len(generator.reach.records)}; handles: {len(generator.reach.handles)}", file=sys.stderr)
        if generator.reach.unknown:
            print(f"warning: {len(generator.reach.unknown)} unresolved root/field types", file=sys.stderr)
        return 0
    except (OSError, ValueError, RuntimeError, json.JSONDecodeError) as exc:
        print(f"error: {exc}", file=sys.stderr)
        return 1


if __name__ == "__main__":
    raise SystemExit(main())
