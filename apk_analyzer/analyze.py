#!/usr/bin/env python3
"""
APK Elite Analyzer v3.0 - Monster-Grade APK Security Scanner

Advanced DEX bytecode disassembly, Dalvik opcode parsing, vulnerability chain
building, taint analysis, cross-reference engine, exploit suggestion, auto Frida
hook generation, component attack surface mapping, and bug-bounty-ready reporting.

Pure Python implementation - no external tools (apktool/jadx) required.

Usage:
    python analyze.py <path-to.apk> [-o output_dir] [--format json|txt|html|all]

Output:
    <output_dir>/
    ├── report.json
    ├── report.txt
    ├── report.html
    ├── frida_hooks/
    │   ├── ssl_bypass.js
    │   ├── crypto_hook.js
    │   ├── root_detection_bypass.js
    │   └── ...
    ├── adb_tests.sh
    ├── attack_chains.txt
    └── exploit_notes.md
"""

from __future__ import annotations

import argparse
import hashlib
import html as html_module
import json
import os
import re
import struct
import sys
import time
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Iterator, Optional, Dict, List, Set, Tuple

# ---------------------------------------------------------------------------
# Color output (optional colorama)
# ---------------------------------------------------------------------------
try:
    from colorama import Fore, Style, init as _color_init
    _color_init()
    C_RED = Fore.RED
    C_YEL = Fore.YELLOW
    C_GRN = Fore.GREEN
    C_CYN = Fore.CYAN
    C_MAG = Fore.MAGENTA
    C_WHT = Fore.WHITE
    C_RST = Style.RESET_ALL
    C_BLD = Style.BRIGHT
except Exception:
    C_RED = C_YEL = C_GRN = C_CYN = C_MAG = C_WHT = C_RST = C_BLD = ""

VERSION = "3.0.0"

# ===========================================================================
# DEX FILE FORMAT CONSTANTS
# ===========================================================================
DEX_MAGIC = b"dex\n"
DEX_HEADER_SIZE = 0x70

# Dalvik Opcodes
OP_NOP = 0x00
OP_MOVE_RESULT = 0x0a
OP_MOVE_RESULT_WIDE = 0x0b
OP_MOVE_RESULT_OBJECT = 0x0c
OP_RETURN_VOID = 0x0e
OP_RETURN = 0x0f
OP_CONST_4 = 0x12
OP_CONST_16 = 0x13
OP_CONST = 0x14
OP_CONST_HIGH16 = 0x15
OP_CONST_STRING = 0x1a
OP_CONST_STRING_JUMBO = 0x1b
OP_CONST_CLASS = 0x1c
OP_NEW_INSTANCE = 0x22
OP_NEW_ARRAY = 0x23
OP_IGET = 0x52
OP_IGET_WIDE = 0x53
OP_IGET_OBJECT = 0x54
OP_IGET_BOOLEAN = 0x55
OP_IGET_BYTE = 0x56
OP_IGET_CHAR = 0x57
OP_IGET_SHORT = 0x58
OP_IPUT = 0x59
OP_IPUT_WIDE = 0x5a
OP_IPUT_OBJECT = 0x5b
OP_IPUT_BOOLEAN = 0x5c
OP_SGET = 0x60
OP_SGET_WIDE = 0x61
OP_SGET_OBJECT = 0x62
OP_SGET_BOOLEAN = 0x63
OP_SPUT = 0x67
OP_SPUT_WIDE = 0x68
OP_SPUT_OBJECT = 0x69
OP_INVOKE_VIRTUAL = 0x6e
OP_INVOKE_SUPER = 0x6f
OP_INVOKE_DIRECT = 0x70
OP_INVOKE_STATIC = 0x71
OP_INVOKE_INTERFACE = 0x72
OP_INVOKE_VIRTUAL_RANGE = 0x74
OP_INVOKE_SUPER_RANGE = 0x75
OP_INVOKE_DIRECT_RANGE = 0x76
OP_INVOKE_STATIC_RANGE = 0x77
OP_INVOKE_INTERFACE_RANGE = 0x78

# Instruction formats sizes (in 16-bit code units)
INSN_SIZE = {
    0x00: 1, 0x01: 1, 0x02: 1, 0x03: 1, 0x04: 1, 0x05: 1, 0x06: 1, 0x07: 1,
    0x08: 1, 0x09: 1, 0x0a: 1, 0x0b: 1, 0x0c: 1, 0x0d: 1, 0x0e: 1, 0x0f: 1,
    0x10: 1, 0x11: 1, 0x12: 1, 0x13: 2, 0x14: 3, 0x15: 2, 0x16: 2, 0x17: 3,
    0x18: 5, 0x19: 2, 0x1a: 2, 0x1b: 3, 0x1c: 2, 0x1d: 1, 0x1e: 1, 0x1f: 2,
    0x20: 2, 0x21: 1, 0x22: 2, 0x23: 2, 0x24: 3, 0x25: 3, 0x26: 3,
    0x27: 1, 0x28: 1, 0x29: 2, 0x2a: 3, 0x2b: 3, 0x2c: 3, 0x2d: 2, 0x2e: 2,
    0x2f: 2, 0x30: 2, 0x31: 2, 0x32: 2, 0x33: 2, 0x34: 2, 0x35: 2, 0x36: 2,
    0x37: 2, 0x38: 2, 0x39: 2, 0x3a: 2, 0x3b: 2, 0x3c: 2, 0x3d: 2,
    0x44: 2, 0x45: 2, 0x46: 2, 0x47: 2, 0x48: 2, 0x49: 2, 0x4a: 2,
    0x4b: 2, 0x4c: 2, 0x4d: 2, 0x4e: 2, 0x4f: 2, 0x50: 2, 0x51: 2,
    0x52: 2, 0x53: 2, 0x54: 2, 0x55: 2, 0x56: 2, 0x57: 2, 0x58: 2,
    0x59: 2, 0x5a: 2, 0x5b: 2, 0x5c: 2, 0x5d: 2, 0x5e: 2, 0x5f: 2,
    0x60: 2, 0x61: 2, 0x62: 2, 0x63: 2, 0x64: 2, 0x65: 2, 0x66: 2,
    0x67: 2, 0x68: 2, 0x69: 2, 0x6a: 2, 0x6b: 2, 0x6c: 2, 0x6d: 2,
    0x6e: 3, 0x6f: 3, 0x70: 3, 0x71: 3, 0x72: 3, 0x73: 3,
    0x74: 3, 0x75: 3, 0x76: 3, 0x77: 3, 0x78: 3,
    0x79: 3, 0x7a: 3, 0x7b: 1, 0x7c: 1, 0x7d: 1, 0x7e: 1, 0x7f: 1,
    0x80: 1, 0x81: 1, 0x82: 1, 0x83: 1, 0x84: 1, 0x85: 1, 0x86: 1,
    0x87: 1, 0x88: 1, 0x89: 1, 0x8a: 1, 0x8b: 1, 0x8c: 1, 0x8d: 1,
    0x8e: 1, 0x8f: 1, 0x90: 2, 0x91: 2, 0x92: 2, 0x93: 2, 0x94: 2,
    0x95: 2, 0x96: 2, 0x97: 2, 0x98: 2, 0x99: 2, 0x9a: 2, 0x9b: 2,
    0x9c: 2, 0x9d: 2, 0x9e: 2, 0x9f: 2, 0xa0: 2, 0xa1: 2, 0xa2: 2,
    0xa3: 2, 0xa4: 2, 0xa5: 2, 0xa6: 2, 0xa7: 2, 0xa8: 2, 0xa9: 2,
    0xaa: 2, 0xab: 2, 0xac: 2, 0xad: 2, 0xae: 2, 0xaf: 2,
    0xb0: 1, 0xb1: 1, 0xb2: 1, 0xb3: 1, 0xb4: 1, 0xb5: 1, 0xb6: 1,
    0xb7: 1, 0xb8: 1, 0xb9: 1, 0xba: 1, 0xbb: 1, 0xbc: 1, 0xbd: 1,
    0xbe: 1, 0xbf: 1, 0xc0: 1, 0xc1: 1, 0xc2: 1, 0xc3: 1, 0xc4: 1,
    0xc5: 1, 0xc6: 1, 0xc7: 1, 0xc8: 1, 0xc9: 1, 0xca: 1, 0xcb: 1,
    0xcc: 1, 0xcd: 1, 0xce: 1, 0xcf: 1, 0xd0: 2, 0xd1: 2, 0xd2: 2,
    0xd3: 2, 0xd4: 2, 0xd5: 2, 0xd6: 2, 0xd7: 2, 0xd8: 2, 0xd9: 2,
    0xda: 2, 0xdb: 2, 0xdc: 2, 0xdd: 2, 0xde: 2, 0xdf: 2, 0xe0: 2,
    0xe1: 2, 0xe2: 2,
}



# ===========================================================================
# DATA STRUCTURES
# ===========================================================================

@dataclass
class DexHeader:
    magic: bytes
    checksum: int
    signature: bytes
    file_size: int
    header_size: int
    endian_tag: int
    link_size: int
    link_off: int
    map_off: int
    string_ids_size: int
    string_ids_off: int
    type_ids_size: int
    type_ids_off: int
    proto_ids_size: int
    proto_ids_off: int
    field_ids_size: int
    field_ids_off: int
    method_ids_size: int
    method_ids_off: int
    class_defs_size: int
    class_defs_off: int
    data_size: int
    data_off: int


@dataclass
class DexClassDef:
    class_idx: int
    access_flags: int
    superclass_idx: int
    interfaces_off: int
    source_file_idx: int
    annotations_off: int
    class_data_off: int
    static_values_off: int


@dataclass
class DexMethodId:
    class_idx: int
    proto_idx: int
    name_idx: int


@dataclass
class DexFieldId:
    class_idx: int
    type_idx: int
    name_idx: int


@dataclass
class DexProtoId:
    shorty_idx: int
    return_type_idx: int
    parameters_off: int


@dataclass
class DecodedInsn:
    """A decoded Dalvik instruction."""
    opcode: int
    offset: int  # offset in code units
    op_name: str = ""
    # For const-string
    string_idx: int = -1
    string_val: str = ""
    # For invoke-*
    method_idx: int = -1
    method_ref: str = ""
    # For field ops
    field_idx: int = -1
    field_ref: str = ""
    # For new-instance
    type_idx: int = -1
    type_ref: str = ""
    # Registers
    dest_reg: int = -1
    src_regs: List[int] = field(default_factory=list)


@dataclass
class MethodCode:
    """Parsed method code with decoded instructions."""
    class_name: str
    method_name: str
    full_name: str  # class->method
    registers_size: int = 0
    ins_size: int = 0
    outs_size: int = 0
    instructions: List[DecodedInsn] = field(default_factory=list)
    # Cross-references
    calls_methods: List[str] = field(default_factory=list)
    uses_strings: List[str] = field(default_factory=list)
    uses_fields: List[str] = field(default_factory=list)
    creates_instances: List[str] = field(default_factory=list)


@dataclass
class CallEdge:
    """Edge in the call graph."""
    caller: str
    callee: str
    call_site_offset: int = 0
    args_strings: List[str] = field(default_factory=list)


@dataclass
class TaintPath:
    """A source-to-sink data flow path."""
    source_method: str
    source_type: str
    sink_method: str
    sink_type: str
    path: List[str] = field(default_factory=list)
    data_description: str = ""


@dataclass
class AttackChain:
    """Complete attack chain for a vulnerability."""
    chain_id: int
    title: str
    severity: str
    entry_point: str
    steps: List[str] = field(default_factory=list)
    cwe: str = ""
    cvss: float = 0.0
    risk_description: str = ""
    impact: str = ""
    exploit_difficulty: str = "Medium"
    exploit_steps: List[str] = field(default_factory=list)
    tools: List[str] = field(default_factory=list)
    poc_template: str = ""
    frida_hook: str = ""
    adb_command: str = ""


@dataclass
class ComponentInfo:
    """Android component from manifest."""
    component_type: str  # activity, service, receiver, provider
    name: str
    exported: bool = False
    intent_filters: List[Dict] = field(default_factory=list)
    permissions: List[str] = field(default_factory=list)
    schemes: List[str] = field(default_factory=list)
    hosts: List[str] = field(default_factory=list)


@dataclass
class Finding:
    """Single security finding."""
    category: str
    severity: str
    name: str
    description: str
    value: str
    source_file: str
    cve_cwe: str = ""
    cvss: float = 0.0
    affected_class: str = ""
    affected_method: str = ""
    remediation: str = ""
    confidence: str = "medium"
    context: str = ""
    attack_chain: Optional[AttackChain] = None
    exploit_info: str = ""
    frida_hook: str = ""
    adb_command: str = ""

    def key(self) -> str:
        return f"{self.category}|{self.name}|{self.value[:100]}|{self.source_file}"


@dataclass
class DexInfo:
    filename: str
    class_count: int = 0
    method_count: int = 0
    field_count: int = 0
    string_count: int = 0
    obfuscated_class_count: int = 0
    total_class_count: int = 0
    methods_with_code: int = 0


@dataclass
class CertInfo:
    filename: str = ""
    issuer: str = ""
    subject: str = ""
    serial: str = ""
    fingerprint_sha256: str = ""
    fingerprint_md5: str = ""


@dataclass
class Report:
    apk_path: str
    apk_size: int
    apk_md5: str
    apk_sha256: str
    scan_time: str = ""
    scan_duration: float = 0.0
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    debuggable: bool = False
    allow_backup: bool = False
    uses_cleartext: bool = False
    permissions: List[str] = field(default_factory=list)
    dangerous_permissions: List[str] = field(default_factory=list)
    components: List[ComponentInfo] = field(default_factory=list)
    exported_components: List[str] = field(default_factory=list)
    deep_links: List[Dict] = field(default_factory=list)
    dex_info: List[DexInfo] = field(default_factory=list)
    cert_info: Optional[CertInfo] = None
    detected_libraries: List[str] = field(default_factory=list)
    tracking_sdks: List[str] = field(default_factory=list)
    security_checks: List[str] = field(default_factory=list)
    obfuscation_score: float = 0.0
    obfuscation_tool: str = ""
    native_libs: List[Dict] = field(default_factory=list)
    findings: List[Finding] = field(default_factory=list)
    attack_chains: List[AttackChain] = field(default_factory=list)
    taint_paths: List[TaintPath] = field(default_factory=list)
    permission_abuse_chains: List[Dict] = field(default_factory=list)
    call_graph_stats: Dict = field(default_factory=dict)
    summary: Dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = {}
        for k, v in self.__dict__.items():
            if k == 'findings':
                d[k] = [self._finding_to_dict(f) for f in v]
            elif k == 'attack_chains':
                d[k] = [asdict(c) for c in v]
            elif k == 'taint_paths':
                d[k] = [asdict(t) for t in v]
            elif k == 'components':
                d[k] = [asdict(c) for c in v]
            elif k == 'cert_info':
                d[k] = asdict(v) if v else None
            elif k == 'dex_info':
                d[k] = [asdict(i) for i in v]
            else:
                d[k] = v
        return d

    def _finding_to_dict(self, f: Finding) -> dict:
        d = {}
        for k, v in f.__dict__.items():
            if k == 'attack_chain':
                d[k] = asdict(v) if v else None
            else:
                d[k] = v
        return d



# ===========================================================================
# DEX PARSER WITH BYTECODE DISASSEMBLER
# ===========================================================================

class DexParser:
    """Full DEX parser with bytecode disassembly and call graph building."""

    def __init__(self, data: bytes):
        self.data = data
        self.header: Optional[DexHeader] = None
        self.string_table: List[str] = []
        self.type_table: List[str] = []
        self.proto_table: List[DexProtoId] = []
        self.field_table: List[DexFieldId] = []
        self.method_table: List[DexMethodId] = []
        self.class_defs: List[DexClassDef] = []
        self.class_names: List[str] = []
        self.full_method_refs: List[str] = []
        self.full_field_refs: List[str] = []
        # Bytecode analysis
        self.method_codes: List[MethodCode] = []
        self.call_graph: Dict[str, Set[str]] = defaultdict(set)  # caller -> set(callee)
        self.reverse_call_graph: Dict[str, Set[str]] = defaultdict(set)  # callee -> set(caller)
        self.string_xrefs: Dict[str, Set[str]] = defaultdict(set)  # string -> set(methods using it)
        self.method_string_map: Dict[str, List[str]] = defaultdict(list)  # method -> strings it uses
        self.class_hierarchy: Dict[str, str] = {}  # class -> superclass

    def parse(self) -> bool:
        try:
            if len(self.data) < DEX_HEADER_SIZE:
                return False
            if self.data[:4] != DEX_MAGIC:
                return False
            self._parse_header()
            self._parse_string_ids()
            self._parse_type_ids()
            self._parse_proto_ids()
            self._parse_field_ids()
            self._parse_method_ids()
            self._parse_class_defs()
            self._build_references()
            self._parse_all_method_bytecode()
            return True
        except Exception:
            return False

    def _parse_header(self):
        d = self.data
        self.header = DexHeader(
            magic=d[0:8],
            checksum=struct.unpack_from('<I', d, 8)[0],
            signature=d[12:32],
            file_size=struct.unpack_from('<I', d, 32)[0],
            header_size=struct.unpack_from('<I', d, 36)[0],
            endian_tag=struct.unpack_from('<I', d, 40)[0],
            link_size=struct.unpack_from('<I', d, 44)[0],
            link_off=struct.unpack_from('<I', d, 48)[0],
            map_off=struct.unpack_from('<I', d, 52)[0],
            string_ids_size=struct.unpack_from('<I', d, 56)[0],
            string_ids_off=struct.unpack_from('<I', d, 60)[0],
            type_ids_size=struct.unpack_from('<I', d, 64)[0],
            type_ids_off=struct.unpack_from('<I', d, 68)[0],
            proto_ids_size=struct.unpack_from('<I', d, 72)[0],
            proto_ids_off=struct.unpack_from('<I', d, 76)[0],
            field_ids_size=struct.unpack_from('<I', d, 80)[0],
            field_ids_off=struct.unpack_from('<I', d, 84)[0],
            method_ids_size=struct.unpack_from('<I', d, 88)[0],
            method_ids_off=struct.unpack_from('<I', d, 92)[0],
            class_defs_size=struct.unpack_from('<I', d, 96)[0],
            class_defs_off=struct.unpack_from('<I', d, 100)[0],
            data_size=struct.unpack_from('<I', d, 104)[0],
            data_off=struct.unpack_from('<I', d, 108)[0],
        )

    def _parse_string_ids(self):
        h = self.header
        if not h:
            return
        for i in range(h.string_ids_size):
            off_pos = h.string_ids_off + i * 4
            if off_pos + 4 > len(self.data):
                break
            string_data_off = struct.unpack_from('<I', self.data, off_pos)[0]
            s = self._read_mutf8(string_data_off)
            self.string_table.append(s)

    def _read_mutf8(self, offset: int) -> str:
        if offset >= len(self.data):
            return ""
        pos = offset
        size = 0
        shift = 0
        while pos < len(self.data):
            b = self.data[pos]
            pos += 1
            size |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        result = []
        count = 0
        while count < size and pos < len(self.data):
            b = self.data[pos]
            pos += 1
            if b == 0:
                break
            if (b & 0x80) == 0:
                result.append(chr(b))
            elif (b & 0xE0) == 0xC0:
                if pos < len(self.data):
                    b2 = self.data[pos]; pos += 1
                    result.append(chr(((b & 0x1F) << 6) | (b2 & 0x3F)))
                else:
                    break
            elif (b & 0xF0) == 0xE0:
                if pos + 1 < len(self.data):
                    b2 = self.data[pos]; b3 = self.data[pos + 1]; pos += 2
                    result.append(chr(((b & 0x0F) << 12) | ((b2 & 0x3F) << 6) | (b3 & 0x3F)))
                else:
                    break
            else:
                result.append('?')
            count += 1
        return "".join(result)

    def _parse_type_ids(self):
        h = self.header
        if not h:
            return
        for i in range(h.type_ids_size):
            off = h.type_ids_off + i * 4
            if off + 4 > len(self.data):
                break
            idx = struct.unpack_from('<I', self.data, off)[0]
            if idx < len(self.string_table):
                self.type_table.append(self.string_table[idx])
            else:
                self.type_table.append("")

    def _parse_proto_ids(self):
        h = self.header
        if not h:
            return
        for i in range(h.proto_ids_size):
            off = h.proto_ids_off + i * 12
            if off + 12 > len(self.data):
                break
            shorty_idx, return_type_idx, params_off = struct.unpack_from('<III', self.data, off)
            self.proto_table.append(DexProtoId(shorty_idx, return_type_idx, params_off))

    def _parse_field_ids(self):
        h = self.header
        if not h:
            return
        for i in range(h.field_ids_size):
            off = h.field_ids_off + i * 8
            if off + 8 > len(self.data):
                break
            class_idx, type_idx, name_idx = struct.unpack_from('<HHI', self.data, off)
            self.field_table.append(DexFieldId(class_idx, type_idx, name_idx))

    def _parse_method_ids(self):
        h = self.header
        if not h:
            return
        for i in range(h.method_ids_size):
            off = h.method_ids_off + i * 8
            if off + 8 > len(self.data):
                break
            class_idx, proto_idx, name_idx = struct.unpack_from('<HHI', self.data, off)
            self.method_table.append(DexMethodId(class_idx, proto_idx, name_idx))

    def _parse_class_defs(self):
        h = self.header
        if not h:
            return
        for i in range(h.class_defs_size):
            off = h.class_defs_off + i * 32
            if off + 32 > len(self.data):
                break
            vals = struct.unpack_from('<IIIIIIII', self.data, off)
            cd = DexClassDef(*vals)
            self.class_defs.append(cd)
            # Build class hierarchy
            if cd.class_idx < len(self.type_table):
                cn = self.type_table[cd.class_idx]
                self.class_names.append(cn)
                if cd.superclass_idx < len(self.type_table) and cd.superclass_idx != 0xFFFFFFFF:
                    self.class_hierarchy[cn] = self.type_table[cd.superclass_idx]

    def _build_references(self):
        for mid in self.method_table:
            class_name = self.type_table[mid.class_idx] if mid.class_idx < len(self.type_table) else "?"
            method_name = self.string_table[mid.name_idx] if mid.name_idx < len(self.string_table) else "?"
            self.full_method_refs.append(f"{class_name}->{method_name}")
        for fid in self.field_table:
            class_name = self.type_table[fid.class_idx] if fid.class_idx < len(self.type_table) else "?"
            field_name = self.string_table[fid.name_idx] if fid.name_idx < len(self.string_table) else "?"
            self.full_field_refs.append(f"{class_name}->{field_name}")

    def _read_uleb128(self, pos: int) -> Tuple[int, int]:
        """Read ULEB128, return (value, new_pos)."""
        result = 0
        shift = 0
        while pos < len(self.data):
            b = self.data[pos]
            pos += 1
            result |= (b & 0x7F) << shift
            if (b & 0x80) == 0:
                break
            shift += 7
        return result, pos

    def _parse_all_method_bytecode(self):
        """Parse bytecode for all methods in all classes."""
        for cd in self.class_defs:
            if cd.class_data_off == 0:
                continue
            class_name = self.type_table[cd.class_idx] if cd.class_idx < len(self.type_table) else "?"
            self._parse_class_data(cd.class_data_off, class_name)

    def _parse_class_data(self, offset: int, class_name: str):
        """Parse class_data_item structure."""
        if offset >= len(self.data):
            return
        pos = offset
        static_fields_size, pos = self._read_uleb128(pos)
        instance_fields_size, pos = self._read_uleb128(pos)
        direct_methods_size, pos = self._read_uleb128(pos)
        virtual_methods_size, pos = self._read_uleb128(pos)

        # Skip field definitions
        field_idx = 0
        for _ in range(static_fields_size):
            diff, pos = self._read_uleb128(pos)
            field_idx += diff
            _, pos = self._read_uleb128(pos)  # access_flags

        field_idx = 0
        for _ in range(instance_fields_size):
            diff, pos = self._read_uleb128(pos)
            field_idx += diff
            _, pos = self._read_uleb128(pos)

        # Parse direct methods
        method_idx = 0
        for _ in range(direct_methods_size):
            diff, pos = self._read_uleb128(pos)
            method_idx += diff
            _, pos = self._read_uleb128(pos)  # access_flags
            code_off, pos = self._read_uleb128(pos)
            if code_off != 0 and method_idx < len(self.full_method_refs):
                method_name = self.full_method_refs[method_idx]
                self._parse_code_item(code_off, class_name, method_name)

        # Parse virtual methods
        method_idx = 0
        for _ in range(virtual_methods_size):
            diff, pos = self._read_uleb128(pos)
            method_idx += diff
            _, pos = self._read_uleb128(pos)
            code_off, pos = self._read_uleb128(pos)
            if code_off != 0 and method_idx < len(self.full_method_refs):
                method_name = self.full_method_refs[method_idx]
                self._parse_code_item(code_off, class_name, method_name)

    def _parse_code_item(self, offset: int, class_name: str, full_method_name: str):
        """Parse a code_item and decode its instructions."""
        if offset + 16 > len(self.data):
            return
        registers_size = struct.unpack_from('<H', self.data, offset)[0]
        ins_size = struct.unpack_from('<H', self.data, offset + 2)[0]
        outs_size = struct.unpack_from('<H', self.data, offset + 4)[0]
        # tries_size = struct.unpack_from('<H', self.data, offset + 6)[0]
        # debug_info_off = struct.unpack_from('<I', self.data, offset + 8)[0]
        insns_size = struct.unpack_from('<I', self.data, offset + 12)[0]

        insns_off = offset + 16
        if insns_off + insns_size * 2 > len(self.data):
            return

        # Extract method short name
        parts = full_method_name.split("->")
        short_method = parts[1] if len(parts) > 1 else full_method_name

        mc = MethodCode(
            class_name=class_name,
            method_name=short_method,
            full_name=full_method_name,
            registers_size=registers_size,
            ins_size=ins_size,
            outs_size=outs_size,
        )

        # Decode instructions
        pos = 0
        insns_data = self.data[insns_off:insns_off + insns_size * 2]

        while pos < insns_size:
            if pos * 2 + 1 >= len(insns_data):
                break
            opcode = insns_data[pos * 2]
            insn = self._decode_instruction(insns_data, pos, opcode)
            if insn:
                mc.instructions.append(insn)
                # Build cross-references
                if insn.string_val:
                    mc.uses_strings.append(insn.string_val)
                    self.string_xrefs[insn.string_val].add(full_method_name)
                    self.method_string_map[full_method_name].append(insn.string_val)
                if insn.method_ref:
                    mc.calls_methods.append(insn.method_ref)
                    self.call_graph[full_method_name].add(insn.method_ref)
                    self.reverse_call_graph[insn.method_ref].add(full_method_name)
                if insn.field_ref:
                    mc.uses_fields.append(insn.field_ref)
                if insn.type_ref and insn.opcode == OP_NEW_INSTANCE:
                    mc.creates_instances.append(insn.type_ref)

            # Advance
            size = INSN_SIZE.get(opcode, 1)
            pos += size

        self.method_codes.append(mc)

    def _decode_instruction(self, insns: bytes, pos: int, opcode: int) -> Optional[DecodedInsn]:
        """Decode a single Dalvik instruction."""
        byte_pos = pos * 2
        if byte_pos + 1 >= len(insns):
            return None

        insn = DecodedInsn(opcode=opcode, offset=pos)

        try:
            if opcode == OP_CONST_STRING:
                # Format 21c: AA|op BBBB
                if byte_pos + 3 < len(insns):
                    insn.dest_reg = insns[byte_pos + 1]
                    insn.string_idx = struct.unpack_from('<H', insns, byte_pos + 2)[0]
                    if insn.string_idx < len(self.string_table):
                        insn.string_val = self.string_table[insn.string_idx]
                    insn.op_name = "const-string"

            elif opcode == OP_CONST_STRING_JUMBO:
                # Format 31c: AA|op BBBBBBBB
                if byte_pos + 5 < len(insns):
                    insn.dest_reg = insns[byte_pos + 1]
                    insn.string_idx = struct.unpack_from('<I', insns, byte_pos + 2)[0]
                    if insn.string_idx < len(self.string_table):
                        insn.string_val = self.string_table[insn.string_idx]
                    insn.op_name = "const-string/jumbo"

            elif opcode in (OP_INVOKE_VIRTUAL, OP_INVOKE_SUPER, OP_INVOKE_DIRECT,
                           OP_INVOKE_STATIC, OP_INVOKE_INTERFACE):
                # Format 35c: A|G|op BBBB F|E|D|C
                if byte_pos + 5 < len(insns):
                    insn.method_idx = struct.unpack_from('<H', insns, byte_pos + 2)[0]
                    if insn.method_idx < len(self.full_method_refs):
                        insn.method_ref = self.full_method_refs[insn.method_idx]
                    op_names = {
                        OP_INVOKE_VIRTUAL: "invoke-virtual",
                        OP_INVOKE_SUPER: "invoke-super",
                        OP_INVOKE_DIRECT: "invoke-direct",
                        OP_INVOKE_STATIC: "invoke-static",
                        OP_INVOKE_INTERFACE: "invoke-interface",
                    }
                    insn.op_name = op_names.get(opcode, "invoke-?")

            elif opcode in (OP_INVOKE_VIRTUAL_RANGE, OP_INVOKE_SUPER_RANGE,
                           OP_INVOKE_DIRECT_RANGE, OP_INVOKE_STATIC_RANGE,
                           OP_INVOKE_INTERFACE_RANGE):
                # Format 3rc: AA|op BBBB CCCC
                if byte_pos + 5 < len(insns):
                    insn.method_idx = struct.unpack_from('<H', insns, byte_pos + 2)[0]
                    if insn.method_idx < len(self.full_method_refs):
                        insn.method_ref = self.full_method_refs[insn.method_idx]
                    insn.op_name = "invoke-*/range"

            elif opcode in (OP_IGET, OP_IGET_WIDE, OP_IGET_OBJECT, OP_IGET_BOOLEAN,
                           OP_IGET_BYTE, OP_IGET_CHAR, OP_IGET_SHORT):
                # Format 22c
                if byte_pos + 3 < len(insns):
                    insn.field_idx = struct.unpack_from('<H', insns, byte_pos + 2)[0]
                    if insn.field_idx < len(self.full_field_refs):
                        insn.field_ref = self.full_field_refs[insn.field_idx]
                    insn.op_name = "iget"

            elif opcode in (OP_IPUT, OP_IPUT_WIDE, OP_IPUT_OBJECT, OP_IPUT_BOOLEAN):
                if byte_pos + 3 < len(insns):
                    insn.field_idx = struct.unpack_from('<H', insns, byte_pos + 2)[0]
                    if insn.field_idx < len(self.full_field_refs):
                        insn.field_ref = self.full_field_refs[insn.field_idx]
                    insn.op_name = "iput"

            elif opcode in (OP_SGET, OP_SGET_WIDE, OP_SGET_OBJECT, OP_SGET_BOOLEAN):
                if byte_pos + 3 < len(insns):
                    insn.field_idx = struct.unpack_from('<H', insns, byte_pos + 2)[0]
                    if insn.field_idx < len(self.full_field_refs):
                        insn.field_ref = self.full_field_refs[insn.field_idx]
                    insn.op_name = "sget"

            elif opcode in (OP_SPUT, OP_SPUT_WIDE, OP_SPUT_OBJECT):
                if byte_pos + 3 < len(insns):
                    insn.field_idx = struct.unpack_from('<H', insns, byte_pos + 2)[0]
                    if insn.field_idx < len(self.full_field_refs):
                        insn.field_ref = self.full_field_refs[insn.field_idx]
                    insn.op_name = "sput"

            elif opcode == OP_NEW_INSTANCE:
                # Format 21c
                if byte_pos + 3 < len(insns):
                    insn.dest_reg = insns[byte_pos + 1]
                    insn.type_idx = struct.unpack_from('<H', insns, byte_pos + 2)[0]
                    if insn.type_idx < len(self.type_table):
                        insn.type_ref = self.type_table[insn.type_idx]
                    insn.op_name = "new-instance"

            elif opcode == OP_CONST_CLASS:
                if byte_pos + 3 < len(insns):
                    insn.dest_reg = insns[byte_pos + 1]
                    insn.type_idx = struct.unpack_from('<H', insns, byte_pos + 2)[0]
                    if insn.type_idx < len(self.type_table):
                        insn.type_ref = self.type_table[insn.type_idx]
                    insn.op_name = "const-class"

        except (struct.error, IndexError):
            pass

        return insn

    def dex_type_to_java(self, dex_type: str) -> str:
        if not dex_type:
            return ""
        if dex_type.startswith("L") and dex_type.endswith(";"):
            return dex_type[1:-1].replace("/", ".")
        return dex_type

    def get_java_class_names(self) -> List[str]:
        return [self.dex_type_to_java(cn) for cn in self.class_names]

    def is_obfuscated(self, name: str) -> bool:
        parts = name.split(".")
        if not parts:
            return False
        last = parts[-1]
        if len(last) <= 2 and last.isalpha() and last.islower():
            return True
        short_parts = [p for p in parts if len(p) <= 2 and p.isalpha()]
        if len(short_parts) > len(parts) * 0.6:
            return True
        return False

    def get_method_callers(self, method_pattern: str) -> Set[str]:
        """Find all methods that call methods matching pattern."""
        callers = set()
        for callee, caller_set in self.reverse_call_graph.items():
            if method_pattern in callee:
                callers.update(caller_set)
        return callers

    def get_string_users(self, string_val: str) -> Set[str]:
        """Find all methods that use a given string."""
        users = set()
        for s, methods in self.string_xrefs.items():
            if string_val in s:
                users.update(methods)
        return users

    def find_path(self, source: str, sink: str, max_depth: int = 6) -> List[str]:
        """Find call path from source method to sink method (BFS)."""
        if source == sink:
            return [source]
        visited = {source}
        queue = [(source, [source])]
        while queue:
            current, path = queue.pop(0)
            if len(path) > max_depth:
                continue
            for callee in self.call_graph.get(current, set()):
                if sink in callee:
                    return path + [callee]
                if callee not in visited:
                    visited.add(callee)
                    queue.append((callee, path + [callee]))
        return []



# ===========================================================================
# VULNERABILITY PATTERNS DATABASE
# ===========================================================================

@dataclass
class VulnPattern:
    vuln_id: str
    name: str
    severity: str
    cve_cwe: str
    cvss: float
    description: str
    remediation: str
    confidence: str
    class_patterns: List[str] = field(default_factory=list)
    method_patterns: List[str] = field(default_factory=list)
    string_patterns: List[str] = field(default_factory=list)
    field_patterns: List[str] = field(default_factory=list)
    exploit_info: str = ""
    frida_template: str = ""
    attack_scenario: str = ""


VULN_PATTERNS: List[VulnPattern] = [
    VulnPattern(
        vuln_id="CRYPTO-001", name="DES/3DES Weak Cipher", severity="HIGH",
        cve_cwe="CWE-327", cvss=7.5,
        description="Use of DES or 3DES which is cryptographically broken.",
        remediation="Replace with AES-256-GCM or ChaCha20-Poly1305.",
        confidence="high",
        string_patterns=["DES/", "DESede/", "DESede", "\"DES\""],
        method_patterns=["Cipher->getInstance"],
        exploit_info="Brute-force DES key (56-bit) in hours with FPGA. 3DES vulnerable to Sweet32 (CVE-2016-2183).",
        frida_template="""Java.perform(function() {
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log('[*] Cipher.getInstance: ' + algo);
        if (algo.indexOf('DES') !== -1) {
            console.log('[!] WEAK CIPHER DETECTED: ' + algo);
            console.log(Java.use('android.util.Log').getStackTraceString(Java.use('java.lang.Exception').$new()));
        }
        return this.getInstance(algo);
    };
});""",
        attack_scenario="Attacker captures encrypted traffic/stored data and brute-forces DES key",
    ),
    VulnPattern(
        vuln_id="CRYPTO-002", name="ECB Mode Usage", severity="HIGH",
        cve_cwe="CWE-327", cvss=7.0,
        description="ECB mode does not provide semantic security. Identical blocks produce identical ciphertext.",
        remediation="Use CBC, CTR, or GCM mode with proper IV/nonce.",
        confidence="high",
        string_patterns=["AES/ECB", "/ECB/", "ECB/PKCS5", "ECB/NoPadding"],
        exploit_info="ECB leaks patterns in encrypted data. Famous example: encrypted Linux penguin still shows penguin shape.",
        attack_scenario="Attacker identifies repeating patterns in ciphertext to deduce plaintext structure",
    ),
    VulnPattern(
        vuln_id="CRYPTO-003", name="Hardcoded Cryptographic Key", severity="CRITICAL",
        cve_cwe="CWE-321", cvss=9.1,
        description="Hardcoded crypto key extractable from APK by any attacker with basic reverse engineering.",
        remediation="Use Android Keystore or derive keys from user credentials with PBKDF2/Argon2.",
        confidence="medium",
        method_patterns=["SecretKeySpec-><init>"],
        string_patterns=["SecretKeySpec"],
        exploit_info="Extract APK, find key in DEX strings/bytecode, decrypt all data encrypted with this key.",
        frida_template="""Java.perform(function() {
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log('[!] SecretKeySpec created:');
        console.log('    Algorithm: ' + algo);
        console.log('    Key (hex): ' + bytesToHex(key));
        return this.$init(key, algo);
    };
    function bytesToHex(bytes) {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        return hex.join('');
    }
});""",
        attack_scenario="Decompile APK -> extract key -> decrypt stored data/tokens",
    ),
    VulnPattern(
        vuln_id="CRYPTO-004", name="Static IV/Nonce", severity="HIGH",
        cve_cwe="CWE-329", cvss=7.0,
        description="Static initialization vector makes encryption deterministic and vulnerable to known-plaintext attacks.",
        remediation="Generate random IV per operation with SecureRandom.",
        confidence="medium",
        method_patterns=["IvParameterSpec-><init>"],
        string_patterns=["IvParameterSpec"],
        exploit_info="Same IV + same key = same ciphertext for same plaintext. Enables frequency analysis.",
        frida_template="""Java.perform(function() {
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        console.log('[!] IvParameterSpec created with IV: ' + bytesToHex(iv));
        return this.$init(iv);
    };
    function bytesToHex(bytes) {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        return hex.join('');
    }
});""",
    ),
    VulnPattern(
        vuln_id="CRYPTO-005", name="MD5 for Security", severity="MEDIUM",
        cve_cwe="CWE-328", cvss=5.3,
        description="MD5 is cryptographically broken. Collisions are trivial to generate.",
        remediation="Use SHA-256/SHA-3 for integrity, bcrypt/scrypt/Argon2 for passwords.",
        confidence="medium",
        string_patterns=["\"MD5\"", "MD5"],
        method_patterns=["MessageDigest->getInstance"],
    ),
    VulnPattern(
        vuln_id="CRYPTO-006", name="SHA1 for Security", severity="MEDIUM",
        cve_cwe="CWE-328", cvss=5.3,
        description="SHA-1 has practical collision attacks (SHAttered, 2017).",
        remediation="Migrate to SHA-256 or SHA-3.",
        confidence="medium",
        string_patterns=["\"SHA-1\"", "\"SHA1\""],
        method_patterns=["MessageDigest->getInstance"],
    ),
    VulnPattern(
        vuln_id="SSL-001", name="Trust All Certificates (TrustManager)", severity="CRITICAL",
        cve_cwe="CWE-295", cvss=9.1,
        description="Custom TrustManager accepts ALL certificates, completely disabling TLS security.",
        remediation="Use default TrustManager or pin specific certificates.",
        confidence="high",
        string_patterns=["TrustAllCertificates", "AllowAllTrustManager", "NullTrustManager",
                        "UnsafeTrustManager", "AcceptAllTrustManager", "TrustAllManager",
                        "InsecureTrustManager", "EmptyTrustManager"],
        method_patterns=["X509TrustManager->checkServerTrusted", "X509TrustManager->checkClientTrusted"],
        exploit_info="Set up mitmproxy/Burp on same network. ALL HTTPS traffic is interceptable.",
        frida_template="""Java.perform(function() {
    // Universal SSL Pinning Bypass
    var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
    if (TrustManagerImpl) {
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[*] SSL Pin Bypass - Host: ' + host);
            return untrustedChain;
        };
    }
    // OkHttp CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(host, certs) {
            console.log('[*] OkHttp Pin Bypass - Host: ' + host);
        };
    } catch(e) {}
    // TrustManager bypass
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');
    var TrustManager = Java.registerClass({
        name: 'com.bypass.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) {},
            checkServerTrusted: function(chain, authType) {},
            getAcceptedIssuers: function() { return []; }
        }
    });
    var TrustManagers = [TrustManager.$new()];
    var sslContext = SSLContext.getInstance('TLS');
    sslContext.init(null, TrustManagers, null);
    console.log('[*] Universal TrustManager bypass installed');
});""",
        attack_scenario="MITM on WiFi -> intercept all HTTPS -> steal credentials/tokens",
    ),
    VulnPattern(
        vuln_id="SSL-002", name="Hostname Verifier Bypass", severity="CRITICAL",
        cve_cwe="CWE-295", cvss=8.1,
        description="Hostname verification disabled. Any valid certificate for any domain is accepted.",
        remediation="Use default HostnameVerifier or implement strict hostname checking.",
        confidence="high",
        string_patterns=["AllowAllHostnameVerifier", "ALLOW_ALL_HOSTNAME_VERIFIER",
                        "NoopHostnameVerifier", "NullHostnameVerifier"],
        method_patterns=["HostnameVerifier->verify"],
        exploit_info="Attacker with ANY valid cert (even self-signed) can intercept connections.",
    ),
    VulnPattern(
        vuln_id="SSL-003", name="Cleartext HTTP Traffic", severity="MEDIUM",
        cve_cwe="CWE-319", cvss=5.9,
        description="App uses cleartext HTTP, all data sent unencrypted over the network.",
        remediation="Use HTTPS. Set android:usesCleartextTraffic='false' in manifest.",
        confidence="medium",
        string_patterns=["usesCleartextTraffic"],
    ),
    VulnPattern(
        vuln_id="SQLI-001", name="SQL Injection (rawQuery)", severity="HIGH",
        cve_cwe="CWE-89", cvss=8.6,
        description="rawQuery with string concatenation enables SQL injection.",
        remediation="Use parameterized queries with selectionArgs.",
        confidence="medium",
        method_patterns=["SQLiteDatabase->rawQuery"],
        exploit_info="Inject via exported ContentProvider or deep link parameter: ' OR 1=1 --",
        frida_template="""Java.perform(function() {
    var SQLiteDatabase = Java.use('android.database.sqlite.SQLiteDatabase');
    SQLiteDatabase.rawQuery.overload('java.lang.String', '[Ljava.lang.String;').implementation = function(sql, args) {
        console.log('[!] rawQuery: ' + sql);
        if (args) console.log('    Args: ' + args);
        return this.rawQuery(sql, args);
    };
});""",
    ),
    VulnPattern(
        vuln_id="WEBVIEW-001", name="JavaScript Interface Injection", severity="CRITICAL",
        cve_cwe="CVE-2012-6636", cvss=9.8,
        description="WebView with JS enabled + addJavascriptInterface. On API<17, full RCE via reflection.",
        remediation="Remove addJavascriptInterface or target API>=17 with @JavascriptInterface.",
        confidence="high",
        method_patterns=["WebView->addJavascriptInterface", "WebSettings->setJavaScriptEnabled"],
        string_patterns=["setJavaScriptEnabled", "addJavascriptInterface"],
        exploit_info="Load malicious page in WebView -> call Java methods via JS -> full device access.",
        frida_template="""Java.perform(function() {
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[*] WebView.loadUrl: ' + url);
        return this.loadUrl(url);
    };
    WebView.addJavascriptInterface.implementation = function(obj, name) {
        console.log('[!] addJavascriptInterface: name=' + name + ' class=' + obj.getClass().getName());
        return this.addJavascriptInterface(obj, name);
    };
});""",
    ),
    VulnPattern(
        vuln_id="WEBVIEW-002", name="WebView File Access", severity="HIGH",
        cve_cwe="CWE-749", cvss=7.5,
        description="WebView with file access can read local files and exfiltrate data.",
        remediation="setAllowFileAccess(false), setAllowFileAccessFromFileURLs(false).",
        confidence="medium",
        method_patterns=["WebSettings->setAllowFileAccess", "WebSettings->setAllowUniversalAccessFromFileURLs"],
        string_patterns=["setAllowFileAccess", "setAllowUniversalAccessFromFileURLs"],
    ),
    VulnPattern(
        vuln_id="CMD-001", name="Command Injection", severity="CRITICAL",
        cve_cwe="CWE-78", cvss=9.8,
        description="Runtime.exec or ProcessBuilder with potential user input enables OS command injection.",
        remediation="Avoid shell commands with user input. Use specific APIs.",
        confidence="medium",
        method_patterns=["Runtime->exec", "ProcessBuilder-><init>", "Runtime->getRuntime"],
        string_patterns=["Runtime.getRuntime", "ProcessBuilder"],
        exploit_info="Inject via: ; cat /data/data/com.app/shared_prefs/*.xml",
        frida_template="""Java.perform(function() {
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        console.log('[!] Runtime.exec: ' + cmd);
        return this.exec(cmd);
    };
    Runtime.exec.overload('[Ljava.lang.String;').implementation = function(cmds) {
        console.log('[!] Runtime.exec: ' + cmds.join(' '));
        return this.exec(cmds);
    };
});""",
    ),
    VulnPattern(
        vuln_id="STORAGE-001", name="World-Readable SharedPreferences", severity="HIGH",
        cve_cwe="CWE-312", cvss=7.5,
        description="SharedPreferences with MODE_WORLD_READABLE accessible by ALL apps.",
        remediation="Use MODE_PRIVATE and EncryptedSharedPreferences.",
        confidence="high",
        string_patterns=["MODE_WORLD_READABLE", "MODE_WORLD_WRITABLE"],
    ),
    VulnPattern(
        vuln_id="STORAGE-002", name="Plaintext Credential Storage", severity="HIGH",
        cve_cwe="CWE-312", cvss=7.5,
        description="Storing credentials/tokens in plaintext without encryption.",
        remediation="Use EncryptedSharedPreferences or Android Keystore.",
        confidence="low",
        string_patterns=["password", "passwd", "credential", "api_key", "access_token",
                        "secret_key", "auth_token", "private_key"],
        method_patterns=["SharedPreferences->edit", "Editor->putString"],
    ),
    VulnPattern(
        vuln_id="LOG-001", name="Sensitive Data Logging", severity="MEDIUM",
        cve_cwe="CWE-532", cvss=5.3,
        description="Logging sensitive data visible via logcat to any app on device.",
        remediation="Strip Log calls in production with ProGuard/R8.",
        confidence="low",
        method_patterns=["Log->d", "Log->v", "Log->i", "Log->w", "Log->e"],
    ),
    VulnPattern(
        vuln_id="INTENT-001", name="Implicit Intent Data Leak", severity="MEDIUM",
        cve_cwe="CWE-927", cvss=5.5,
        description="Implicit intents can be intercepted by malicious apps.",
        remediation="Use explicit intents or verify receiver.",
        confidence="low",
        method_patterns=["sendBroadcast"],
        string_patterns=["sendBroadcast"],
    ),
    VulnPattern(
        vuln_id="RANDOM-001", name="Insecure Random (java.util.Random)", severity="MEDIUM",
        cve_cwe="CWE-330", cvss=5.3,
        description="java.util.Random is predictable. NOT cryptographically secure.",
        remediation="Use java.security.SecureRandom.",
        confidence="medium",
        class_patterns=["java/util/Random"],
        method_patterns=["Random-><init>", "Random->nextInt"],
    ),
    VulnPattern(
        vuln_id="DESER-001", name="Insecure Deserialization", severity="HIGH",
        cve_cwe="CWE-502", cvss=8.1,
        description="ObjectInputStream without type filtering enables arbitrary code execution.",
        remediation="Use safe serialization (JSON, Protocol Buffers) or ObjectInputFilter.",
        confidence="medium",
        method_patterns=["ObjectInputStream-><init>", "ObjectInputStream->readObject"],
    ),
    VulnPattern(
        vuln_id="ZIP-001", name="Zip Slip Path Traversal", severity="HIGH",
        cve_cwe="CWE-22", cvss=7.5,
        description="ZipEntry extraction without path validation enables arbitrary file overwrite.",
        remediation="Validate ZipEntry.getName() does not contain '..'.",
        confidence="medium",
        method_patterns=["ZipEntry->getName", "ZipInputStream->getNextEntry"],
    ),
    VulnPattern(
        vuln_id="BACKUP-001", name="Application Backup Allowed", severity="MEDIUM",
        cve_cwe="CWE-921", cvss=5.3,
        description="allowBackup=true enables data extraction via adb backup.",
        remediation="Set android:allowBackup='false' or encrypt backup data.",
        confidence="high",
        string_patterns=["allowBackup"],
    ),
    VulnPattern(
        vuln_id="DEBUG-001", name="Debuggable Application", severity="HIGH",
        cve_cwe="CWE-489", cvss=7.5,
        description="debuggable=true allows attaching debugger and accessing app internals.",
        remediation="Remove debuggable flag for production.",
        confidence="high",
        string_patterns=["debuggable"],
    ),
    VulnPattern(
        vuln_id="CLIP-001", name="Clipboard Data Leakage", severity="LOW",
        cve_cwe="CWE-200", cvss=3.3,
        description="Sensitive data on clipboard accessible to all apps (pre-Android 10).",
        remediation="Avoid clipboard for sensitive data. Use PersistableBundle flags.",
        confidence="low",
        method_patterns=["ClipboardManager->setPrimaryClip"],
    ),
    VulnPattern(
        vuln_id="DEEP-001", name="Unvalidated Deep Links", severity="MEDIUM",
        cve_cwe="CWE-939", cvss=5.3,
        description="Deep link handlers without input validation exploitable by malicious apps.",
        remediation="Validate all parameters. Use App Links with Digital Asset Links.",
        confidence="low",
        string_patterns=["android.intent.action.VIEW", "android:scheme"],
        method_patterns=["Intent->getData", "Intent->getDataString"],
    ),
    VulnPattern(
        vuln_id="FRAG-001", name="Fragment Injection", severity="HIGH",
        cve_cwe="CVE-2013-6271", cvss=7.5,
        description="Exported PreferenceActivity allows loading arbitrary fragments.",
        remediation="Override isValidFragment() to whitelist allowed fragments.",
        confidence="medium",
        class_patterns=["PreferenceActivity"],
        string_patterns=["PreferenceActivity"],
    ),
]



# ===========================================================================
# KNOWN VULNERABLE LIBRARIES
# ===========================================================================

VULN_LIBRARIES = [
    {"name": "OkHttp < 3.12.1", "pattern": r"com/squareup/okhttp3?/", "cve": "CVE-2018-20200", "severity": "HIGH", "cvss": 7.4},
    {"name": "Apache HttpClient", "pattern": r"org/apache/http/", "cve": "CVE-2014-3577", "severity": "MEDIUM", "cvss": 5.9},
    {"name": "BouncyCastle < 1.61", "pattern": r"org/bouncycastle/|org/spongycastle/", "cve": "CVE-2018-1000613", "severity": "HIGH", "cvss": 7.5},
    {"name": "Jackson Databind", "pattern": r"com/fasterxml/jackson/databind/", "cve": "CVE-2020-36518", "severity": "HIGH", "cvss": 7.5},
    {"name": "Gson < 2.8.9", "pattern": r"com/google/gson/", "cve": "CVE-2022-25647", "severity": "HIGH", "cvss": 7.5},
    {"name": "Facebook SDK (old)", "pattern": r"com/facebook/", "cve": "CVE-2020-25870", "severity": "MEDIUM", "cvss": 5.3},
    {"name": "Glide < 4.11", "pattern": r"com/bumptech/glide/", "cve": "CVE-2019-10773", "severity": "MEDIUM", "cvss": 5.3},
    {"name": "Retrofit < 2.5", "pattern": r"retrofit2/|retrofit/", "cve": "CWE-295", "severity": "MEDIUM", "cvss": 5.3},
    {"name": "Volley < 1.2", "pattern": r"com/android/volley/", "cve": "CWE-295", "severity": "MEDIUM", "cvss": 5.3},
    {"name": "Log4j", "pattern": r"org/apache/logging/log4j/", "cve": "CVE-2021-44228", "severity": "CRITICAL", "cvss": 10.0},
    {"name": "Commons Collections < 3.2.2", "pattern": r"org/apache/commons/collections/", "cve": "CVE-2015-6420", "severity": "HIGH", "cvss": 7.5},
]

TRACKING_SDKS = {
    "com/google/firebase/analytics/": "Firebase Analytics",
    "com/google/android/gms/analytics/": "Google Analytics",
    "com/facebook/appevents/": "Facebook Analytics",
    "com/mixpanel/": "Mixpanel",
    "com/amplitude/": "Amplitude",
    "com/segment/": "Segment",
    "com/appsflyer/": "AppsFlyer",
    "com/adjust/": "Adjust SDK",
    "io/sentry/": "Sentry",
    "com/crashlytics/": "Crashlytics",
    "com/newrelic/": "New Relic",
    "com/onesignal/": "OneSignal",
    "com/braze/": "Braze",
}

SECURITY_CHECKS = {
    "isRooted": "Root detection",
    "isDeviceRooted": "Root detection",
    "RootBeer": "RootBeer library",
    "Superuser": "Superuser detection",
    "isDebuggerConnected": "Debugger detection",
    "TracerPid": "Anti-ptrace",
    "frida": "Frida detection",
    "xposed": "Xposed detection",
    "SafetyNet": "Google SafetyNet",
    "PlayIntegrity": "Play Integrity API",
    "isEmulator": "Emulator detection",
    "substrate": "Substrate detection",
}

# Taint analysis sources and sinks
TAINT_SOURCES = {
    "EditText->getText": "User Input (EditText)",
    "Intent->getData": "Intent Data (Deep Link)",
    "Intent->getStringExtra": "Intent Extra",
    "Intent->getExtras": "Intent Bundle",
    "SharedPreferences->getString": "SharedPreferences Read",
    "SQLiteDatabase->query": "Database Query Result",
    "SQLiteDatabase->rawQuery": "Raw Database Query",
    "ContentResolver->query": "ContentProvider Query",
    "WebView->getUrl": "WebView URL",
    "Location->getLatitude": "GPS Location",
    "Location->getLongitude": "GPS Location",
    "TelephonyManager->getDeviceId": "Device IMEI",
    "TelephonyManager->getLine1Number": "Phone Number",
    "AccountManager->getAccounts": "Device Accounts",
    "Cursor->getString": "Database Cursor",
    "BufferedReader->readLine": "File/Stream Read",
    "InputStream->read": "Stream Read",
    "ClipboardManager->getPrimaryClip": "Clipboard Data",
    "SmsMessage->getMessageBody": "SMS Content",
}

TAINT_SINKS = {
    "Log->d": "Debug Log",
    "Log->v": "Verbose Log",
    "Log->i": "Info Log",
    "Log->e": "Error Log",
    "Log->w": "Warning Log",
    "Runtime->exec": "System Command Execution",
    "ProcessBuilder-><init>": "Process Builder",
    "WebView->loadUrl": "WebView URL Load",
    "WebView->evaluateJavascript": "WebView JS Execution",
    "startActivity": "Activity Launch",
    "sendBroadcast": "Broadcast Send",
    "OutputStream->write": "Stream Write",
    "HttpURLConnection->getOutputStream": "HTTP Output",
    "URLConnection->getOutputStream": "URL Output",
    "Socket->getOutputStream": "Socket Output",
    "sendTextMessage": "SMS Send",
    "ContentResolver->insert": "ContentProvider Insert",
    "SQLiteDatabase->execSQL": "SQL Execution",
    "FileOutputStream-><init>": "File Write",
    "SharedPreferences.Editor->putString": "Prefs Write",
}

# Secret patterns
SECRET_PATTERNS: List[Tuple[str, str, str]] = [
    ("Google API Key", "HIGH", r"AIza[0-9A-Za-z_\-]{35}"),
    ("Google OAuth Token", "HIGH", r"ya29\.[0-9A-Za-z_\-]+"),
    ("Firebase URL", "MEDIUM", r"https?://[a-z0-9\-]+\.firebaseio\.com"),
    ("AWS Access Key", "CRITICAL", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA)[0-9A-Z]{16}\b"),
    ("AWS Secret Key", "CRITICAL", r"(?i)aws(.{0,20})?(secret|sk)[\"'\s:=]{1,5}[A-Za-z0-9/+=]{40}"),
    ("Slack Token", "HIGH", r"xox[abprs]-[0-9A-Za-z\-]{10,}"),
    ("GitHub Token", "CRITICAL", r"\bghp_[A-Za-z0-9]{36}\b"),
    ("Stripe Secret", "CRITICAL", r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    ("Twilio SID", "HIGH", r"\bAC[a-f0-9]{32}\b"),
    ("SendGrid Key", "HIGH", r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("PEM Private Key", "CRITICAL", r"-----BEGIN (?:RSA |EC |DSA )?PRIVATE KEY-----"),
    ("Basic Auth URL", "CRITICAL", r"https?://[^/\s:@]+:[^/\s:@]+@[A-Za-z0-9.\-]+"),
    ("Hardcoded Password", "HIGH", r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\'\s]{4,}["\']'),
    ("Hardcoded Secret", "HIGH", r'(?i)(?:secret|api[_\-]?key|apikey|client[_\-]?secret)\s*[:=]\s*["\'][A-Za-z0-9._\-]{8,}["\']'),
    ("JWT Token", "MEDIUM", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("Telegram Bot Token", "HIGH", r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
    ("Discord Token", "HIGH", r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}\b"),
    ("Mapbox Token", "MEDIUM", r"\bpk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ("Azure Key", "HIGH", r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
    ("Algolia Key", "MEDIUM", r"(?i)algolia.{0,20}[\"'\s:=]{1,5}[a-f0-9]{32}"),
    ("Mailgun Key", "HIGH", r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("Square Token", "HIGH", r"\bsq0atp-[0-9A-Za-z_\-]{22}\b"),
    ("PayPal Token", "HIGH", r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"),
    ("Heroku Key", "HIGH", r"(?i)heroku.{0,20}[\"'\s:=]{1,5}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
]

URL_PATTERN = re.compile(rb"https?://[A-Za-z0-9._\-:/?#\[\]@!$&'()*+,;=%~]+", re.IGNORECASE)
IP_PATTERN = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?::\d{2,5})?\b")

NOISE_HOSTS = (
    "schemas.android.com", "schemas.google.com", "www.w3.org",
    "ns.adobe.com", "play.google.com", "developer.android.com",
    "fonts.google.com", "fonts.gstatic.com",
)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.WRITE_SETTINGS",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
}

# Permission abuse combinations
PERMISSION_ABUSE_CHAINS = [
    {
        "permissions": ["android.permission.READ_SMS", "android.permission.INTERNET"],
        "chain": "READ_SMS + INTERNET = Can exfiltrate SMS messages to remote server",
        "severity": "CRITICAL",
        "impact": "2FA token theft, password reset interception",
    },
    {
        "permissions": ["android.permission.CAMERA", "android.permission.INTERNET"],
        "chain": "CAMERA + INTERNET = Can silently capture photos and upload them",
        "severity": "HIGH",
        "impact": "Surveillance, privacy violation",
    },
    {
        "permissions": ["android.permission.RECORD_AUDIO", "android.permission.INTERNET"],
        "chain": "RECORD_AUDIO + INTERNET = Can record ambient audio and exfiltrate",
        "severity": "CRITICAL",
        "impact": "Eavesdropping, corporate espionage",
    },
    {
        "permissions": ["android.permission.ACCESS_FINE_LOCATION", "android.permission.INTERNET"],
        "chain": "FINE_LOCATION + INTERNET = Real-time location tracking",
        "severity": "HIGH",
        "impact": "Stalking, movement profiling",
    },
    {
        "permissions": ["android.permission.READ_CONTACTS", "android.permission.INTERNET"],
        "chain": "READ_CONTACTS + INTERNET = Contact list exfiltration",
        "severity": "HIGH",
        "impact": "Social engineering, spam, identity mapping",
    },
    {
        "permissions": ["android.permission.READ_CALL_LOG", "android.permission.INTERNET"],
        "chain": "READ_CALL_LOG + INTERNET = Call history exfiltration",
        "severity": "HIGH",
        "impact": "Behavioral profiling, blackmail",
    },
    {
        "permissions": ["android.permission.SYSTEM_ALERT_WINDOW", "android.permission.BIND_ACCESSIBILITY_SERVICE"],
        "chain": "SYSTEM_ALERT_WINDOW + ACCESSIBILITY = Overlay + keylogging (banking trojan pattern)",
        "severity": "CRITICAL",
        "impact": "Credential theft, transaction manipulation",
    },
    {
        "permissions": ["android.permission.REQUEST_INSTALL_PACKAGES", "android.permission.INTERNET"],
        "chain": "INSTALL_PACKAGES + INTERNET = Can download and install arbitrary APKs",
        "severity": "CRITICAL",
        "impact": "Malware dropper, device compromise",
    },
    {
        "permissions": ["android.permission.SEND_SMS", "android.permission.RECEIVE_SMS"],
        "chain": "SEND_SMS + RECEIVE_SMS = Premium SMS fraud, intercepting OTP",
        "severity": "CRITICAL",
        "impact": "Financial fraud, account takeover",
    },
    {
        "permissions": ["android.permission.WRITE_EXTERNAL_STORAGE", "android.permission.INTERNET"],
        "chain": "WRITE_STORAGE + INTERNET = Can download malicious files to shared storage",
        "severity": "MEDIUM",
        "impact": "Media injection, document replacement",
    },
]



# ===========================================================================
# AXML (Binary Android Manifest) PARSER
# ===========================================================================

def parse_axml_strings(data: bytes) -> List[str]:
    """Extract all strings from binary AXML."""
    if len(data) < 8 or data[:4] != b"\x03\x00\x08\x00":
        return []
    pos = 8
    if pos + 24 > len(data):
        return []
    chunk_type = int.from_bytes(data[pos:pos+2], "little")
    if chunk_type != 0x0001:
        return []
    header_size = int.from_bytes(data[pos+2:pos+4], "little")
    string_count = int.from_bytes(data[pos+8:pos+12], "little")
    flags = int.from_bytes(data[pos+16:pos+20], "little")
    strings_start = int.from_bytes(data[pos+20:pos+24], "little")
    is_utf8 = bool(flags & (1 << 8))
    offsets_base = pos + header_size
    strings_base = pos + strings_start
    out: List[str] = []
    for i in range(string_count):
        off_pos = offsets_base + i * 4
        if off_pos + 4 > len(data):
            break
        rel = int.from_bytes(data[off_pos:off_pos+4], "little")
        sp = strings_base + rel
        if sp >= len(data):
            continue
        try:
            if is_utf8:
                p = sp
                if p < len(data) and data[p] & 0x80:
                    p += 2
                else:
                    p += 1
                if p < len(data) and data[p] & 0x80:
                    bl = ((data[p] & 0x7F) << 8) | data[p+1]
                    p += 2
                else:
                    bl = data[p] if p < len(data) else 0
                    p += 1
                s = data[p:p+bl].decode("utf-8", errors="replace")
            else:
                p = sp
                cl = int.from_bytes(data[p:p+2], "little")
                if cl & 0x8000:
                    cl = ((cl & 0x7FFF) << 16) | int.from_bytes(data[p+2:p+4], "little")
                    p += 4
                else:
                    p += 2
                s = data[p:p+cl*2].decode("utf-16-le", errors="replace")
            out.append(s)
        except Exception:
            continue
    return out


# ===========================================================================
# STRING EXTRACTORS
# ===========================================================================

def extract_ascii_strings(buf: bytes, min_len: int = 6) -> Iterator[str]:
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for m in pat.finditer(buf):
        try:
            yield m.group(0).decode("ascii", errors="ignore")
        except Exception:
            continue


def extract_utf16le_strings(buf: bytes, min_len: int = 6) -> Iterator[str]:
    pat = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    for m in pat.finditer(buf):
        try:
            yield m.group(0).decode("utf-16-le", errors="ignore")
        except Exception:
            continue


# ===========================================================================
# NATIVE LIBRARY (.so) SCANNER
# ===========================================================================

class NativeLibScanner:
    """Scan ELF binaries for strings, JNI methods, hardcoded data."""

    ELF_MAGIC = b"\x7fELF"

    def __init__(self, data: bytes, filename: str):
        self.data = data
        self.filename = filename
        self.strings: List[str] = []
        self.jni_methods: List[str] = []
        self.urls: List[str] = []
        self.suspicious: List[str] = []

    def scan(self) -> Dict:
        if not self.data.startswith(self.ELF_MAGIC):
            return {}

        # Extract all printable strings (min 8 chars for native)
        for s in extract_ascii_strings(self.data, 8):
            self.strings.append(s)
            # JNI method detection
            if s.startswith("Java_"):
                self.jni_methods.append(s)
            # URL detection
            if s.startswith("http://") or s.startswith("https://"):
                if not any(n in s for n in NOISE_HOSTS):
                    self.urls.append(s)
            # Suspicious patterns
            if any(kw in s.lower() for kw in ["password", "secret", "api_key", "token",
                                               "encrypt", "decrypt", "cipher", "/bin/sh",
                                               "su", "system(", "exec("]):
                self.suspicious.append(s)

        return {
            "filename": self.filename,
            "arch": self._detect_arch(),
            "total_strings": len(self.strings),
            "jni_methods": self.jni_methods[:50],
            "urls": self.urls[:30],
            "suspicious_strings": self.suspicious[:30],
        }

    def _detect_arch(self) -> str:
        if len(self.data) < 19:
            return "unknown"
        # ELF e_machine field at offset 18
        machine = struct.unpack_from('<H', self.data, 18)[0]
        archs = {3: "x86", 40: "ARM", 62: "x86_64", 183: "ARM64/AArch64"}
        return archs.get(machine, f"unknown({machine})")


# ===========================================================================
# MAIN SCANNER CLASS
# ===========================================================================

class APKEliteAnalyzer:
    """Elite APK security analyzer with bytecode disassembly and attack chain building."""

    def __init__(self, apk_path: str, output_dir: str = None, min_str_len: int = 6):
        self.apk_path = apk_path
        self.output_dir = output_dir or os.path.splitext(apk_path)[0] + "_report"
        self.min_str_len = min_str_len
        self.report = Report(
            apk_path=apk_path,
            apk_size=os.path.getsize(apk_path),
            apk_md5=self._hash("md5"),
            apk_sha256=self._hash("sha256"),
            scan_time=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        )
        self._compiled_secrets = [(n, s, re.compile(p)) for n, s, p in SECRET_PATTERNS]
        self._seen: Set[str] = set()
        self._all_dex_strings: Set[str] = set()
        self._all_class_names: Set[str] = set()
        self._all_method_refs: Set[str] = set()
        self._all_field_refs: Set[str] = set()
        self._dex_parsers: List[DexParser] = []
        self._start_time = time.time()
        self._chain_counter = 0

    def _hash(self, algo: str) -> str:
        h = hashlib.new(algo)
        with open(self.apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    # ------------------------------------------------------------------
    # PUBLIC API
    # ------------------------------------------------------------------
    def analyze(self) -> Report:
        """Run full elite analysis."""
        with zipfile.ZipFile(self.apk_path, "r") as z:
            names = z.namelist()

            # 1. Parse AndroidManifest.xml
            if "AndroidManifest.xml" in names:
                self._analyze_manifest(z.read("AndroidManifest.xml"))

            # 2. Deep parse DEX files with bytecode disassembly
            for n in sorted(names):
                if n.startswith("classes") and n.endswith(".dex"):
                    self._analyze_dex(z.read(n), n)

            # 3. Scan native libraries
            for n in names:
                if n.endswith(".so") and "/lib/" in n:
                    try:
                        self._analyze_native_lib(z.read(n), n)
                    except Exception:
                        pass

            # 4. Certificate
            self._extract_cert_info(z, names)

            # 5. Resource scanning
            for n in names:
                if n == "AndroidManifest.xml" or (n.startswith("classes") and n.endswith(".dex")):
                    continue
                if n.endswith(".so"):
                    continue
                lower = n.lower()
                if (lower.endswith((".xml", ".json", ".txt", ".properties", ".js",
                                    ".html", ".htm", ".cfg", ".conf", ".yml", ".yaml",
                                    ".pem", ".key", ".cer", ".crt"))
                    or lower.startswith("assets/") or lower.startswith("res/raw/")):
                    try:
                        self._scan_resource_blob(z.read(n), n)
                    except Exception:
                        continue

        # 6. Run vulnerability detection with cross-referencing
        self._detect_vulnerabilities_with_xrefs()

        # 7. Detect libraries
        self._detect_vulnerable_libraries()

        # 8. Detect SDKs and security checks
        self._detect_tracking_sdks()
        self._detect_security_checks()

        # 9. Taint analysis
        self._run_taint_analysis()

        # 10. Build attack chains
        self._build_attack_chains()

        # 11. Permission abuse analysis
        self._analyze_permission_abuse()

        # 12. Deep crypto analysis
        self._deep_crypto_analysis()

        # 13. Deep link analysis
        self._analyze_deep_links()

        # 14. Obfuscation detection
        self._detect_obfuscation()

        # 15. Finalize
        self.report.scan_duration = round(time.time() - self._start_time, 2)
        self._build_call_graph_stats()
        self._build_summary()

        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.report.findings.sort(key=lambda x: (sev_order.get(x.severity, 9), x.category))

        return self.report

    # ------------------------------------------------------------------
    # MANIFEST ANALYSIS
    # ------------------------------------------------------------------
    def _analyze_manifest(self, data: bytes):
        strings = parse_axml_strings(data)
        joined = "\n".join(strings)

        perms = sorted({s for s in strings if "permission." in s and "." in s})
        self.report.permissions = perms
        self.report.dangerous_permissions = sorted(set(perms) & DANGEROUS_PERMISSIONS)

        if "usesCleartextTraffic" in joined:
            self.report.uses_cleartext = True
        if "debuggable" in joined:
            self.report.debuggable = True
        if "allowBackup" in joined:
            self.report.allow_backup = True

        # Extract components with intent-filters
        self._extract_components(strings)

        # Scan for secrets
        for s in strings:
            self._scan_string_for_secrets(s, "AndroidManifest.xml")

        # Findings for dangerous permissions
        for p in self.report.dangerous_permissions:
            self._add_finding(Finding(
                category="manifest", severity="MEDIUM",
                name="Dangerous Permission", description=f"Requests: {p}",
                value=p, source_file="AndroidManifest.xml",
                cve_cwe="CWE-250", cvss=4.3,
                remediation="Verify necessity; request at runtime.",
                confidence="high",
            ))

        if self.report.debuggable:
            self._add_finding(Finding(
                category="manifest", severity="HIGH",
                name="Debuggable Application",
                description="android:debuggable allows attaching debugger to running app.",
                value="android:debuggable=true",
                source_file="AndroidManifest.xml",
                cve_cwe="CWE-489", cvss=7.5,
                remediation="Set android:debuggable='false' for production.",
                confidence="high",
                adb_command="adb shell run-as <package> cat /data/data/<package>/shared_prefs/*.xml",
            ))

        if self.report.allow_backup:
            self._add_finding(Finding(
                category="manifest", severity="MEDIUM",
                name="Backup Allowed",
                description="adb backup can extract all app data without root.",
                value="android:allowBackup=true",
                source_file="AndroidManifest.xml",
                cve_cwe="CWE-921", cvss=5.3,
                remediation="Set allowBackup='false' or implement encrypted BackupAgent.",
                confidence="high",
                adb_command="adb backup -apk -shared <package> && dd if=backup.ab bs=24 skip=1 | openssl zlib -d | tar xf -",
            ))

    def _extract_components(self, strings: List[str]):
        """Extract Android components from manifest strings."""
        components = []
        exported_names = []

        for s in strings:
            s_strip = s.strip()
            # Detect component class names
            if (s_strip.startswith(".") or
                ("Activity" in s_strip or "Service" in s_strip or
                 "Receiver" in s_strip or "Provider" in s_strip)):
                if any(c.isupper() for c in s_strip):
                    comp_type = "activity"
                    if "Service" in s_strip:
                        comp_type = "service"
                    elif "Receiver" in s_strip:
                        comp_type = "receiver"
                    elif "Provider" in s_strip:
                        comp_type = "provider"
                    ci = ComponentInfo(
                        component_type=comp_type,
                        name=s_strip,
                        exported=True,  # Heuristic: if has intent-filter, likely exported
                    )
                    components.append(ci)
                    exported_names.append(s_strip)

        # Extract deep link schemes
        schemes = []
        hosts = []
        for s in strings:
            if s in ("http", "https", "content", "file"):
                continue
            # Detect custom schemes (short, lowercase, no dots)
            if (len(s) > 2 and len(s) < 20 and s.isalpha() and s.islower()
                and s not in ("activity", "service", "receiver", "provider",
                             "intent", "action", "category", "data", "name",
                             "exported", "enabled", "permission", "true", "false")):
                schemes.append(s)
            # Detect hosts
            if "." in s and not s.startswith("android.") and not s.startswith("com.android"):
                if re.match(r'^[a-z0-9\-]+\.[a-z]{2,}', s):
                    hosts.append(s)

        self.report.components = components[:100]
        self.report.exported_components = exported_names[:50]

        # Store deep link info
        for scheme in schemes[:20]:
            self.report.deep_links.append({
                "scheme": scheme,
                "hosts": hosts[:5],
                "test_url": f"{scheme}://evil.com/payload",
            })

    # ------------------------------------------------------------------
    # DEX DEEP ANALYSIS
    # ------------------------------------------------------------------
    def _analyze_dex(self, data: bytes, filename: str):
        parser = DexParser(data)
        if not parser.parse():
            self._scan_resource_blob(data, filename)
            return

        self._dex_parsers.append(parser)

        java_classes = parser.get_java_class_names()
        obfuscated_count = sum(1 for c in java_classes if parser.is_obfuscated(c))

        dex_info = DexInfo(
            filename=filename,
            class_count=len(parser.class_defs),
            method_count=len(parser.method_table),
            field_count=len(parser.field_table),
            string_count=len(parser.string_table),
            obfuscated_class_count=obfuscated_count,
            total_class_count=len(java_classes),
            methods_with_code=len(parser.method_codes),
        )
        self.report.dex_info.append(dex_info)

        self._all_class_names.update(parser.class_names)
        self._all_method_refs.update(parser.full_method_refs)
        self._all_field_refs.update(parser.full_field_refs)
        self._all_dex_strings.update(parser.string_table)

        for s in parser.string_table:
            if len(s) >= self.min_str_len:
                self._scan_string_for_secrets(s, filename)

        self._extract_urls_ips(data, filename)

    # ------------------------------------------------------------------
    # NATIVE LIBRARY ANALYSIS
    # ------------------------------------------------------------------
    def _analyze_native_lib(self, data: bytes, filename: str):
        scanner = NativeLibScanner(data, filename)
        result = scanner.scan()
        if result:
            self.report.native_libs.append(result)
            # Check for hardcoded secrets in native code
            for s in scanner.suspicious:
                self._add_finding(Finding(
                    category="native", severity="MEDIUM",
                    name="Suspicious Native String",
                    description=f"Potentially sensitive string in native library: {filename}",
                    value=s[:200], source_file=filename,
                    confidence="low",
                ))
            for url in scanner.urls:
                sev = "MEDIUM" if url.startswith("http://") else "LOW"
                self._add_finding(Finding(
                    category="native", severity=sev,
                    name="URL in Native Library",
                    description=f"Hardcoded URL in native code: {filename}",
                    value=url[:200], source_file=filename,
                    cve_cwe="CWE-319" if sev == "MEDIUM" else "",
                    cvss=5.9 if sev == "MEDIUM" else 2.0,
                    confidence="high" if sev == "MEDIUM" else "low",
                ))



    # ------------------------------------------------------------------
    # VULNERABILITY DETECTION WITH CROSS-REFERENCES
    # ------------------------------------------------------------------
    def _detect_vulnerabilities_with_xrefs(self):
        """Detect vulnerabilities with full cross-reference chains."""
        for pattern in VULN_PATTERNS:
            matches = []
            match_context = []

            for cp in pattern.class_patterns:
                for cn in self._all_class_names:
                    if cp in cn:
                        matches.append(f"class:{cn}")

            for mp in pattern.method_patterns:
                for mr in self._all_method_refs:
                    if mp in mr:
                        matches.append(f"method:{mr}")
                        # Cross-reference: who calls this method?
                        for dp in self._dex_parsers:
                            callers = dp.get_method_callers(mp)
                            for caller in list(callers)[:5]:
                                match_context.append(f"Called by: {caller}")

            for sp in pattern.string_patterns:
                for ds in self._all_dex_strings:
                    if sp in ds:
                        matches.append(f"string:{ds[:100]}")
                        # Cross-reference: which methods use this string?
                        for dp in self._dex_parsers:
                            users = dp.get_string_users(sp)
                            for user in list(users)[:5]:
                                match_context.append(f"String '{sp}' used in: {user}")
                        break

            for fp in pattern.field_patterns:
                for fr in self._all_field_refs:
                    if fp in fr:
                        matches.append(f"field:{fr}")

            if matches:
                affected_class = ""
                affected_method = ""
                for m in matches:
                    if m.startswith("method:"):
                        parts = m[7:].split("->")
                        if len(parts) == 2:
                            affected_class = parts[0]
                            affected_method = parts[1]
                            break
                    elif m.startswith("class:"):
                        affected_class = m[6:]

                # Build context string with xrefs
                context_str = "\n".join(match_context[:10])

                self._add_finding(Finding(
                    category="vulnerability",
                    severity=pattern.severity,
                    name=pattern.name,
                    description=pattern.description,
                    value="; ".join(matches[:5]),
                    source_file="DEX bytecode",
                    cve_cwe=pattern.cve_cwe,
                    cvss=pattern.cvss,
                    affected_class=affected_class,
                    affected_method=affected_method,
                    remediation=pattern.remediation,
                    confidence=pattern.confidence,
                    context=context_str,
                    exploit_info=pattern.exploit_info,
                    frida_hook=pattern.frida_template,
                ))

    # ------------------------------------------------------------------
    # VULNERABLE LIBRARY DETECTION
    # ------------------------------------------------------------------
    def _detect_vulnerable_libraries(self):
        all_types = self._all_class_names.copy()
        for dp in self._dex_parsers:
            all_types.update(dp.type_table)
        all_searchable = all_types | self._all_dex_strings

        for lib in VULN_LIBRARIES:
            regex = re.compile(lib["pattern"])
            found = any(regex.search(item) for item in all_searchable)
            if found:
                self.report.detected_libraries.append(lib["name"])
                self._add_finding(Finding(
                    category="library", severity=lib["severity"],
                    name=f"Vulnerable Library: {lib['name']}",
                    description=f"Detected potentially vulnerable library: {lib['name']}",
                    value=f"Pattern: {lib['pattern']}",
                    source_file="DEX type table",
                    cve_cwe=lib["cve"], cvss=lib["cvss"],
                    remediation=f"Update {lib['name']} to latest secure version.",
                    confidence="medium",
                ))

    # ------------------------------------------------------------------
    # TRACKING AND SECURITY
    # ------------------------------------------------------------------
    def _detect_tracking_sdks(self):
        all_searchable = self._all_class_names | self._all_dex_strings
        for dp in self._dex_parsers:
            all_searchable.update(dp.type_table)
        for pat, sdk_name in TRACKING_SDKS.items():
            if any(pat in item for item in all_searchable):
                if sdk_name not in self.report.tracking_sdks:
                    self.report.tracking_sdks.append(sdk_name)

    def _detect_security_checks(self):
        for pattern, check_name in SECURITY_CHECKS.items():
            found = any(pattern.lower() in s.lower() for s in self._all_dex_strings)
            if not found:
                found = any(pattern in mr for mr in self._all_method_refs)
            if found and check_name not in self.report.security_checks:
                self.report.security_checks.append(check_name)

    # ------------------------------------------------------------------
    # TAINT ANALYSIS
    # ------------------------------------------------------------------
    def _run_taint_analysis(self):
        """Simplified taint analysis: find paths from sources to sinks."""
        for dp in self._dex_parsers:
            # Find methods that call taint sources
            source_methods: Dict[str, str] = {}  # method -> source_type
            for source_pattern, source_desc in TAINT_SOURCES.items():
                for method_name, callees in dp.call_graph.items():
                    for callee in callees:
                        if source_pattern in callee:
                            source_methods[method_name] = source_desc

            # Find methods that call taint sinks
            sink_methods: Dict[str, str] = {}  # method -> sink_type
            for sink_pattern, sink_desc in TAINT_SINKS.items():
                for method_name, callees in dp.call_graph.items():
                    for callee in callees:
                        if sink_pattern in callee:
                            sink_methods[method_name] = sink_desc

            # Check for direct source->sink in same method (intra-procedural)
            for src_method, src_type in source_methods.items():
                if src_method in sink_methods:
                    sink_type = sink_methods[src_method]
                    tp = TaintPath(
                        source_method=src_method,
                        source_type=src_type,
                        sink_method=src_method,
                        sink_type=sink_type,
                        path=[src_method],
                        data_description=f"{src_type} flows to {sink_type} in same method",
                    )
                    self.report.taint_paths.append(tp)

            # Inter-procedural: source method calls sink method (1-hop)
            for src_method, src_type in source_methods.items():
                for callee in dp.call_graph.get(src_method, set()):
                    if callee in sink_methods:
                        sink_type = sink_methods[callee]
                        tp = TaintPath(
                            source_method=src_method,
                            source_type=src_type,
                            sink_method=callee,
                            sink_type=sink_type,
                            path=[src_method, callee],
                            data_description=f"{src_type} passed to {sink_type}",
                        )
                        self.report.taint_paths.append(tp)

            # Find paths from source callers to sink callers (max 4 hops)
            for src_method, src_type in list(source_methods.items())[:50]:
                for sink_method, sink_type in list(sink_methods.items())[:50]:
                    if src_method == sink_method:
                        continue
                    path = dp.find_path(src_method, sink_method, max_depth=4)
                    if path and len(path) > 1:
                        tp = TaintPath(
                            source_method=src_method,
                            source_type=src_type,
                            sink_method=sink_method,
                            sink_type=sink_type,
                            path=path,
                            data_description=f"{src_type} -> {len(path)-1} hops -> {sink_type}",
                        )
                        self.report.taint_paths.append(tp)

        # Deduplicate taint paths
        seen_paths = set()
        unique_paths = []
        for tp in self.report.taint_paths:
            key = f"{tp.source_method}|{tp.sink_method}"
            if key not in seen_paths:
                seen_paths.add(key)
                unique_paths.append(tp)
        self.report.taint_paths = unique_paths[:100]

        # Create findings for critical taint paths
        for tp in self.report.taint_paths[:30]:
            severity = "HIGH"
            if "Command Execution" in tp.sink_type or "SMS Send" in tp.sink_type:
                severity = "CRITICAL"
            elif "Log" in tp.sink_type:
                severity = "MEDIUM"

            self._add_finding(Finding(
                category="taint",
                severity=severity,
                name=f"Data Flow: {tp.source_type} -> {tp.sink_type}",
                description=f"Sensitive data ({tp.source_type}) flows to dangerous sink ({tp.sink_type}) through {len(tp.path)} method(s).",
                value=f"Path: {' -> '.join(tp.path[:5])}",
                source_file="DEX bytecode (taint analysis)",
                cve_cwe="CWE-200",
                cvss=7.5 if severity == "HIGH" else 9.0 if severity == "CRITICAL" else 5.0,
                affected_method=tp.source_method,
                remediation=f"Sanitize {tp.source_type} before passing to {tp.sink_type}.",
                confidence="medium",
            ))

    # ------------------------------------------------------------------
    # ATTACK CHAIN BUILDER
    # ------------------------------------------------------------------
    def _build_attack_chains(self):
        """Build complete attack chains from findings."""
        # Chain 1: SSL/TLS bypass chain
        ssl_findings = [f for f in self.report.findings
                       if "SSL" in f.name or "Trust" in f.name or "Certificate" in f.name
                       or "Hostname" in f.name]
        if ssl_findings:
            self._chain_counter += 1
            steps = [
                "Attacker connects to same WiFi network as victim",
                "Run ARP spoofing: arpspoof -i wlan0 -t <victim_ip> <gateway_ip>",
                f"App disables certificate validation ({ssl_findings[0].name})",
                "All HTTPS traffic now passes through attacker's proxy",
                "Capture credentials, tokens, and sensitive data",
                "Replay captured tokens for account takeover",
            ]
            chain = AttackChain(
                chain_id=self._chain_counter,
                title="Insecure TLS: Full Traffic Interception",
                severity="CRITICAL",
                entry_point=ssl_findings[0].affected_class or "Network layer",
                steps=steps,
                cwe="CWE-295",
                cvss=9.1,
                risk_description="Complete loss of transport security. All data in transit can be read and modified.",
                impact="Account takeover, credential theft, session hijacking, data manipulation",
                exploit_difficulty="Easy",
                exploit_steps=[
                    "1. Install mitmproxy on attacker machine",
                    "2. Connect to same WiFi as target device",
                    "3. Run: arpspoof -i wlan0 -t TARGET_IP GATEWAY_IP",
                    "4. Start mitmproxy: mitmproxy --mode transparent --listen-port 8080",
                    "5. Route traffic: iptables -t nat -A PREROUTING -p tcp --dport 443 -j REDIRECT --to-port 8080",
                    "6. All app traffic is now visible in mitmproxy",
                ],
                tools=["mitmproxy", "arpspoof (dsniff)", "Burp Suite", "iptables"],
                poc_template="## SSL/TLS Bypass - MITM\n\n**Impact:** All HTTPS traffic can be intercepted\n**Steps to reproduce:**\n1. Connect to same network\n2. ARP spoof victim\n3. Run mitmproxy\n4. Observe decrypted traffic\n\n**Evidence:** Certificate validation is disabled in the app.",
            )
            self.report.attack_chains.append(chain)

        # Chain 2: Exported component exploitation
        exported = [c for c in self.report.components if c.exported]
        if exported:
            self._chain_counter += 1
            comp = exported[0]
            chain = AttackChain(
                chain_id=self._chain_counter,
                title=f"Exported Component Abuse: {comp.name}",
                severity="HIGH",
                entry_point=comp.name,
                steps=[
                    f"Identify exported {comp.component_type}: {comp.name}",
                    "Craft malicious intent with manipulated extras",
                    "Launch component from attacker app or ADB",
                    "Trigger unintended behavior / access protected functionality",
                ],
                cwe="CWE-926",
                cvss=7.5,
                risk_description="Exported components can be triggered by any app on the device.",
                impact="Unauthorized access, data leak, privilege escalation",
                exploit_difficulty="Easy",
                exploit_steps=[
                    f"adb shell am start -n <package>/{comp.name}",
                    f"adb shell am start -n <package>/{comp.name} -d 'content://evil'",
                    f"adb shell am start -n <package>/{comp.name} --es 'url' 'http://evil.com'",
                ],
                tools=["adb", "drozer", "custom Android app"],
                adb_command=f"adb shell am start -n <package>/{comp.name}",
            )
            self.report.attack_chains.append(chain)

        # Chain 3: Crypto weakness exploitation
        crypto_findings = [f for f in self.report.findings
                         if f.category == "vulnerability" and "CRYPTO" in f.cve_cwe.upper()
                         or "Cipher" in f.name or "Key" in f.name or "ECB" in f.name
                         or "DES" in f.name]
        if crypto_findings:
            self._chain_counter += 1
            cf = crypto_findings[0]
            chain = AttackChain(
                chain_id=self._chain_counter,
                title=f"Weak Cryptography: {cf.name}",
                severity=cf.severity,
                entry_point=cf.affected_class or "Crypto implementation",
                steps=[
                    "Extract APK and decompile (apktool d app.apk)",
                    f"Identify weak crypto: {cf.name}",
                    "Extract hardcoded keys from DEX strings/bytecode",
                    "Decrypt stored data using extracted key + identified algorithm",
                    "Access sensitive data (tokens, credentials, PII)",
                ],
                cwe=cf.cve_cwe,
                cvss=cf.cvss,
                risk_description="Weak cryptography can be broken, exposing all protected data.",
                impact="Data breach, credential exposure, PII leak",
                exploit_difficulty="Medium",
                tools=["apktool", "jadx", "CyberChef", "Python (pycryptodome)"],
                poc_template=f"## Weak Cryptography - {cf.name}\n\n**Algorithm:** {cf.value[:80]}\n**Impact:** Protected data can be decrypted\n**Steps:**\n1. Extract APK\n2. Find crypto implementation\n3. Extract key material\n4. Decrypt stored data",
            )
            self.report.attack_chains.append(chain)

        # Chain 4: Data injection via deep links
        if self.report.deep_links:
            self._chain_counter += 1
            dl = self.report.deep_links[0]
            chain = AttackChain(
                chain_id=self._chain_counter,
                title="Deep Link Injection",
                severity="MEDIUM",
                entry_point=f"URI scheme: {dl['scheme']}://",
                steps=[
                    f"Identify deep link scheme: {dl['scheme']}://",
                    "Craft malicious URL with injected parameters",
                    "Send to victim via SMS/email/social engineering",
                    "App processes attacker-controlled data without validation",
                    "Potential: XSS in WebView, open redirect, IDOR",
                ],
                cwe="CWE-939",
                cvss=5.3,
                risk_description="Deep links accept arbitrary input that may not be validated.",
                impact="Phishing, data injection, unauthorized actions",
                exploit_difficulty="Easy",
                adb_command=f"adb shell am start -a android.intent.action.VIEW -d \"{dl['scheme']}://evil.com/payload\"",
                tools=["adb", "custom HTML page", "SMS"],
            )
            self.report.attack_chains.append(chain)

        # Chain 5: Taint-based chains
        critical_taints = [t for t in self.report.taint_paths
                          if "Command" in t.sink_type or "SMS" in t.sink_type]
        for tp in critical_taints[:3]:
            self._chain_counter += 1
            chain = AttackChain(
                chain_id=self._chain_counter,
                title=f"Taint: {tp.source_type} -> {tp.sink_type}",
                severity="CRITICAL",
                entry_point=tp.source_method,
                steps=[
                    f"Data enters from: {tp.source_type} ({tp.source_method})",
                    f"Flows through: {' -> '.join(tp.path[1:-1]) if len(tp.path) > 2 else 'direct'}",
                    f"Reaches dangerous sink: {tp.sink_type} ({tp.sink_method})",
                    "Attacker controls source, can inject malicious payload",
                ],
                cwe="CWE-78" if "Command" in tp.sink_type else "CWE-200",
                cvss=9.8 if "Command" in tp.sink_type else 7.5,
                risk_description=f"User-controlled input from {tp.source_type} reaches {tp.sink_type} without sanitization.",
                impact="Remote code execution" if "Command" in tp.sink_type else "Data exfiltration",
                exploit_difficulty="Medium",
            )
            self.report.attack_chains.append(chain)

    # ------------------------------------------------------------------
    # PERMISSION ABUSE ANALYSIS
    # ------------------------------------------------------------------
    def _analyze_permission_abuse(self):
        app_perms = set(self.report.permissions)
        for chain_def in PERMISSION_ABUSE_CHAINS:
            if all(p in app_perms for p in chain_def["permissions"]):
                self.report.permission_abuse_chains.append(chain_def)
                self._add_finding(Finding(
                    category="permission_abuse",
                    severity=chain_def["severity"],
                    name="Permission Abuse Chain",
                    description=chain_def["chain"],
                    value=" + ".join(chain_def["permissions"]),
                    source_file="AndroidManifest.xml",
                    cve_cwe="CWE-250",
                    cvss=8.0 if chain_def["severity"] == "CRITICAL" else 6.0,
                    remediation="Remove unnecessary permissions or justify their combination.",
                    confidence="high",
                    context=f"Impact: {chain_def['impact']}",
                ))

    # ------------------------------------------------------------------
    # DEEP CRYPTO ANALYSIS
    # ------------------------------------------------------------------
    def _deep_crypto_analysis(self):
        """Analyze cryptographic implementations in detail."""
        for dp in self._dex_parsers:
            for mc in dp.method_codes:
                cipher_calls = []
                key_specs = []
                iv_specs = []
                digest_calls = []
                string_args = {}  # register -> string value (simplified)

                for insn in mc.instructions:
                    # Track const-string -> register mapping
                    if insn.op_name == "const-string" and insn.dest_reg >= 0:
                        string_args[insn.dest_reg] = insn.string_val

                    # Detect Cipher.getInstance calls with algorithm argument
                    if insn.method_ref and "Cipher->getInstance" in insn.method_ref:
                        # Look for preceding const-string that provides the algorithm
                        algo = self._find_preceding_string(mc.instructions, insn.offset)
                        cipher_calls.append({
                            "method": mc.full_name,
                            "algorithm": algo or "unknown",
                        })
                        if algo:
                            issues = []
                            if "ECB" in algo:
                                issues.append("ECB mode (no semantic security)")
                            if "DES" in algo and "AES" not in algo:
                                issues.append("Weak cipher (DES)")
                            if "NoPadding" in algo and "GCM" not in algo:
                                issues.append("No padding (potential padding oracle)")
                            if "PKCS5Padding" in algo and "CBC" in algo:
                                issues.append("CBC+PKCS5 (vulnerable to padding oracle)")
                            if issues:
                                self._add_finding(Finding(
                                    category="crypto_deep",
                                    severity="HIGH",
                                    name=f"Insecure Cipher: {algo}",
                                    description=f"Cipher.getInstance('{algo}') in {mc.full_name}: {', '.join(issues)}",
                                    value=algo,
                                    source_file="DEX bytecode",
                                    cve_cwe="CWE-327",
                                    cvss=7.5,
                                    affected_class=mc.class_name,
                                    affected_method=mc.method_name,
                                    remediation="Use AES/GCM/NoPadding (AES-GCM) or ChaCha20-Poly1305.",
                                    confidence="high",
                                    context=f"Method: {mc.full_name}\nAlgorithm: {algo}\nIssues: {', '.join(issues)}",
                                ))

                    # Detect MessageDigest.getInstance
                    if insn.method_ref and "MessageDigest->getInstance" in insn.method_ref:
                        algo = self._find_preceding_string(mc.instructions, insn.offset)
                        if algo and algo.upper() in ("MD5", "SHA-1", "SHA1"):
                            digest_calls.append({"method": mc.full_name, "algorithm": algo})

                    # Detect SecretKeySpec
                    if insn.method_ref and "SecretKeySpec-><init>" in insn.method_ref:
                        key_specs.append(mc.full_name)

                    # Detect IvParameterSpec
                    if insn.method_ref and "IvParameterSpec-><init>" in insn.method_ref:
                        iv_specs.append(mc.full_name)

    def _find_preceding_string(self, instructions: List[DecodedInsn], target_offset: int) -> str:
        """Find the most recent const-string before a given offset."""
        best = ""
        for insn in instructions:
            if insn.offset >= target_offset:
                break
            if insn.string_val and insn.op_name in ("const-string", "const-string/jumbo"):
                best = insn.string_val
        return best

    # ------------------------------------------------------------------
    # DEEP LINK ANALYSIS
    # ------------------------------------------------------------------
    def _analyze_deep_links(self):
        """Analyze deep link handlers for vulnerabilities."""
        for dl in self.report.deep_links:
            scheme = dl["scheme"]
            # Generate test commands
            test_urls = [
                f"{scheme}://evil.com/steal",
                f"{scheme}://localhost/admin",
                f"{scheme}://..%2f..%2fetc%2fpasswd",
                f"{scheme}://<script>alert(1)</script>",
                f"{scheme}://callback?token=INJECTED",
            ]
            dl["test_urls"] = test_urls

            self._add_finding(Finding(
                category="deep_link",
                severity="MEDIUM",
                name=f"Deep Link Scheme: {scheme}://",
                description=f"App registers custom URI scheme '{scheme}://' which can be triggered by any app.",
                value=f"Scheme: {scheme}://",
                source_file="AndroidManifest.xml",
                cve_cwe="CWE-939",
                cvss=5.3,
                remediation="Validate all parameters from deep links. Use App Links for verified domains.",
                confidence="medium",
                adb_command=f"adb shell am start -a android.intent.action.VIEW -d \"{scheme}://test/path?param=value\"",
            ))

    # ------------------------------------------------------------------
    # OBFUSCATION DETECTION
    # ------------------------------------------------------------------
    def _detect_obfuscation(self):
        """Detect obfuscation level and identify tool used."""
        if not self._dex_parsers:
            return

        total_classes = 0
        obf_classes = 0
        indicators = defaultdict(int)

        for dp in self._dex_parsers:
            java_names = dp.get_java_class_names()
            total_classes += len(java_names)
            for name in java_names:
                if dp.is_obfuscated(name):
                    obf_classes += 1

            # Check for obfuscation tool signatures
            for s in dp.string_table:
                if "proguard" in s.lower() or "r8" in s.lower():
                    indicators["ProGuard/R8"] += 1
                if "dexguard" in s.lower():
                    indicators["DexGuard"] += 1
                if "ixguard" in s.lower():
                    indicators["iXGuard"] += 1
                if "allatori" in s.lower():
                    indicators["Allatori"] += 1
                if "zelix" in s.lower():
                    indicators["Zelix KlassMaster"] += 1

            # Check for string encryption patterns (XOR loops, base64+AES)
            for mc in dp.method_codes:
                # String decryption heuristic: method with many const-string + XOR operations
                if len(mc.uses_strings) > 5 and any("xor" in s.lower() or "decrypt" in s.lower()
                                                    for s in mc.uses_strings):
                    indicators["String encryption detected"] += 1

        if total_classes > 0:
            self.report.obfuscation_score = round((obf_classes / total_classes) * 100, 1)

        # Determine tool
        if indicators:
            tool = max(indicators, key=indicators.get)
            self.report.obfuscation_tool = tool
        elif self.report.obfuscation_score > 50:
            self.report.obfuscation_tool = "ProGuard/R8 (likely)"
        else:
            self.report.obfuscation_tool = "None/Minimal"



    # ------------------------------------------------------------------
    # CERTIFICATE, RESOURCES, HELPERS
    # ------------------------------------------------------------------
    def _extract_cert_info(self, z: zipfile.ZipFile, names: List[str]):
        cert_files = [n for n in names if n.startswith("META-INF/") and
                      n.upper().endswith((".RSA", ".DSA", ".EC"))]
        if not cert_files:
            return
        try:
            cert_data = z.read(cert_files[0])
            sha256_fp = hashlib.sha256(cert_data).hexdigest()
            md5_fp = hashlib.md5(cert_data).hexdigest()
            cert_strings = list(extract_ascii_strings(cert_data, 4))
            issuer = ""
            subject = ""
            for s in cert_strings:
                if "CN=" in s or "O=" in s:
                    if not issuer:
                        issuer = s
                    elif not subject:
                        subject = s
            self.report.cert_info = CertInfo(
                filename=cert_files[0], issuer=issuer, subject=subject,
                fingerprint_sha256=sha256_fp, fingerprint_md5=md5_fp,
            )
        except Exception:
            pass

    def _scan_resource_blob(self, data: bytes, source: str):
        for s in extract_ascii_strings(data, self.min_str_len):
            self._scan_string_for_secrets(s, source)
        for s in extract_utf16le_strings(data, self.min_str_len):
            self._scan_string_for_secrets(s, source)
        self._extract_urls_ips(data, source)

    def _scan_string_for_secrets(self, s: str, source: str):
        if not s or len(s) < 6:
            return
        for name, sev, rx in self._compiled_secrets:
            for m in rx.finditer(s):
                val = m.group(0)
                if len(val) > 400:
                    val = val[:400] + "..."
                self._add_finding(Finding(
                    category="secret", severity=sev, name=name,
                    description=f"Hardcoded {name} found in application.",
                    value=val, source_file=source,
                    cve_cwe="CWE-798", cvss=7.5 if sev in ("CRITICAL", "HIGH") else 4.3,
                    remediation="Remove hardcoded secrets; use secure vault or env vars.",
                    confidence="high",
                ))

    def _extract_urls_ips(self, data: bytes, source: str):
        for m in URL_PATTERN.finditer(data):
            try:
                url = m.group(0).decode("ascii", "ignore").rstrip(".,);:'\"")
            except Exception:
                continue
            if not url or any(h in url for h in NOISE_HOSTS):
                continue
            sev = "MEDIUM" if url.lower().startswith("http://") else "LOW"
            self._add_finding(Finding(
                category="network", severity=sev,
                name="Hardcoded URL", description="Hardcoded URL in app.",
                value=url[:300], source_file=source,
                cve_cwe="CWE-319" if sev == "MEDIUM" else "",
                cvss=5.9 if sev == "MEDIUM" else 2.0,
                confidence="high" if sev == "MEDIUM" else "low",
            ))

    def _add_finding(self, f: Finding):
        k = f.key()
        if k in self._seen:
            return
        self._seen.add(k)
        self.report.findings.append(f)

    def _build_call_graph_stats(self):
        total_edges = 0
        total_methods = 0
        for dp in self._dex_parsers:
            total_methods += len(dp.method_codes)
            total_edges += sum(len(v) for v in dp.call_graph.values())
        self.report.call_graph_stats = {
            "total_methods_analyzed": total_methods,
            "total_call_edges": total_edges,
            "taint_paths_found": len(self.report.taint_paths),
            "attack_chains_built": len(self.report.attack_chains),
        }

    def _build_summary(self):
        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        for f in self.report.findings:
            by_sev[f.severity] += 1
            by_cat[f.category] += 1

        total_dex_classes = sum(d.class_count for d in self.report.dex_info)
        total_dex_methods = sum(d.method_count for d in self.report.dex_info)

        self.report.summary = {
            "total_findings": len(self.report.findings),
            "by_severity": dict(by_sev),
            "by_category": dict(by_cat),
            "risk_score": self._calculate_risk_score(by_sev),
            "dex_files_analyzed": len(self.report.dex_info),
            "total_classes": total_dex_classes,
            "total_methods": total_dex_methods,
            "methods_disassembled": sum(d.methods_with_code for d in self.report.dex_info),
            "call_graph": self.report.call_graph_stats,
            "taint_paths": len(self.report.taint_paths),
            "attack_chains": len(self.report.attack_chains),
            "vulnerable_libraries": len(self.report.detected_libraries),
            "tracking_sdks": len(self.report.tracking_sdks),
            "native_libs_scanned": len(self.report.native_libs),
            "permission_abuse_chains": len(self.report.permission_abuse_chains),
            "obfuscation_percent": self.report.obfuscation_score,
            "obfuscation_tool": self.report.obfuscation_tool,
            "has_root_detection": any("Root" in s for s in self.report.security_checks),
            "has_debug_detection": any("Debug" in s for s in self.report.security_checks),
            "has_frida_detection": any("Frida" in s for s in self.report.security_checks),
        }

    def _calculate_risk_score(self, by_sev: dict) -> int:
        score = 0
        score += by_sev.get("CRITICAL", 0) * 25
        score += by_sev.get("HIGH", 0) * 15
        score += by_sev.get("MEDIUM", 0) * 7
        score += by_sev.get("LOW", 0) * 2
        return min(100, score)



# ===========================================================================
# OUTPUT GENERATION
# ===========================================================================

SEV_COLOR = {"CRITICAL": C_RED, "HIGH": C_RED, "MEDIUM": C_YEL, "LOW": C_CYN, "INFO": C_GRN}


def generate_frida_hooks(report: Report, output_dir: str):
    """Generate ready-to-use Frida hook scripts."""
    hooks_dir = os.path.join(output_dir, "frida_hooks")
    os.makedirs(hooks_dir, exist_ok=True)

    # SSL Bypass hook
    ssl_hook = """// Auto-generated: Universal SSL Pinning Bypass
// Usage: frida -U -f <package> -l ssl_bypass.js --no-pause

Java.perform(function() {
    console.log('[*] SSL Pinning Bypass loaded');

    // TrustManager bypass
    var X509TrustManager = Java.use('javax.net.ssl.X509TrustManager');
    var SSLContext = Java.use('javax.net.ssl.SSLContext');

    var TrustManager = Java.registerClass({
        name: 'com.frida.bypass.TrustManager',
        implements: [X509TrustManager],
        methods: {
            checkClientTrusted: function(chain, authType) { },
            checkServerTrusted: function(chain, authType) { },
            getAcceptedIssuers: function() { return []; }
        }
    });

    // Install custom TrustManager
    var TrustManagers = [TrustManager.$new()];
    var sslContext = SSLContext.getInstance('TLS');
    sslContext.init(null, TrustManagers, null);
    console.log('[+] Custom TrustManager installed');

    // OkHttp3 CertificatePinner bypass
    try {
        var CertificatePinner = Java.use('okhttp3.CertificatePinner');
        CertificatePinner.check.overload('java.lang.String', 'java.util.List').implementation = function(hostname, peerCerts) {
            console.log('[+] OkHttp3 pin bypassed for: ' + hostname);
        };
    } catch(e) { console.log('[-] OkHttp3 not found'); }

    // Conscrypt TrustManagerImpl
    try {
        var TrustManagerImpl = Java.use('com.android.org.conscrypt.TrustManagerImpl');
        TrustManagerImpl.verifyChain.implementation = function(untrustedChain, trustAnchorChain, host, clientAuth, ocspData, tlsSctData) {
            console.log('[+] Conscrypt pin bypassed for: ' + host);
            return untrustedChain;
        };
    } catch(e) { console.log('[-] Conscrypt not found'); }

    // HostnameVerifier bypass
    try {
        var HostnameVerifier = Java.use('javax.net.ssl.HostnameVerifier');
        var HttpsURLConnection = Java.use('javax.net.ssl.HttpsURLConnection');
        HttpsURLConnection.setDefaultHostnameVerifier.implementation = function(verifier) {
            console.log('[+] HostnameVerifier bypassed');
        };
    } catch(e) {}

    console.log('[*] All SSL bypasses active');
});
"""
    with open(os.path.join(hooks_dir, "ssl_bypass.js"), "w") as f:
        f.write(ssl_hook)

    # Crypto monitoring hook
    crypto_hook = """// Auto-generated: Cryptographic Operations Monitor
// Usage: frida -U -f <package> -l crypto_hook.js --no-pause

Java.perform(function() {
    console.log('[*] Crypto Monitor loaded');

    function bytesToHex(bytes) {
        var hex = [];
        for (var i = 0; i < bytes.length; i++) {
            hex.push(('0' + (bytes[i] & 0xFF).toString(16)).slice(-2));
        }
        return hex.join('');
    }

    // Monitor Cipher operations
    var Cipher = Java.use('javax.crypto.Cipher');
    Cipher.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log('[CIPHER] Algorithm: ' + algo);
        return this.getInstance(algo);
    };

    Cipher.doFinal.overload('[B').implementation = function(input) {
        console.log('[CIPHER] doFinal input (' + input.length + ' bytes): ' + bytesToHex(input).substring(0, 64));
        var result = this.doFinal(input);
        console.log('[CIPHER] doFinal output (' + result.length + ' bytes): ' + bytesToHex(result).substring(0, 64));
        return result;
    };

    // Monitor SecretKeySpec
    var SecretKeySpec = Java.use('javax.crypto.spec.SecretKeySpec');
    SecretKeySpec.$init.overload('[B', 'java.lang.String').implementation = function(key, algo) {
        console.log('[KEY] SecretKeySpec: algo=' + algo + ' key=' + bytesToHex(key));
        return this.$init(key, algo);
    };

    // Monitor IvParameterSpec
    var IvParameterSpec = Java.use('javax.crypto.spec.IvParameterSpec');
    IvParameterSpec.$init.overload('[B').implementation = function(iv) {
        console.log('[IV] IvParameterSpec: ' + bytesToHex(iv));
        return this.$init(iv);
    };

    // Monitor MessageDigest
    var MessageDigest = Java.use('java.security.MessageDigest');
    MessageDigest.getInstance.overload('java.lang.String').implementation = function(algo) {
        console.log('[HASH] MessageDigest: ' + algo);
        return this.getInstance(algo);
    };

    // Monitor SharedPreferences writes
    try {
        var Editor = Java.use('android.app.SharedPreferencesImpl$EditorImpl');
        Editor.putString.implementation = function(key, value) {
            console.log('[PREFS] putString: ' + key + ' = ' + value);
            return this.putString(key, value);
        };
    } catch(e) {}

    console.log('[*] Crypto monitoring active');
});
"""
    with open(os.path.join(hooks_dir, "crypto_hook.js"), "w") as f:
        f.write(crypto_hook)

    # Root detection bypass
    root_hook = """// Auto-generated: Root & Emulator Detection Bypass
// Usage: frida -U -f <package> -l root_detection_bypass.js --no-pause

Java.perform(function() {
    console.log('[*] Root Detection Bypass loaded');

    // File.exists bypass for root binaries
    var File = Java.use('java.io.File');
    File.exists.implementation = function() {
        var path = this.getAbsolutePath();
        var blocked = ['/system/bin/su', '/system/xbin/su', '/sbin/su',
                      '/system/app/Superuser.apk', '/data/local/bin/su',
                      '/data/local/su', '/system/sd/xbin/su',
                      '/system/bin/failsafe/su', '/data/local/xbin/su',
                      '/su/bin/su', '/su/bin', '/magisk'];
        for (var i = 0; i < blocked.length; i++) {
            if (path.indexOf(blocked[i]) !== -1) {
                console.log('[ROOT] Blocked file check: ' + path);
                return false;
            }
        }
        return this.exists();
    };

    // Runtime.exec bypass for root checks
    var Runtime = Java.use('java.lang.Runtime');
    Runtime.exec.overload('java.lang.String').implementation = function(cmd) {
        if (cmd.indexOf('su') !== -1 || cmd.indexOf('which') !== -1) {
            console.log('[ROOT] Blocked exec: ' + cmd);
            throw Java.use('java.io.IOException').$new('Permission denied');
        }
        return this.exec(cmd);
    };

    // RootBeer bypass
    try {
        var RootBeer = Java.use('com.scottyab.rootbeer.RootBeer');
        RootBeer.isRooted.implementation = function() {
            console.log('[ROOT] RootBeer.isRooted() -> false');
            return false;
        };
        RootBeer.isRootedWithoutBusyBoxCheck.implementation = function() { return false; };
    } catch(e) {}

    // Build.TAGS bypass
    try {
        var Build = Java.use('android.os.Build');
        var tags = Build.TAGS.value;
        if (tags && tags.indexOf('test-keys') !== -1) {
            Build.TAGS.value = 'release-keys';
            console.log('[ROOT] Build.TAGS patched');
        }
    } catch(e) {}

    // Debug detection bypass
    try {
        var Debug = Java.use('android.os.Debug');
        Debug.isDebuggerConnected.implementation = function() {
            console.log('[DEBUG] isDebuggerConnected -> false');
            return false;
        };
    } catch(e) {}

    // Frida detection bypass
    try {
        var Runtime2 = Java.use('java.lang.Runtime');
        var originalExec = Runtime2.exec.overload('[Ljava.lang.String;');
        originalExec.implementation = function(cmds) {
            for (var i = 0; i < cmds.length; i++) {
                if (cmds[i].indexOf('frida') !== -1 || cmds[i].indexOf('27042') !== -1) {
                    console.log('[FRIDA] Blocked detection command');
                    throw Java.use('java.io.IOException').$new('');
                }
            }
            return originalExec.call(this, cmds);
        };
    } catch(e) {}

    console.log('[*] Root/Debug/Frida detection bypassed');
});
"""
    with open(os.path.join(hooks_dir, "root_detection_bypass.js"), "w") as f:
        f.write(root_hook)

    # Activity/Intent monitor
    intent_hook = """// Auto-generated: Activity & Intent Monitor
// Usage: frida -U -f <package> -l intent_monitor.js --no-pause

Java.perform(function() {
    console.log('[*] Intent Monitor loaded');

    var Activity = Java.use('android.app.Activity');
    Activity.startActivity.overload('android.content.Intent').implementation = function(intent) {
        console.log('[INTENT] startActivity:');
        console.log('  Action: ' + intent.getAction());
        console.log('  Data: ' + intent.getDataString());
        console.log('  Component: ' + intent.getComponent());
        var extras = intent.getExtras();
        if (extras) {
            var keys = extras.keySet().iterator();
            while (keys.hasNext()) {
                var key = keys.next();
                console.log('  Extra: ' + key + ' = ' + extras.get(key));
            }
        }
        return this.startActivity(intent);
    };

    // WebView monitoring
    var WebView = Java.use('android.webkit.WebView');
    WebView.loadUrl.overload('java.lang.String').implementation = function(url) {
        console.log('[WEBVIEW] loadUrl: ' + url);
        return this.loadUrl(url);
    };
    WebView.evaluateJavascript.implementation = function(js, callback) {
        console.log('[WEBVIEW] evaluateJavascript: ' + js.substring(0, 200));
        return this.evaluateJavascript(js, callback);
    };

    // Network monitor
    try {
        var URL = Java.use('java.net.URL');
        URL.$init.overload('java.lang.String').implementation = function(url) {
            console.log('[NET] URL: ' + url);
            return this.$init(url);
        };
    } catch(e) {}

    console.log('[*] Intent/WebView/Network monitoring active');
});
"""
    with open(os.path.join(hooks_dir, "intent_monitor.js"), "w") as f:
        f.write(intent_hook)

    # Write any custom hooks from findings
    custom_hooks = []
    for f in report.findings:
        if f.frida_hook and f.frida_hook not in custom_hooks:
            custom_hooks.append(f.frida_hook)

    if custom_hooks:
        with open(os.path.join(hooks_dir, "custom_vuln_hooks.js"), "w") as fh:
            fh.write("// Auto-generated vulnerability-specific Frida hooks\n\n")
            for i, hook in enumerate(custom_hooks[:10]):
                fh.write(f"\n// === Hook {i+1} ===\n")
                fh.write(hook)
                fh.write("\n")


def generate_adb_tests(report: Report, output_dir: str):
    """Generate ADB test commands script."""
    adb_path = os.path.join(output_dir, "adb_tests.sh")
    lines = [
        "#!/bin/bash",
        "# Auto-generated ADB security test commands",
        f"# Target APK: {os.path.basename(report.apk_path)}",
        f"# Generated: {report.scan_time}",
        "",
        "PKG=\"<PACKAGE_NAME>\"  # Replace with actual package name",
        "",
        "echo '=== APK Security Testing Commands ==='",
        "",
        "# Check if app is debuggable",
        "echo '[*] Checking debuggable flag...'",
        "adb shell run-as $PKG id 2>/dev/null && echo '[!] APP IS DEBUGGABLE' || echo '[+] Not debuggable'",
        "",
        "# Backup test",
        "echo '[*] Testing backup...'",
        "echo 'adb backup -apk -shared $PKG'",
        "",
        "# List exported activities",
        "echo '[*] Exported components:'",
        "adb shell dumpsys package $PKG | grep -A5 'exported=true'",
        "",
    ]

    # Add component tests
    for comp in report.components[:20]:
        lines.append(f"# Test component: {comp.name}")
        lines.append(f"echo '[*] Testing {comp.component_type}: {comp.name}'")
        if comp.component_type == "activity":
            lines.append(f"adb shell am start -n $PKG/{comp.name}")
            lines.append(f"adb shell am start -n $PKG/{comp.name} -d 'content://evil'")
        elif comp.component_type == "service":
            lines.append(f"adb shell am startservice -n $PKG/{comp.name}")
        elif comp.component_type == "receiver":
            lines.append(f"adb shell am broadcast -n $PKG/{comp.name} -a android.intent.action.BOOT_COMPLETED")
        lines.append("")

    # Deep link tests
    for dl in report.deep_links[:10]:
        lines.append(f"# Deep link test: {dl['scheme']}://")
        lines.append(f"echo '[*] Testing deep link: {dl['scheme']}://'")
        for url in dl.get("test_urls", [])[:3]:
            lines.append(f"adb shell am start -a android.intent.action.VIEW -d \"{url}\"")
        lines.append("")

    # Add custom ADB commands from findings
    lines.append("# === Vulnerability-specific tests ===")
    for f in report.findings:
        if f.adb_command:
            lines.append(f"# {f.name}")
            lines.append(f"echo '[*] {f.name}'")
            lines.append(f.adb_command.replace("<package>", "$PKG"))
            lines.append("")

    lines.append("echo '[*] ADB testing complete'")

    with open(adb_path, "w") as f:
        f.write("\n".join(lines))
    os.chmod(adb_path, 0o755)


def generate_attack_chains_file(report: Report, output_dir: str):
    """Generate attack chains visualization file."""
    path = os.path.join(output_dir, "attack_chains.txt")
    lines = [
        "=" * 70,
        "  ATTACK CHAIN ANALYSIS",
        f"  {len(report.attack_chains)} chains identified",
        "=" * 70,
        "",
    ]

    for chain in report.attack_chains:
        sev_marker = {"CRITICAL": "[!!!]", "HIGH": "[!!]", "MEDIUM": "[!]", "LOW": "[.]"}.get(chain.severity, "[?]")
        lines.append(f"{'='*60}")
        lines.append(f"ATTACK CHAIN #{chain.chain_id}: {chain.title}")
        lines.append(f"Severity: {sev_marker} {chain.severity} | CVSS: {chain.cvss} | {chain.cwe}")
        lines.append(f"Exploit Difficulty: {chain.exploit_difficulty}")
        lines.append(f"{'='*60}")
        lines.append("")
        lines.append(f"  Entry Point: {chain.entry_point}")
        lines.append("")
        lines.append("  Attack Steps:")
        for i, step in enumerate(chain.steps):
            connector = "|--" if i < len(chain.steps) - 1 else "`--"
            lines.append(f"    {connector} {step}")
        lines.append("")
        lines.append(f"  Risk: {chain.risk_description}")
        lines.append(f"  Impact: {chain.impact}")
        lines.append("")

        if chain.exploit_steps:
            lines.append("  Exploitation Guide:")
            for step in chain.exploit_steps:
                lines.append(f"    {step}")
            lines.append("")

        if chain.tools:
            lines.append(f"  Tools: {', '.join(chain.tools)}")
            lines.append("")

        if chain.adb_command:
            lines.append(f"  ADB Test: {chain.adb_command}")
            lines.append("")

        lines.append("")

    # Taint analysis paths
    if report.taint_paths:
        lines.append("=" * 70)
        lines.append("  DATA FLOW (TAINT) ANALYSIS")
        lines.append("=" * 70)
        lines.append("")
        for tp in report.taint_paths[:30]:
            lines.append(f"  [{tp.source_type}] -> [{tp.sink_type}]")
            lines.append(f"    Source: {tp.source_method}")
            lines.append(f"    Sink:   {tp.sink_method}")
            if len(tp.path) > 2:
                lines.append(f"    Path:   {' -> '.join(tp.path)}")
            lines.append(f"    Risk:   {tp.data_description}")
            lines.append("")

    with open(path, "w") as f:
        f.write("\n".join(lines))


def generate_exploit_notes(report: Report, output_dir: str):
    """Generate exploit notes in Markdown format for bug bounty."""
    path = os.path.join(output_dir, "exploit_notes.md")
    lines = [
        f"# Exploit Notes - {os.path.basename(report.apk_path)}",
        "",
        f"**Generated:** {report.scan_time}",
        f"**Risk Score:** {report.summary.get('risk_score', 0)}/100",
        "",
        "---",
        "",
        "## Executive Summary",
        "",
        f"- **Critical:** {report.summary.get('by_severity', {}).get('CRITICAL', 0)}",
        f"- **High:** {report.summary.get('by_severity', {}).get('HIGH', 0)}",
        f"- **Medium:** {report.summary.get('by_severity', {}).get('MEDIUM', 0)}",
        f"- **Attack Chains:** {len(report.attack_chains)}",
        f"- **Taint Paths:** {len(report.taint_paths)}",
        "",
        "---",
        "",
    ]

    # Top findings for bug bounty
    critical_high = [f for f in report.findings if f.severity in ("CRITICAL", "HIGH")]
    if critical_high:
        lines.append("## Priority Findings (Bug Bounty)")
        lines.append("")
        for i, finding in enumerate(critical_high[:15], 1):
            lines.append(f"### {i}. [{finding.severity}] {finding.name}")
            lines.append("")
            lines.append(f"**{finding.cve_cwe}** | CVSS: {finding.cvss}")
            lines.append("")
            lines.append(f"**Description:** {finding.description}")
            lines.append("")
            lines.append(f"**Evidence:** `{finding.value[:150]}`")
            lines.append("")
            if finding.affected_class:
                lines.append(f"**Affected Class:** `{finding.affected_class}`")
                lines.append("")
            if finding.context:
                lines.append(f"**Context:**")
                lines.append(f"```")
                lines.append(finding.context[:500])
                lines.append(f"```")
                lines.append("")
            if finding.exploit_info:
                lines.append(f"**Exploit Info:** {finding.exploit_info}")
                lines.append("")
            lines.append(f"**Remediation:** {finding.remediation}")
            lines.append("")
            if finding.adb_command:
                lines.append(f"**ADB Test:** `{finding.adb_command}`")
                lines.append("")
            lines.append("---")
            lines.append("")

    # Attack chains
    if report.attack_chains:
        lines.append("## Attack Chains")
        lines.append("")
        for chain in report.attack_chains:
            lines.append(f"### Chain #{chain.chain_id}: {chain.title}")
            lines.append("")
            lines.append(f"**Severity:** {chain.severity} | **CVSS:** {chain.cvss} | **{chain.cwe}**")
            lines.append("")
            lines.append(f"**Entry Point:** `{chain.entry_point}`")
            lines.append("")
            lines.append("**Steps:**")
            for step in chain.steps:
                lines.append(f"1. {step}")
            lines.append("")
            lines.append(f"**Impact:** {chain.impact}")
            lines.append("")
            if chain.poc_template:
                lines.append("**PoC Template (HackerOne):**")
                lines.append("```")
                lines.append(chain.poc_template)
                lines.append("```")
                lines.append("")
            lines.append("---")
            lines.append("")

    # Permission abuse
    if report.permission_abuse_chains:
        lines.append("## Permission Abuse Chains")
        lines.append("")
        for pac in report.permission_abuse_chains:
            lines.append(f"- **{pac['chain']}**")
            lines.append(f"  - Severity: {pac['severity']}")
            lines.append(f"  - Impact: {pac['impact']}")
            lines.append("")

    # Frida usage guide
    lines.extend([
        "",
        "## Frida Hooks Usage",
        "",
        "```bash",
        "# Install Frida",
        "pip install frida-tools",
        "",
        "# Push frida-server to device",
        "adb push frida-server /data/local/tmp/",
        "adb shell chmod 755 /data/local/tmp/frida-server",
        "adb shell /data/local/tmp/frida-server &",
        "",
        "# Run hooks",
        "frida -U -f <package> -l frida_hooks/ssl_bypass.js --no-pause",
        "frida -U -f <package> -l frida_hooks/crypto_hook.js --no-pause",
        "frida -U -f <package> -l frida_hooks/root_detection_bypass.js --no-pause",
        "```",
        "",
    ])

    with open(path, "w") as f:
        f.write("\n".join(lines))



# ===========================================================================
# REPORT FORMATTERS
# ===========================================================================

def print_report(rep: Report):
    """Print colored report to terminal."""
    print(f"\n{C_BLD}{C_MAG}{'='*70}{C_RST}")
    print(f"{C_BLD}{C_MAG}  APK ELITE ANALYZER v{VERSION} - Monster-Grade Security Assessment{C_RST}")
    print(f"{C_BLD}{C_MAG}{'='*70}{C_RST}")

    print(f"\n{C_BLD}[TARGET]{C_RST}")
    print(f"  File     : {rep.apk_path}")
    print(f"  Size     : {rep.apk_size:,} bytes")
    print(f"  MD5      : {rep.apk_md5}")
    print(f"  SHA-256  : {rep.apk_sha256}")
    print(f"  Duration : {rep.scan_duration}s")

    risk = rep.summary.get("risk_score", 0)
    risk_color = C_GRN if risk < 25 else C_YEL if risk < 50 else C_RED
    print(f"\n{C_BLD}[RISK SCORE]{C_RST} {risk_color}{C_BLD}{risk}/100{C_RST}")

    # Call graph stats
    cg = rep.call_graph_stats
    if cg:
        print(f"\n{C_BLD}[BYTECODE ANALYSIS]{C_RST}")
        print(f"  Methods disassembled : {cg.get('total_methods_analyzed', 0):,}")
        print(f"  Call graph edges     : {cg.get('total_call_edges', 0):,}")
        print(f"  Taint paths found    : {cg.get('taint_paths_found', 0)}")
        print(f"  Attack chains built  : {cg.get('attack_chains_built', 0)}")

    if rep.dex_info:
        print(f"\n{C_BLD}[DEX ANALYSIS]{C_RST}")
        for di in rep.dex_info:
            print(f"  {di.filename}: {di.class_count} classes, "
                  f"{di.method_count} methods, {di.methods_with_code} with code")
        print(f"  Obfuscation: {rep.obfuscation_score:.1f}% ({rep.obfuscation_tool})")

    if rep.native_libs:
        print(f"\n{C_BLD}[NATIVE LIBRARIES]{C_RST}")
        for nl in rep.native_libs[:10]:
            print(f"  {nl['filename']} ({nl['arch']}): {nl['total_strings']} strings, "
                  f"{len(nl.get('jni_methods', []))} JNI methods")

    if rep.cert_info:
        print(f"\n{C_BLD}[CERTIFICATE]{C_RST}")
        print(f"  File    : {rep.cert_info.filename}")
        print(f"  SHA-256 : {rep.cert_info.fingerprint_sha256}")

    flags = []
    if rep.debuggable:
        flags.append(f"{C_RED}DEBUGGABLE{C_RST}")
    if rep.allow_backup:
        flags.append(f"{C_YEL}BACKUP{C_RST}")
    if rep.uses_cleartext:
        flags.append(f"{C_YEL}CLEARTEXT{C_RST}")
    if flags:
        print(f"\n{C_BLD}[FLAGS]{C_RST} {' | '.join(flags)}")

    if rep.dangerous_permissions:
        print(f"\n{C_BLD}[DANGEROUS PERMISSIONS] ({len(rep.dangerous_permissions)}){C_RST}")
        for p in rep.dangerous_permissions[:10]:
            print(f"  {C_YEL}- {p}{C_RST}")

    if rep.permission_abuse_chains:
        print(f"\n{C_BLD}{C_RED}[PERMISSION ABUSE CHAINS]{C_RST}")
        for pac in rep.permission_abuse_chains[:5]:
            print(f"  {C_RED}! {pac['chain']}{C_RST}")
            print(f"    Impact: {pac['impact']}")

    if rep.detected_libraries:
        print(f"\n{C_BLD}[VULNERABLE LIBRARIES]{C_RST}")
        for lib in rep.detected_libraries:
            print(f"  {C_RED}- {lib}{C_RST}")

    if rep.tracking_sdks:
        print(f"\n{C_BLD}[TRACKING SDKs]{C_RST}")
        for sdk in rep.tracking_sdks:
            print(f"  {C_CYN}- {sdk}{C_RST}")

    if rep.security_checks:
        print(f"\n{C_BLD}[SECURITY PROTECTIONS]{C_RST}")
        for sc in rep.security_checks:
            print(f"  {C_GRN}+ {sc}{C_RST}")

    # Attack chains
    if rep.attack_chains:
        print(f"\n{C_BLD}{C_RED}[ATTACK CHAINS] ({len(rep.attack_chains)}){C_RST}")
        for chain in rep.attack_chains[:5]:
            marker = {"CRITICAL": "!!!","HIGH": "!!", "MEDIUM": "!"}.get(chain.severity, ".")
            print(f"\n  {C_RED}[{marker}] Chain #{chain.chain_id}: {chain.title}{C_RST}")
            print(f"      Severity: {chain.severity} | CVSS: {chain.cvss} | {chain.cwe}")
            print(f"      Entry: {chain.entry_point}")
            for step in chain.steps[:4]:
                print(f"      |-- {step}")
            print(f"      Impact: {chain.impact}")

    # Taint paths
    if rep.taint_paths:
        print(f"\n{C_BLD}{C_MAG}[TAINT ANALYSIS] ({len(rep.taint_paths)} paths){C_RST}")
        for tp in rep.taint_paths[:5]:
            print(f"  {C_MAG}{tp.source_type} -> {tp.sink_type}{C_RST}")
            print(f"    Path: {' -> '.join(tp.path[:4])}")

    # Findings summary
    by_sev = rep.summary.get("by_severity", {})
    print(f"\n{C_BLD}[FINDINGS]{C_RST} Total: {len(rep.findings)}  "
          f"{C_RED}CRIT={by_sev.get('CRITICAL', 0)}{C_RST} "
          f"{C_RED}HIGH={by_sev.get('HIGH', 0)}{C_RST} "
          f"{C_YEL}MED={by_sev.get('MEDIUM', 0)}{C_RST} "
          f"{C_CYN}LOW={by_sev.get('LOW', 0)}{C_RST}")

    # Top findings
    for sev in ("CRITICAL", "HIGH"):
        items = [f for f in rep.findings if f.severity == sev]
        if not items:
            continue
        col = SEV_COLOR.get(sev, "")
        print(f"\n  {col}{C_BLD}--- [{sev}] ---{C_RST}")
        groups: Dict[str, List[Finding]] = defaultdict(list)
        for it in items:
            groups[it.name].append(it)
        for name, arr in list(groups.items())[:10]:
            cve = f" [{arr[0].cve_cwe}]" if arr[0].cve_cwe else ""
            print(f"  {col}{name}{cve} CVSS:{arr[0].cvss} (x{len(arr)}){C_RST}")
            if arr[0].context:
                ctx_line = arr[0].context.split('\n')[0][:80]
                print(f"    {C_MAG}{ctx_line}{C_RST}")


def save_json_report(rep: Report, path: str):
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rep.to_dict(), f, indent=2, ensure_ascii=False, default=str)


def save_txt_report(rep: Report, path: str):
    lines = []
    lines.append("=" * 70)
    lines.append(f"  APK ELITE ANALYZER v{VERSION} - Security Assessment Report")
    lines.append("=" * 70)
    lines.append("")
    lines.append(f"File     : {rep.apk_path}")
    lines.append(f"Size     : {rep.apk_size:,} bytes")
    lines.append(f"MD5      : {rep.apk_md5}")
    lines.append(f"SHA-256  : {rep.apk_sha256}")
    lines.append(f"Duration : {rep.scan_duration}s")
    lines.append("")

    risk = rep.summary.get("risk_score", 0)
    lines.append(f"RISK SCORE: {risk}/100")
    lines.append("")

    # Call graph stats
    cg = rep.call_graph_stats
    if cg:
        lines.append("[BYTECODE DISASSEMBLY STATS]")
        lines.append(f"  Methods disassembled: {cg.get('total_methods_analyzed', 0):,}")
        lines.append(f"  Call graph edges: {cg.get('total_call_edges', 0):,}")
        lines.append(f"  Taint paths: {cg.get('taint_paths_found', 0)}")
        lines.append(f"  Attack chains: {cg.get('attack_chains_built', 0)}")
        lines.append("")

    if rep.dex_info:
        lines.append("[DEX ANALYSIS]")
        for di in rep.dex_info:
            lines.append(f"  {di.filename}: {di.class_count} classes, {di.method_count} methods, {di.methods_with_code} disassembled")
        lines.append(f"  Obfuscation: {rep.obfuscation_score:.1f}% ({rep.obfuscation_tool})")
        lines.append("")

    if rep.native_libs:
        lines.append("[NATIVE LIBRARIES (.so)]")
        for nl in rep.native_libs:
            lines.append(f"  {nl['filename']} ({nl['arch']})")
            for jni in nl.get('jni_methods', [])[:5]:
                lines.append(f"    JNI: {jni}")
            for url in nl.get('urls', [])[:3]:
                lines.append(f"    URL: {url}")
        lines.append("")

    if rep.dangerous_permissions:
        lines.append(f"[DANGEROUS PERMISSIONS] ({len(rep.dangerous_permissions)})")
        for p in rep.dangerous_permissions:
            lines.append(f"  - {p}")
        lines.append("")

    if rep.permission_abuse_chains:
        lines.append("[PERMISSION ABUSE CHAINS]")
        for pac in rep.permission_abuse_chains:
            lines.append(f"  ! {pac['chain']}")
            lines.append(f"    Severity: {pac['severity']} | Impact: {pac['impact']}")
        lines.append("")

    if rep.attack_chains:
        lines.append("=" * 70)
        lines.append("[ATTACK CHAINS]")
        lines.append("=" * 70)
        for chain in rep.attack_chains:
            lines.append(f"\n  Chain #{chain.chain_id}: {chain.title}")
            lines.append(f"  Severity: {chain.severity} | CVSS: {chain.cvss} | {chain.cwe}")
            lines.append(f"  Entry: {chain.entry_point}")
            for step in chain.steps:
                lines.append(f"    |-- {step}")
            lines.append(f"  Impact: {chain.impact}")
            lines.append(f"  Difficulty: {chain.exploit_difficulty}")
        lines.append("")

    if rep.taint_paths:
        lines.append("=" * 70)
        lines.append("[TAINT ANALYSIS - DATA FLOW PATHS]")
        lines.append("=" * 70)
        for tp in rep.taint_paths[:30]:
            lines.append(f"\n  {tp.source_type} --> {tp.sink_type}")
            lines.append(f"    Source: {tp.source_method}")
            lines.append(f"    Sink:   {tp.sink_method}")
            lines.append(f"    Path:   {' -> '.join(tp.path)}")
            lines.append(f"    Risk:   {tp.data_description}")
        lines.append("")

    lines.append("=" * 70)
    lines.append("[ALL FINDINGS]")
    lines.append("=" * 70)
    for f in rep.findings:
        lines.append(f"\n[{f.severity:8}] {f.name}")
        if f.cve_cwe:
            lines.append(f"           CVE/CWE: {f.cve_cwe} | CVSS: {f.cvss}")
        lines.append(f"           Category: {f.category}")
        lines.append(f"           Value: {f.value[:200]}")
        lines.append(f"           Source: {f.source_file}")
        if f.affected_class:
            lines.append(f"           Class: {f.affected_class}")
        if f.context:
            lines.append(f"           Context: {f.context[:200]}")
        if f.description:
            lines.append(f"           Desc: {f.description}")
        lines.append(f"           Fix: {f.remediation}")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))


def save_html_report(rep: Report, path: str):
    """Generate dark-themed HTML report."""
    h = html_module.escape
    risk = rep.summary.get("risk_score", 0)
    by_sev = rep.summary.get("by_severity", {})
    risk_color = "#28a745" if risk < 25 else "#ffc107" if risk < 50 else "#dc3545"
    sev_colors = {"CRITICAL": "#dc3545", "HIGH": "#e85d04", "MEDIUM": "#ffc107", "LOW": "#17a2b8", "INFO": "#28a745"}

    html_parts = [f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APK Elite Analysis - {h(os.path.basename(rep.apk_path))}</title>
<style>
* {{ box-sizing: border-box; }}
body {{ font-family: 'JetBrains Mono', 'Fira Code', monospace; margin: 0; padding: 20px; background: #0a0a1a; color: #e0e0e0; line-height: 1.6; }}
.container {{ max-width: 1400px; margin: 0 auto; }}
h1 {{ color: #ff0040; border-bottom: 2px solid #ff0040; padding-bottom: 15px; font-size: 24px; text-transform: uppercase; letter-spacing: 2px; }}
h2 {{ color: #00ff88; background: #111; padding: 12px 18px; border-radius: 5px; border-left: 4px solid #00ff88; margin-top: 35px; font-size: 16px; }}
h3 {{ color: #00bfff; margin-top: 20px; }}
.badge {{ display: inline-block; padding: 3px 10px; border-radius: 3px; color: #fff; font-weight: bold; font-size: 11px; margin-right: 5px; text-transform: uppercase; }}
.risk-score {{ font-size: 72px; font-weight: bold; text-align: center; padding: 30px; border-radius: 10px; border: 3px solid; text-shadow: 0 0 20px; }}
.meta-table {{ width: 100%; border-collapse: collapse; margin: 15px 0; }}
.meta-table td {{ padding: 8px 15px; border-bottom: 1px solid #222; font-size: 13px; }}
.meta-table td:first-child {{ font-weight: bold; width: 180px; color: #888; }}
code {{ background: #1a1a2e; padding: 2px 6px; border-radius: 3px; font-size: 12px; color: #00ff88; }}
.finding-card {{ background: #111; border-radius: 6px; padding: 15px; margin: 10px 0; border-left: 4px solid; font-size: 13px; }}
.finding-card .title {{ font-weight: bold; font-size: 14px; margin-bottom: 8px; }}
.finding-card .details {{ color: #999; }}
.finding-card .value {{ font-family: monospace; background: #1a1a2e; padding: 4px 8px; border-radius: 3px; margin: 5px 0; display: inline-block; word-break: break-all; color: #ff6b6b; font-size: 12px; }}
.stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(140px, 1fr)); gap: 12px; margin: 15px 0; }}
.stat-box {{ background: #111; padding: 15px; border-radius: 6px; text-align: center; border: 1px solid #222; }}
.stat-box .number {{ font-size: 28px; font-weight: bold; }}
.stat-box .label {{ font-size: 11px; color: #888; margin-top: 5px; text-transform: uppercase; }}
.chain-box {{ background: #0d1117; border: 1px solid #30363d; border-radius: 8px; padding: 20px; margin: 15px 0; }}
.chain-box .chain-title {{ font-size: 16px; font-weight: bold; color: #ff4444; }}
.chain-step {{ padding: 4px 0; padding-left: 20px; border-left: 2px solid #333; margin-left: 10px; font-size: 13px; }}
.taint-path {{ background: #111; padding: 10px 15px; margin: 8px 0; border-radius: 4px; border-left: 3px solid #9b59b6; font-size: 12px; }}
.permission-chain {{ background: #1a0000; border: 1px solid #ff000044; padding: 12px; margin: 8px 0; border-radius: 4px; }}
pre {{ background: #0d1117; padding: 15px; border-radius: 6px; overflow-x: auto; font-size: 12px; border: 1px solid #222; }}
</style>
</head>
<body>
<div class="container">
<h1>APK Elite Analyzer v{VERSION}</h1>
<p style="color:#666; font-size:12px;">Monster-Grade Security Assessment | {rep.scan_time} | Duration: {rep.scan_duration}s</p>
"""]

    # Meta
    html_parts.append(f"""
<table class="meta-table">
<tr><td>Target</td><td><code>{h(os.path.basename(rep.apk_path))}</code></td></tr>
<tr><td>Size</td><td>{rep.apk_size:,} bytes</td></tr>
<tr><td>MD5</td><td><code>{rep.apk_md5}</code></td></tr>
<tr><td>SHA-256</td><td><code>{rep.apk_sha256}</code></td></tr>
<tr><td>Obfuscation</td><td>{rep.obfuscation_score:.1f}% ({h(rep.obfuscation_tool)})</td></tr>
</table>
""")

    # Risk Score
    html_parts.append(f"""
<div class="risk-score" style="color:{risk_color}; border-color:{risk_color};">{risk}/100</div>
<div class="stat-grid">
<div class="stat-box"><div class="number" style="color:#dc3545">{by_sev.get('CRITICAL',0)}</div><div class="label">Critical</div></div>
<div class="stat-box"><div class="number" style="color:#e85d04">{by_sev.get('HIGH',0)}</div><div class="label">High</div></div>
<div class="stat-box"><div class="number" style="color:#ffc107">{by_sev.get('MEDIUM',0)}</div><div class="label">Medium</div></div>
<div class="stat-box"><div class="number" style="color:#17a2b8">{by_sev.get('LOW',0)}</div><div class="label">Low</div></div>
<div class="stat-box"><div class="number" style="color:#9b59b6">{len(rep.attack_chains)}</div><div class="label">Attack Chains</div></div>
<div class="stat-box"><div class="number" style="color:#e91e63">{len(rep.taint_paths)}</div><div class="label">Taint Paths</div></div>
</div>
""")

    # Bytecode stats
    cg = rep.call_graph_stats
    if cg:
        html_parts.append("""<h2>Bytecode Disassembly Engine</h2><div class="stat-grid">""")
        html_parts.append(f'<div class="stat-box"><div class="number">{cg.get("total_methods_analyzed",0):,}</div><div class="label">Methods Parsed</div></div>')
        html_parts.append(f'<div class="stat-box"><div class="number">{cg.get("total_call_edges",0):,}</div><div class="label">Call Edges</div></div>')
        html_parts.append(f'<div class="stat-box"><div class="number">{cg.get("taint_paths_found",0)}</div><div class="label">Taint Flows</div></div>')
        html_parts.append('</div>')

    # Attack Chains
    if rep.attack_chains:
        html_parts.append("<h2>Attack Chains</h2>")
        for chain in rep.attack_chains:
            color = sev_colors.get(chain.severity, "#666")
            html_parts.append(f"""<div class="chain-box">
<div class="chain-title" style="color:{color}">Chain #{chain.chain_id}: {h(chain.title)}</div>
<p><span class="badge" style="background:{color}">{chain.severity}</span> CVSS: {chain.cvss} | {h(chain.cwe)} | Difficulty: {h(chain.exploit_difficulty)}</p>
<p><strong>Entry:</strong> <code>{h(chain.entry_point)}</code></p>""")
            for step in chain.steps:
                html_parts.append(f'<div class="chain-step">{h(step)}</div>')
            html_parts.append(f"<p><strong>Impact:</strong> {h(chain.impact)}</p>")
            if chain.tools:
                html_parts.append(f"<p><strong>Tools:</strong> {', '.join(h(t) for t in chain.tools)}</p>")
            html_parts.append("</div>")

    # Taint Analysis
    if rep.taint_paths:
        html_parts.append("<h2>Taint Analysis (Data Flow)</h2>")
        for tp in rep.taint_paths[:20]:
            html_parts.append(f"""<div class="taint-path">
<strong>{h(tp.source_type)}</strong> &#8594; <strong>{h(tp.sink_type)}</strong><br>
<code>{h(tp.source_method)}</code> &#8594; <code>{h(tp.sink_method)}</code><br>
<small>{h(tp.data_description)}</small>
</div>""")

    # Permission Abuse
    if rep.permission_abuse_chains:
        html_parts.append("<h2>Permission Abuse Chains</h2>")
        for pac in rep.permission_abuse_chains:
            color = sev_colors.get(pac["severity"], "#666")
            html_parts.append(f"""<div class="permission-chain">
<span class="badge" style="background:{color}">{pac['severity']}</span>
<strong>{h(pac['chain'])}</strong><br>
<small>Impact: {h(pac['impact'])}</small>
</div>""")

    # Findings
    html_parts.append("<h2>All Findings</h2>")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW"):
        items = [f for f in rep.findings if f.severity == sev]
        if not items:
            continue
        color = sev_colors.get(sev, "#666")
        html_parts.append(f'<h3 style="color:{color}">{sev} ({len(items)})</h3>')
        for item in items[:40]:
            html_parts.append(f"""<div class="finding-card" style="border-left-color:{color}">
<div class="title"><span class="badge" style="background:{color}">{item.severity}</span> {h(item.name)} {f'<code>{h(item.cve_cwe)}</code>' if item.cve_cwe else ''} CVSS:{item.cvss}</div>
<div class="details">
<div class="value">{h(item.value[:180])}</div>
<div>Source: {h(item.source_file)} {f'| Class: <code>{h(item.affected_class)}</code>' if item.affected_class else ''}</div>
{f'<div>Context: {h(item.context[:200])}</div>' if item.context else ''}
<div>{h(item.description)}</div>
<div><strong>Fix:</strong> {h(item.remediation)}</div>
</div></div>""")

    html_parts.append(f"""
<hr style="margin-top:50px;border-color:#222">
<p style="text-align:center;color:#444;font-size:11px">APK Elite Analyzer v{VERSION} | {rep.scan_time}</p>
</div></body></html>""")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))



# ===========================================================================
# CLI ENTRY POINT
# ===========================================================================

def main() -> int:
    ap = argparse.ArgumentParser(
        description=f"APK Elite Analyzer v{VERSION} - Monster-Grade APK Security Scanner",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze.py app.apk
  python analyze.py app.apk -o ./output_report
  python analyze.py app.apk --format all
  python analyze.py app.apk --format html --quiet

Features:
  - DEX bytecode disassembly (Dalvik opcode parsing)
  - Call graph construction & cross-reference engine
  - Simplified taint analysis (source -> sink tracking)
  - Vulnerability chain building with exploit suggestions
  - Auto-generated Frida hooks for bypass/monitoring
  - Native library (.so) string scanning
  - Permission abuse chain detection
  - Deep link / URI scheme analysis
  - Obfuscation tool detection
  - Bug-bounty-ready reporting (JSON + TXT + HTML)
        """
    )
    ap.add_argument("apk", help="Path to the APK file")
    ap.add_argument("-o", "--output", default=None,
                    help="Output directory for all reports (default: <apk>_report/)")
    ap.add_argument("--format", choices=["json", "txt", "html", "all"], default="all",
                    help="Output format (default: all)")
    ap.add_argument("--min-len", type=int, default=6,
                    help="Minimum string length to extract (default: 6)")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress terminal output")
    ap.add_argument("--version", action="version", version=f"APK Elite Analyzer v{VERSION}")
    args = ap.parse_args()

    if not os.path.isfile(args.apk):
        print(f"{C_RED}[-] File not found: {args.apk}{C_RST}", file=sys.stderr)
        return 2
    if not zipfile.is_zipfile(args.apk):
        print(f"{C_RED}[-] Not a valid ZIP/APK file: {args.apk}{C_RST}", file=sys.stderr)
        return 2

    output_dir = args.output or (os.path.splitext(args.apk)[0] + "_report")
    os.makedirs(output_dir, exist_ok=True)

    if not args.quiet:
        print(f"{C_RED}{C_BLD}")
        print(r"     _    ____  _  __  _____ _ _ _       ")
        print(r"    / \  |  _ \| |/ / | ____| (_) |_ ___ ")
        print(r"   / _ \ | |_) | ' /  |  _| | | | __/ _ \ ")
        print(r"  / ___ \|  __/| . \  | |___| | | ||  __/")
        print(r" /_/   \_\_|   |_|\_\ |_____|_|_|\__\___|")
        print(f"                                          ")
        print(f"  v{VERSION} - Monster-Grade Security Scanner")
        print(f"  DEX Disassembly | Taint Analysis | Attack Chains")
        print(f"{C_RST}")
        print(f"{C_CYN}[*] Target: {args.apk}{C_RST}")
        print(f"{C_CYN}[*] Output: {output_dir}/{C_RST}")
        print(f"{C_CYN}[*] Disassembling DEX bytecode...{C_RST}")

    analyzer = APKEliteAnalyzer(args.apk, output_dir=output_dir, min_str_len=args.min_len)
    report = analyzer.analyze()

    if not args.quiet:
        print_report(report)

    # Generate all output files
    saved_files = []

    if args.format in ("json", "all"):
        p = os.path.join(output_dir, "report.json")
        save_json_report(report, p)
        saved_files.append(p)

    if args.format in ("txt", "all"):
        p = os.path.join(output_dir, "report.txt")
        save_txt_report(report, p)
        saved_files.append(p)

    if args.format in ("html", "all"):
        p = os.path.join(output_dir, "report.html")
        save_html_report(report, p)
        saved_files.append(p)

    # Always generate supplementary files
    generate_frida_hooks(report, output_dir)
    saved_files.append(os.path.join(output_dir, "frida_hooks/"))

    generate_adb_tests(report, output_dir)
    saved_files.append(os.path.join(output_dir, "adb_tests.sh"))

    generate_attack_chains_file(report, output_dir)
    saved_files.append(os.path.join(output_dir, "attack_chains.txt"))

    generate_exploit_notes(report, output_dir)
    saved_files.append(os.path.join(output_dir, "exploit_notes.md"))

    if not args.quiet:
        print(f"\n{C_GRN}{C_BLD}[+] Output generated:{C_RST}")
        for fp in saved_files:
            print(f"    {C_GRN}{fp}{C_RST}")

        risk = report.summary.get("risk_score", 0)
        print(f"\n{C_BLD}[VERDICT]{C_RST} ", end="")
        if risk >= 75:
            print(f"{C_RED}CRITICAL RISK - Multiple severe vulnerabilities. Immediate action required.{C_RST}")
        elif risk >= 50:
            print(f"{C_RED}HIGH RISK - Significant security issues found.{C_RST}")
        elif risk >= 25:
            print(f"{C_YEL}MODERATE RISK - Several issues worth investigating.{C_RST}")
        else:
            print(f"{C_GRN}LOW RISK - Few issues detected (still review findings).{C_RST}")

        print(f"\n{C_CYN}[*] Next steps:{C_RST}")
        print(f"    1. Review attack_chains.txt for exploitation paths")
        print(f"    2. Use frida_hooks/ scripts for dynamic testing")
        print(f"    3. Run adb_tests.sh on test device")
        print(f"    4. Submit exploit_notes.md for bug bounty")

    return 0


if __name__ == "__main__":
    sys.exit(main())
