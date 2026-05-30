#!/usr/bin/env python3
"""
APK Deep Analyzer v2.0 - Super Advanced APK Security Scanner

DEX binary format parsing, vulnerability detection with CVE/CWE mapping,
known vulnerable library detection, and comprehensive reporting.
No decompilation tools required - pure Python binary parsing.

Usage:
    python analyze.py <path-to.apk> [-o prefix] [--format json|txt|html|all]
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
from typing import Iterator, Optional

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

VERSION = "2.0.0"


# ===========================================================================
# DEX FILE FORMAT PARSER
# ===========================================================================

DEX_MAGIC = b"dex\n"
DEX_ENDIAN_CONSTANT = 0x12345678
DEX_REVERSE_ENDIAN = 0x78563412

# DEX Header offsets
DEX_HEADER_SIZE = 0x70


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
class DexFieldId:
    class_idx: int
    type_idx: int
    name_idx: int


@dataclass
class DexMethodId:
    class_idx: int
    proto_idx: int
    name_idx: int


@dataclass
class DexProtoId:
    shorty_idx: int
    return_type_idx: int
    parameters_off: int


class DexParser:
    """Parse DEX binary format without decompilation."""

    def __init__(self, data: bytes):
        self.data = data
        self.header: Optional[DexHeader] = None
        self.string_table: list[str] = []
        self.type_table: list[str] = []
        self.proto_table: list[DexProtoId] = []
        self.field_table: list[DexFieldId] = []
        self.method_table: list[DexMethodId] = []
        self.class_defs: list[DexClassDef] = []
        self.class_names: list[str] = []
        self.method_names: list[str] = []
        self.field_names: list[str] = []
        self.full_method_refs: list[str] = []
        self.full_field_refs: list[str] = []

    def parse(self) -> bool:
        """Parse the DEX file. Returns True on success."""
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
        """Read MUTF-8 encoded string from DEX data."""
        if offset >= len(self.data):
            return ""
        # First read the ULEB128 encoded size
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
        # Read the string bytes
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
                    b2 = self.data[pos]
                    pos += 1
                    result.append(chr(((b & 0x1F) << 6) | (b2 & 0x3F)))
                else:
                    break
            elif (b & 0xF0) == 0xE0:
                if pos + 1 < len(self.data):
                    b2 = self.data[pos]
                    b3 = self.data[pos + 1]
                    pos += 2
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
            self.class_defs.append(DexClassDef(*vals))

    def _build_references(self):
        """Build full method and field reference strings."""
        for cd in self.class_defs:
            if cd.class_idx < len(self.type_table):
                self.class_names.append(self.type_table[cd.class_idx])

        for mid in self.method_table:
            class_name = self.type_table[mid.class_idx] if mid.class_idx < len(self.type_table) else "?"
            method_name = self.string_table[mid.name_idx] if mid.name_idx < len(self.string_table) else "?"
            self.method_names.append(method_name)
            self.full_method_refs.append(f"{class_name}->{method_name}")

        for fid in self.field_table:
            class_name = self.type_table[fid.class_idx] if fid.class_idx < len(self.type_table) else "?"
            field_name = self.string_table[fid.name_idx] if fid.name_idx < len(self.string_table) else "?"
            self.field_names.append(field_name)
            self.full_field_refs.append(f"{class_name}->{field_name}")

    def dex_type_to_java(self, dex_type: str) -> str:
        """Convert DEX type descriptor to Java class name."""
        if not dex_type:
            return ""
        if dex_type.startswith("L") and dex_type.endswith(";"):
            return dex_type[1:-1].replace("/", ".")
        return dex_type

    def get_java_class_names(self) -> list[str]:
        """Get all class names in Java dot notation."""
        return [self.dex_type_to_java(cn) for cn in self.class_names]

    def is_obfuscated(self, name: str) -> bool:
        """Heuristic: detect if a class/method name is obfuscated."""
        parts = name.split(".")
        if not parts:
            return False
        last = parts[-1]
        # Single letter or very short names that are not standard
        if len(last) <= 2 and last.isalpha() and last.islower():
            return True
        # All lowercase single chars in package
        short_parts = [p for p in parts if len(p) <= 2 and p.isalpha()]
        if len(short_parts) > len(parts) * 0.6:
            return True
        return False


# ===========================================================================
# VULNERABILITY PATTERNS DATABASE
# ===========================================================================

@dataclass
class VulnPattern:
    """Vulnerability detection pattern."""
    vuln_id: str
    name: str
    severity: str  # CRITICAL, HIGH, MEDIUM, LOW, INFO
    cve_cwe: str   # CVE or CWE identifier
    cvss: float    # Estimated CVSS score
    description: str
    remediation: str
    confidence: str  # high, medium, low
    # Detection: list of method/class/string patterns
    class_patterns: list[str] = field(default_factory=list)
    method_patterns: list[str] = field(default_factory=list)
    string_patterns: list[str] = field(default_factory=list)
    field_patterns: list[str] = field(default_factory=list)
    combined_patterns: list[tuple[str, str]] = field(default_factory=list)


VULN_PATTERNS: list[VulnPattern] = [
    # --- INSECURE CRYPTO ---
    VulnPattern(
        vuln_id="CRYPTO-001",
        name="DES/3DES Weak Cipher",
        severity="HIGH",
        cve_cwe="CWE-327",
        cvss=7.5,
        description="Use of DES or 3DES cipher which is cryptographically weak and deprecated.",
        remediation="Replace with AES-256-GCM or ChaCha20-Poly1305.",
        confidence="high",
        string_patterns=[r"DES/", r"DESede/", r"DESede", r'"DES"'],
        method_patterns=[r"Cipher->getInstance"],
    ),
    VulnPattern(
        vuln_id="CRYPTO-002",
        name="RC4 Stream Cipher",
        severity="HIGH",
        cve_cwe="CWE-327",
        cvss=7.5,
        description="RC4 cipher is broken and should not be used for any purpose.",
        remediation="Use AES-GCM or ChaCha20-Poly1305 instead.",
        confidence="high",
        string_patterns=[r"RC4", r"ARCFOUR", r"ARC4"],
        method_patterns=[r"Cipher->getInstance"],
    ),
    VulnPattern(
        vuln_id="CRYPTO-003",
        name="ECB Mode Usage",
        severity="HIGH",
        cve_cwe="CWE-327",
        cvss=7.0,
        description="ECB mode does not provide semantic security; identical plaintext blocks produce identical ciphertext.",
        remediation="Use CBC, CTR, or GCM mode with proper IV/nonce.",
        confidence="high",
        string_patterns=[r"AES/ECB", r"/ECB/"],
    ),
    VulnPattern(
        vuln_id="CRYPTO-004",
        name="MD5 for Security Purpose",
        severity="MEDIUM",
        cve_cwe="CWE-328",
        cvss=5.3,
        description="MD5 is cryptographically broken; collision attacks are practical.",
        remediation="Use SHA-256 or SHA-3 for integrity, bcrypt/scrypt/Argon2 for passwords.",
        confidence="medium",
        string_patterns=[r'"MD5"', r"MD5"],
        method_patterns=[r"MessageDigest->getInstance"],
    ),
    VulnPattern(
        vuln_id="CRYPTO-005",
        name="Hardcoded Cryptographic Key",
        severity="CRITICAL",
        cve_cwe="CWE-321",
        cvss=9.1,
        description="Hardcoded cryptographic keys can be extracted from the APK by any attacker.",
        remediation="Use Android Keystore or derive keys from user credentials with proper KDF.",
        confidence="medium",
        method_patterns=[r"SecretKeySpec-><init>", r"SecretKeySpec->init"],
        string_patterns=[r"SecretKeySpec"],
    ),
    VulnPattern(
        vuln_id="CRYPTO-006",
        name="Static IV/Nonce",
        severity="HIGH",
        cve_cwe="CWE-329",
        cvss=7.0,
        description="Using a static initialization vector makes encryption deterministic and vulnerable to attacks.",
        remediation="Generate a random IV for each encryption operation using SecureRandom.",
        confidence="medium",
        method_patterns=[r"IvParameterSpec-><init>"],
        string_patterns=[r"IvParameterSpec"],
    ),

    # --- WEAK SSL/TLS ---
    VulnPattern(
        vuln_id="SSL-001",
        name="Trust All Certificates",
        severity="CRITICAL",
        cve_cwe="CWE-295",
        cvss=9.1,
        description="Custom TrustManager that accepts all certificates enables MITM attacks.",
        remediation="Use system default TrustManager or pin specific certificates.",
        confidence="high",
        string_patterns=[r"TrustAllCertificates", r"AllowAllTrustManager",
                        r"NullTrustManager", r"UnsafeTrustManager",
                        r"AcceptAllTrustManager", r"TrustAllManager"],
        method_patterns=[r"X509TrustManager->checkServerTrusted",
                        r"X509TrustManager->checkClientTrusted"],
    ),
    VulnPattern(
        vuln_id="SSL-002",
        name="AllowAllHostnameVerifier",
        severity="CRITICAL",
        cve_cwe="CVE-2014-3566",
        cvss=8.1,
        description="Hostname verification disabled; server identity not validated.",
        remediation="Use default HostnameVerifier or implement proper hostname checking.",
        confidence="high",
        string_patterns=[r"AllowAllHostnameVerifier", r"ALLOW_ALL_HOSTNAME_VERIFIER",
                        r"NoopHostnameVerifier", r"NullHostnameVerifier"],
        method_patterns=[r"HostnameVerifier->verify"],
    ),
    VulnPattern(
        vuln_id="SSL-003",
        name="SSLSocketFactory with No Verification",
        severity="HIGH",
        cve_cwe="CWE-295",
        cvss=7.4,
        description="Custom SSLSocketFactory that bypasses certificate verification.",
        remediation="Use default SSLSocketFactory or configure proper certificate validation.",
        confidence="medium",
        method_patterns=[r"SSLSocketFactory->createSocket", r"SSLContext->init"],
        string_patterns=[r"SSLSocketFactory", r"TrustManager"],
    ),
    VulnPattern(
        vuln_id="SSL-004",
        name="Cleartext HTTP Traffic",
        severity="MEDIUM",
        cve_cwe="CWE-319",
        cvss=5.9,
        description="Application uses cleartext HTTP traffic which can be intercepted.",
        remediation="Use HTTPS for all network communications. Set usesCleartextTraffic=false.",
        confidence="medium",
        string_patterns=[r"usesCleartextTraffic"],
    ),

    # --- SQL INJECTION ---
    VulnPattern(
        vuln_id="SQLI-001",
        name="SQL Injection via rawQuery",
        severity="HIGH",
        cve_cwe="CWE-89",
        cvss=8.6,
        description="Use of rawQuery with potential string concatenation enables SQL injection.",
        remediation="Use parameterized queries with selectionArgs parameter.",
        confidence="medium",
        method_patterns=[r"SQLiteDatabase->rawQuery", r"rawQuery"],
        string_patterns=[r"rawQuery"],
    ),
    VulnPattern(
        vuln_id="SQLI-002",
        name="SQL Injection via execSQL",
        severity="HIGH",
        cve_cwe="CWE-89",
        cvss=8.6,
        description="execSQL with user-controlled input can lead to SQL injection.",
        remediation="Use parameterized statements or ContentValues for data manipulation.",
        confidence="medium",
        method_patterns=[r"SQLiteDatabase->execSQL", r"execSQL"],
        string_patterns=[r"execSQL"],
    ),

    # --- PATH TRAVERSAL ---
    VulnPattern(
        vuln_id="PATH-001",
        name="Path Traversal Vulnerability",
        severity="HIGH",
        cve_cwe="CWE-22",
        cvss=7.5,
        description="File operations with unsanitized input may allow directory traversal attacks.",
        remediation="Validate and canonicalize file paths; reject paths containing '..'.",
        confidence="low",
        string_patterns=[r"\.\./", r"\.\.\\", r"getExternalStorage", r"getFilesDir"],
        method_patterns=[r"File-><init>", r"FileInputStream-><init>"],
    ),

    # --- INSECURE WEBVIEW ---
    VulnPattern(
        vuln_id="WEBVIEW-001",
        name="JavaScript Enabled WebView with Interface",
        severity="CRITICAL",
        cve_cwe="CVE-2012-6636",
        cvss=9.8,
        description="WebView with JavaScript enabled and addJavascriptInterface exposes Java objects to JS code. On API<17, all public methods are accessible via reflection.",
        remediation="Remove addJavascriptInterface or target API>=17 with @JavascriptInterface annotation.",
        confidence="high",
        method_patterns=[r"WebView->addJavascriptInterface",
                        r"WebSettings->setJavaScriptEnabled",
                        r"addJavascriptInterface"],
        string_patterns=[r"setJavaScriptEnabled", r"addJavascriptInterface"],
    ),
    VulnPattern(
        vuln_id="WEBVIEW-002",
        name="WebView File Access Enabled",
        severity="HIGH",
        cve_cwe="CWE-749",
        cvss=7.5,
        description="WebView with file access can read local files and exfiltrate data.",
        remediation="Disable file access: setAllowFileAccess(false), setAllowFileAccessFromFileURLs(false).",
        confidence="medium",
        method_patterns=[r"WebSettings->setAllowFileAccess",
                        r"WebSettings->setAllowUniversalAccessFromFileURLs",
                        r"WebSettings->setAllowFileAccessFromFileURLs"],
        string_patterns=[r"setAllowFileAccess", r"setAllowUniversalAccessFromFileURLs",
                        r"setAllowFileAccessFromFileURLs"],
    ),

    # --- INSECURE DATA STORAGE ---
    VulnPattern(
        vuln_id="STORAGE-001",
        name="World-Readable/Writable SharedPreferences",
        severity="HIGH",
        cve_cwe="CWE-312",
        cvss=7.5,
        description="SharedPreferences with MODE_WORLD_READABLE/WRITABLE accessible by any app.",
        remediation="Use MODE_PRIVATE and EncryptedSharedPreferences for sensitive data.",
        confidence="high",
        string_patterns=[r"MODE_WORLD_READABLE", r"MODE_WORLD_WRITABLE",
                        r"getSharedPreferences"],
        method_patterns=[r"Context->getSharedPreferences"],
    ),
    VulnPattern(
        vuln_id="STORAGE-002",
        name="Plaintext Credential Storage",
        severity="HIGH",
        cve_cwe="CWE-312",
        cvss=7.5,
        description="Storing credentials in plaintext (SharedPreferences/SQLite) without encryption.",
        remediation="Use EncryptedSharedPreferences or Android Keystore for credential storage.",
        confidence="low",
        string_patterns=[r"password", r"passwd", r"credential", r"api_key",
                        r"access_token", r"secret_key", r"auth_token"],
        method_patterns=[r"SharedPreferences->edit", r"Editor->putString"],
    ),

    # --- INTENT INJECTION ---
    VulnPattern(
        vuln_id="INTENT-001",
        name="Implicit Intent with Sensitive Data",
        severity="MEDIUM",
        cve_cwe="CWE-927",
        cvss=5.5,
        description="Implicit intents can be intercepted by malicious apps on the device.",
        remediation="Use explicit intents for sensitive data or verify receiver with permissions.",
        confidence="low",
        method_patterns=[r"Intent-><init>", r"startActivity", r"sendBroadcast"],
        string_patterns=[r"sendBroadcast", r"startActivity"],
    ),

    # --- INSECURE RANDOM ---
    VulnPattern(
        vuln_id="RANDOM-001",
        name="Insecure Random Number Generator",
        severity="MEDIUM",
        cve_cwe="CWE-330",
        cvss=5.3,
        description="java.util.Random is not cryptographically secure; predictable output.",
        remediation="Use java.security.SecureRandom for all security-sensitive randomness.",
        confidence="medium",
        method_patterns=[r"Random-><init>", r"Random->nextInt", r"Random->nextBytes"],
        class_patterns=[r"java/util/Random"],
    ),

    # --- LOGGING ---
    VulnPattern(
        vuln_id="LOG-001",
        name="Sensitive Data in Logs",
        severity="MEDIUM",
        cve_cwe="CWE-532",
        cvss=5.3,
        description="Logging sensitive information (passwords, tokens) visible via logcat.",
        remediation="Remove sensitive logging in production builds or use ProGuard to strip Log calls.",
        confidence="low",
        method_patterns=[r"Log->d", r"Log->v", r"Log->i", r"Log->w", r"Log->e"],
        string_patterns=[r"Log.d(", r"Log.v(", r"Log.i("],
    ),

    # --- BACKUP VULNERABILITY ---
    VulnPattern(
        vuln_id="BACKUP-001",
        name="Application Backup Allowed",
        severity="MEDIUM",
        cve_cwe="CWE-921",
        cvss=5.3,
        description="allowBackup=true allows extraction of app data via adb backup.",
        remediation="Set android:allowBackup=\"false\" or implement BackupAgent with encryption.",
        confidence="high",
        string_patterns=[r"allowBackup"],
    ),

    # --- DEBUGGABLE ---
    VulnPattern(
        vuln_id="DEBUG-001",
        name="Debuggable Application",
        severity="HIGH",
        cve_cwe="CWE-489",
        cvss=7.5,
        description="android:debuggable=true allows attaching debugger and accessing app internals.",
        remediation="Remove android:debuggable or set to false for production builds.",
        confidence="high",
        string_patterns=[r"debuggable"],
    ),

    # --- TAPJACKING ---
    VulnPattern(
        vuln_id="TAP-001",
        name="Tapjacking Vulnerability",
        severity="MEDIUM",
        cve_cwe="CWE-1021",
        cvss=4.7,
        description="Views without filterTouchesWhenObscured are vulnerable to overlay attacks.",
        remediation="Set android:filterTouchesWhenObscured=\"true\" on sensitive UI elements.",
        confidence="low",
        string_patterns=[r"filterTouchesWhenObscured"],
    ),

    # --- FRAGMENT INJECTION ---
    VulnPattern(
        vuln_id="FRAG-001",
        name="Fragment Injection",
        severity="HIGH",
        cve_cwe="CVE-2013-6271",
        cvss=7.5,
        description="Exported PreferenceActivity allows loading arbitrary fragments.",
        remediation="Override isValidFragment() in PreferenceActivity subclasses.",
        confidence="medium",
        class_patterns=[r"PreferenceActivity"],
        method_patterns=[r"PreferenceActivity->isValidFragment"],
        string_patterns=[r"PreferenceActivity"],
    ),

    # --- ZIP SLIP ---
    VulnPattern(
        vuln_id="ZIP-001",
        name="Zip Slip Path Traversal",
        severity="HIGH",
        cve_cwe="CWE-22",
        cvss=7.5,
        description="ZipEntry extraction without path validation enables arbitrary file overwrite.",
        remediation="Validate ZipEntry.getName() does not contain '..' before extraction.",
        confidence="medium",
        method_patterns=[r"ZipEntry->getName", r"ZipInputStream->getNextEntry"],
        string_patterns=[r"ZipEntry", r"ZipInputStream", r"getNextEntry"],
    ),

    # --- DESERIALIZATION ---
    VulnPattern(
        vuln_id="DESER-001",
        name="Insecure Deserialization",
        severity="HIGH",
        cve_cwe="CWE-502",
        cvss=8.1,
        description="ObjectInputStream without type validation enables arbitrary code execution.",
        remediation="Use allowlisted ObjectInputStream or switch to safe serialization (JSON, Protocol Buffers).",
        confidence="medium",
        method_patterns=[r"ObjectInputStream-><init>", r"ObjectInputStream->readObject"],
        string_patterns=[r"ObjectInputStream", r"readObject"],
    ),

    # --- COMMAND INJECTION ---
    VulnPattern(
        vuln_id="CMD-001",
        name="Command Injection Risk",
        severity="CRITICAL",
        cve_cwe="CWE-78",
        cvss=9.8,
        description="Runtime.exec or ProcessBuilder with potential user input enables OS command injection.",
        remediation="Avoid Runtime.exec with user input; use specific APIs instead of shell commands.",
        confidence="medium",
        method_patterns=[r"Runtime->exec", r"ProcessBuilder-><init>",
                        r"Runtime->getRuntime"],
        string_patterns=[r"Runtime.getRuntime", r"ProcessBuilder"],
    ),

    # --- CLIPBOARD ---
    VulnPattern(
        vuln_id="CLIP-001",
        name="Clipboard Data Leakage",
        severity="LOW",
        cve_cwe="CWE-200",
        cvss=3.3,
        description="Sensitive data placed on clipboard is accessible to all apps.",
        remediation="Avoid copying sensitive data to clipboard; use ClipData.newPlainText with PersistableBundle flags.",
        confidence="low",
        method_patterns=[r"ClipboardManager->setPrimaryClip", r"ClipData->newPlainText"],
        string_patterns=[r"ClipboardManager", r"setPrimaryClip"],
    ),

    # --- DEEP LINK ABUSE ---
    VulnPattern(
        vuln_id="DEEP-001",
        name="Unvalidated Deep Links",
        severity="MEDIUM",
        cve_cwe="CWE-939",
        cvss=5.3,
        description="Deep link handlers without input validation can be exploited by malicious apps.",
        remediation="Validate all deep link parameters; use App Links with Digital Asset Links for verification.",
        confidence="low",
        string_patterns=[r"android.intent.action.VIEW", r"android:scheme",
                        r"android:host", r"intent-filter"],
        method_patterns=[r"Intent->getData", r"Intent->getDataString"],
    ),
]


# ===========================================================================
# KNOWN VULNERABLE LIBRARIES DATABASE
# ===========================================================================

@dataclass
class VulnLibrary:
    """Known vulnerable library entry."""
    name: str
    package_pattern: str  # Regex for class path detection
    vulnerable_versions: str
    cve: str
    severity: str
    cvss: float
    description: str
    remediation: str


VULN_LIBRARIES: list[VulnLibrary] = [
    VulnLibrary(
        name="OkHttp (< 3.12.1)",
        package_pattern=r"com/squareup/okhttp3?/",
        vulnerable_versions="< 3.12.1",
        cve="CVE-2018-20200",
        severity="HIGH",
        cvss=7.4,
        description="OkHttp versions before 3.12.1 are vulnerable to certificate pinning bypass.",
        remediation="Update OkHttp to >= 3.12.1 or latest 4.x version.",
    ),
    VulnLibrary(
        name="Apache HttpClient (deprecated)",
        package_pattern=r"org/apache/http/",
        vulnerable_versions="All versions",
        cve="CVE-2014-3577",
        severity="MEDIUM",
        cvss=5.9,
        description="Apache HttpClient for Android is deprecated and has known hostname verification issues.",
        remediation="Migrate to HttpURLConnection, OkHttp, or Retrofit.",
    ),
    VulnLibrary(
        name="BouncyCastle (old versions)",
        package_pattern=r"org/bouncycastle/|org/spongycastle/",
        vulnerable_versions="< 1.61",
        cve="CVE-2018-1000613",
        severity="HIGH",
        cvss=7.5,
        description="Old BouncyCastle versions have multiple vulnerabilities in key parsing.",
        remediation="Update to BouncyCastle >= 1.70.",
    ),
    VulnLibrary(
        name="Jackson Databind",
        package_pattern=r"com/fasterxml/jackson/databind/",
        vulnerable_versions="< 2.13.4",
        cve="CVE-2020-36518",
        severity="HIGH",
        cvss=7.5,
        description="Jackson-databind has deserialization vulnerabilities allowing DoS or RCE.",
        remediation="Update to Jackson >= 2.13.4 or 2.14.x.",
    ),
    VulnLibrary(
        name="Gson (CVE-2022-25647)",
        package_pattern=r"com/google/gson/",
        vulnerable_versions="< 2.8.9",
        cve="CVE-2022-25647",
        severity="HIGH",
        cvss=7.5,
        description="Gson before 2.8.9 is vulnerable to DoS via deserialization of untrusted data.",
        remediation="Update Gson to >= 2.8.9.",
    ),
    VulnLibrary(
        name="Facebook SDK (old)",
        package_pattern=r"com/facebook/",
        vulnerable_versions="< 12.0",
        cve="CVE-2020-25870",
        severity="MEDIUM",
        cvss=5.3,
        description="Old Facebook SDK versions may leak access tokens.",
        remediation="Update to latest Facebook SDK.",
    ),
    VulnLibrary(
        name="Glide Image Loader",
        package_pattern=r"com/bumptech/glide/",
        vulnerable_versions="< 4.11.0",
        cve="CVE-2019-10773",
        severity="MEDIUM",
        cvss=5.3,
        description="Glide older versions may have SSRF or path traversal in image loading.",
        remediation="Update Glide to >= 4.14.x.",
    ),
    VulnLibrary(
        name="Retrofit",
        package_pattern=r"retrofit2/|retrofit/",
        vulnerable_versions="< 2.5.0",
        cve="CWE-295",
        severity="MEDIUM",
        cvss=5.3,
        description="Old Retrofit versions may not enforce TLS properly.",
        remediation="Update Retrofit to >= 2.9.x.",
    ),
    VulnLibrary(
        name="Picasso Image Loader",
        package_pattern=r"com/squareup/picasso/",
        vulnerable_versions="< 2.8",
        cve="CWE-295",
        severity="LOW",
        cvss=3.7,
        description="Old Picasso versions may load images over HTTP without TLS verification.",
        remediation="Update Picasso to latest version.",
    ),
    VulnLibrary(
        name="Volley HTTP Library",
        package_pattern=r"com/android/volley/",
        vulnerable_versions="< 1.2.0",
        cve="CWE-295",
        severity="MEDIUM",
        cvss=5.3,
        description="Old Volley versions may have improper certificate validation.",
        remediation="Update Volley to >= 1.2.x.",
    ),
    VulnLibrary(
        name="Butterknife (deprecated)",
        package_pattern=r"butterknife/",
        vulnerable_versions="All (deprecated)",
        cve="CWE-1104",
        severity="LOW",
        cvss=3.1,
        description="Butterknife is deprecated and no longer maintained; potential unpatched issues.",
        remediation="Migrate to ViewBinding.",
    ),
    VulnLibrary(
        name="EventBus",
        package_pattern=r"org/greenrobot/eventbus/",
        vulnerable_versions="< 3.2.0",
        cve="CWE-502",
        severity="LOW",
        cvss=3.7,
        description="EventBus can be exploited for inter-component data injection if exported.",
        remediation="Update EventBus and avoid using with exported components.",
    ),
    VulnLibrary(
        name="Firebase Database",
        package_pattern=r"com/google/firebase/database/",
        vulnerable_versions="Misconfigured",
        cve="CWE-284",
        severity="MEDIUM",
        cvss=5.3,
        description="Firebase Realtime Database may have misconfigured security rules.",
        remediation="Review Firebase security rules; restrict read/write access.",
    ),
    VulnLibrary(
        name="Dagger (old)",
        package_pattern=r"dagger/",
        vulnerable_versions="< 2.38",
        cve="CWE-1104",
        severity="LOW",
        cvss=3.1,
        description="Old Dagger versions may have dependency confusion issues.",
        remediation="Update Dagger to latest version.",
    ),
]

# Analytics/tracking SDK patterns
TRACKING_SDKS: dict[str, str] = {
    "com/google/firebase/analytics/": "Firebase Analytics",
    "com/google/android/gms/analytics/": "Google Analytics",
    "com/facebook/appevents/": "Facebook Analytics",
    "com/mixpanel/": "Mixpanel",
    "com/amplitude/": "Amplitude",
    "com/segment/": "Segment",
    "com/appsflyer/": "AppsFlyer",
    "com/adjust/": "Adjust SDK",
    "com/crashlytics/": "Crashlytics",
    "io/sentry/": "Sentry",
    "com/bugsnag/": "Bugsnag",
    "com/newrelic/": "New Relic",
    "com/flurry/": "Flurry Analytics",
    "com/kochava/": "Kochava",
    "com/branch/": "Branch.io",
    "com/airship/": "Urban Airship",
    "com/onesignal/": "OneSignal",
    "com/braze/": "Braze (Appboy)",
    "com/clevertap/": "CleverTap",
    "ly/count/android/": "Countly",
}

# Anti-debugging/anti-root detection patterns
SECURITY_CHECKS: dict[str, str] = {
    "isRooted": "Root detection",
    "isDeviceRooted": "Root detection",
    "RootBeer": "RootBeer library (root detection)",
    "su": "Superuser binary check",
    "Superuser": "Superuser app detection",
    "com/scottyab/rootbeer/": "RootBeer library",
    "isDebuggerConnected": "Debugger detection",
    "Debug.isDebuggerConnected": "Debugger detection",
    "android.os.Debug": "Debug class usage",
    "TracerPid": "Anti-ptrace check",
    "frida": "Frida detection",
    "xposed": "Xposed detection",
    "substrate": "Cydia Substrate detection",
    "SafetyNet": "Google SafetyNet",
    "PlayIntegrity": "Play Integrity API",
    "isEmulator": "Emulator detection",
    "tamper": "Tamper detection",
    "integrity": "Integrity check",
}


# ===========================================================================
# SECRET PATTERNS (kept from original + expanded)
# ===========================================================================

SECRET_PATTERNS: list[tuple[str, str, str]] = [
    ("Google API Key",            "HIGH",   r"AIza[0-9A-Za-z_\-]{35}"),
    ("Google OAuth Access Token", "HIGH",   r"ya29\.[0-9A-Za-z_\-]+"),
    ("Firebase URL",              "MEDIUM", r"https?://[a-z0-9\-]+\.firebaseio\.com"),
    ("Firebase Cloud Messaging",  "MEDIUM", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}"),
    ("AWS Access Key ID",         "CRITICAL", r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b"),
    ("AWS Secret Access Key",     "CRITICAL", r"(?i)aws(.{0,20})?(secret|sk)[\"'\s:=]{1,5}[A-Za-z0-9/+=]{40}"),
    ("AWS S3 URL",                "LOW",    r"[a-z0-9.\-]+\.s3[\.\-][a-z0-9\-]*\.amazonaws\.com"),
    ("Slack Token",               "HIGH",   r"xox[abprs]-[0-9A-Za-z\-]{10,}"),
    ("Slack Webhook",             "HIGH",   r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("GitHub Token",              "CRITICAL", r"\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b"),
    ("Stripe Secret Key",         "CRITICAL", r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    ("Stripe Publishable Key",    "LOW",    r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
    ("Twilio Account SID",        "HIGH",   r"\bAC[a-f0-9]{32}\b"),
    ("Twilio Auth Token",         "HIGH",   r"(?i)twilio.{0,20}[\"'\s:=]{1,5}[a-f0-9]{32}"),
    ("SendGrid API Key",          "HIGH",   r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("Mapbox Token",              "MEDIUM", r"\bpk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ("Square Access Token",       "HIGH",   r"\bsq0atp-[0-9A-Za-z_\-]{22}\b"),
    ("PayPal Braintree Token",    "HIGH",   r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"),
    ("Heroku API Key",            "HIGH",   r"(?i)heroku.{0,20}[\"'\s:=]{1,5}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("Generic Bearer JWT",        "MEDIUM", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("PEM Private Key",           "CRITICAL", r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("Authorization Header",      "HIGH",   r"(?i)Authorization:\s*(?:Bearer|Basic|Token)\s+[A-Za-z0-9._\-=/+]{8,}"),
    ("Basic Auth in URL",         "CRITICAL", r"https?://[^/\s:@]+:[^/\s:@]+@[A-Za-z0-9.\-]+"),
    ("Hardcoded Password",        "HIGH",   r'(?i)(?:password|passwd|pwd)\s*[:=]\s*["\'][^"\'\s]{4,}["\']'),
    ("Hardcoded Secret",          "HIGH",   r'(?i)(?:secret|api[_\-]?key|apikey|access[_\-]?key|client[_\-]?secret)\s*[:=]\s*["\'][A-Za-z0-9._\-]{8,}["\']'),
    ("Telegram Bot Token",        "HIGH",   r"\b\d{8,10}:[A-Za-z0-9_\-]{35}\b"),
    ("Discord Bot Token",         "HIGH",   r"\b[MN][A-Za-z\d]{23,}\.[\w-]{6}\.[\w-]{27}\b"),
    ("Mailgun API Key",           "HIGH",   r"\bkey-[0-9a-zA-Z]{32}\b"),
    ("Azure Storage Key",         "HIGH",   r"(?i)DefaultEndpointsProtocol=https;AccountName=[^;]+;AccountKey=[A-Za-z0-9+/=]{88}"),
    ("DigitalOcean Token",        "HIGH",   r"\b(?:dop_v1_)[a-f0-9]{64}\b"),
    ("Algolia API Key",           "MEDIUM", r"(?i)algolia.{0,20}[\"'\s:=]{1,5}[a-f0-9]{32}"),
]

URL_PATTERN = re.compile(rb"https?://[A-Za-z0-9._\-:/?#\[\]@!$&'()*+,;=%~]+", re.IGNORECASE)
IP_PATTERN = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?::\d{2,5})?\b")

NOISE_HOSTS = (
    "schemas.android.com", "schemas.google.com",
    "www.w3.org", "ns.adobe.com",
    "play.google.com", "developer.android.com",
    "fonts.google.com", "fonts.gstatic.com",
    "www.google.com/schemas",
)

DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS",
    "android.permission.RECEIVE_SMS", "android.permission.READ_CONTACTS",
    "android.permission.WRITE_CONTACTS", "android.permission.READ_CALL_LOG",
    "android.permission.WRITE_CALL_LOG", "android.permission.RECORD_AUDIO",
    "android.permission.CAMERA", "android.permission.ACCESS_FINE_LOCATION",
    "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE",
    "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE",
    "android.permission.READ_PHONE_NUMBERS",
    "android.permission.SYSTEM_ALERT_WINDOW",
    "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS",
    "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.GET_ACCOUNTS", "android.permission.USE_FINGERPRINT",
    "android.permission.BIND_DEVICE_ADMIN",
    "android.permission.WRITE_SETTINGS",
    "android.permission.BIND_NOTIFICATION_LISTENER_SERVICE",
}


# ===========================================================================
# FINDING / REPORT DATA STRUCTURES
# ===========================================================================

@dataclass
class Finding:
    """Single security finding."""
    category: str        # secret, vuln, library, manifest, network, info
    severity: str        # CRITICAL, HIGH, MEDIUM, LOW, INFO
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

    def key(self) -> str:
        return f"{self.category}|{self.name}|{self.value[:100]}|{self.source_file}"


@dataclass
class DexInfo:
    """Info about a parsed DEX file."""
    filename: str
    class_count: int = 0
    method_count: int = 0
    field_count: int = 0
    string_count: int = 0
    obfuscated_class_count: int = 0
    total_class_count: int = 0


@dataclass
class CertInfo:
    """APK signing certificate info."""
    filename: str = ""
    issuer: str = ""
    subject: str = ""
    serial: str = ""
    fingerprint_sha256: str = ""
    fingerprint_md5: str = ""


@dataclass
class Report:
    """Complete analysis report."""
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
    permissions: list[str] = field(default_factory=list)
    dangerous_permissions: list[str] = field(default_factory=list)
    exported_components: list[str] = field(default_factory=list)
    dex_info: list[DexInfo] = field(default_factory=list)
    cert_info: Optional[CertInfo] = None
    detected_libraries: list[str] = field(default_factory=list)
    tracking_sdks: list[str] = field(default_factory=list)
    security_checks: list[str] = field(default_factory=list)
    obfuscation_score: float = 0.0
    findings: list[Finding] = field(default_factory=list)
    summary: dict = field(default_factory=dict)

    def to_dict(self) -> dict:
        d = asdict(self)
        return d


# ===========================================================================
# AXML (Binary Android Manifest) PARSER
# ===========================================================================

def parse_axml_strings(data: bytes) -> list[str]:
    """Extract all strings from binary AXML (AndroidManifest.xml)."""
    if len(data) < 8:
        return []
    if data[:4] != b"\x03\x00\x08\x00":
        return []
    pos = 8
    if pos + 8 > len(data):
        return []
    chunk_type = int.from_bytes(data[pos:pos+2], "little")
    if chunk_type != 0x0001:
        return []
    header_size = int.from_bytes(data[pos+2:pos+4], "little")
    chunk_size = int.from_bytes(data[pos+4:pos+8], "little")
    string_count = int.from_bytes(data[pos+8:pos+12], "little")
    flags = int.from_bytes(data[pos+16:pos+20], "little")
    strings_start = int.from_bytes(data[pos+20:pos+24], "little")
    is_utf8 = bool(flags & (1 << 8))
    offsets_base = pos + header_size
    strings_base = pos + strings_start
    out: list[str] = []
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
# MAIN SCANNER CLASS
# ===========================================================================

class APKDeepAnalyzer:
    """Advanced APK security analyzer with DEX parsing and CVE mapping."""

    def __init__(self, apk_path: str, min_str_len: int = 6):
        self.apk_path = apk_path
        self.min_str_len = min_str_len
        self.report = Report(
            apk_path=apk_path,
            apk_size=os.path.getsize(apk_path),
            apk_md5=self._hash("md5"),
            apk_sha256=self._hash("sha256"),
            scan_time=time.strftime("%Y-%m-%d %H:%M:%S UTC", time.gmtime()),
        )
        self._compiled_secrets = [(n, s, re.compile(p)) for n, s, p in SECRET_PATTERNS]
        self._seen: set[str] = set()
        self._all_dex_strings: set[str] = set()
        self._all_class_names: set[str] = set()
        self._all_method_refs: set[str] = set()
        self._all_field_refs: set[str] = set()
        self._dex_parsers: list[DexParser] = []
        self._start_time = time.time()

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
        """Run full analysis and return the report."""
        with zipfile.ZipFile(self.apk_path, "r") as z:
            names = z.namelist()

            # 1. Parse AndroidManifest.xml
            if "AndroidManifest.xml" in names:
                self._analyze_manifest(z.read("AndroidManifest.xml"))

            # 2. Deep parse DEX files
            for n in sorted(names):
                if n.startswith("classes") and n.endswith(".dex"):
                    self._analyze_dex(z.read(n), n)

            # 3. Extract certificate info
            self._extract_cert_info(z, names)

            # 4. Scan resource files
            for n in names:
                if n == "AndroidManifest.xml":
                    continue
                if n.startswith("classes") and n.endswith(".dex"):
                    continue
                lower = n.lower()
                if (lower.endswith((".xml", ".json", ".txt", ".properties",
                                    ".js", ".html", ".htm", ".css",
                                    ".cfg", ".conf", ".ini", ".yml", ".yaml",
                                    ".pem", ".key", ".cer", ".crt"))
                    or lower.startswith("assets/")
                    or lower.startswith("res/raw/")
                    or lower == "resources.arsc"):
                    try:
                        data = z.read(n)
                    except Exception:
                        continue
                    self._scan_resource_blob(data, n)

        # 5. Run vulnerability pattern detection
        self._detect_vulnerabilities()

        # 6. Detect vulnerable libraries
        self._detect_vulnerable_libraries()

        # 7. Detect tracking SDKs
        self._detect_tracking_sdks()

        # 8. Detect security checks (anti-debug/root)
        self._detect_security_checks()

        # 9. Calculate obfuscation score
        self._calculate_obfuscation_score()

        # 10. Build summary
        self.report.scan_duration = round(time.time() - self._start_time, 2)
        self._build_summary()

        # Sort findings
        sev_order = {"CRITICAL": 0, "HIGH": 1, "MEDIUM": 2, "LOW": 3, "INFO": 4}
        self.report.findings.sort(key=lambda x: (sev_order.get(x.severity, 9), x.category, x.name))

        return self.report

    # ------------------------------------------------------------------
    # MANIFEST ANALYSIS
    # ------------------------------------------------------------------
    def _analyze_manifest(self, data: bytes):
        strings = parse_axml_strings(data)
        joined = "\n".join(strings)

        # Extract permissions
        perms = sorted({s for s in strings if "permission." in s and "." in s})
        self.report.permissions = perms
        self.report.dangerous_permissions = sorted(set(perms) & DANGEROUS_PERMISSIONS)

        # Flags detection
        if "usesCleartextTraffic" in joined:
            self.report.uses_cleartext = True
        if "debuggable" in joined:
            self.report.debuggable = True
        if "allowBackup" in joined:
            self.report.allow_backup = True

        # Exported components detection
        exported = []
        for s in strings:
            if s.startswith(".") or ("Activity" in s or "Service" in s or
                                     "Receiver" in s or "Provider" in s):
                if any(c.isupper() for c in s) and "." in s or s.startswith("."):
                    exported.append(s)
        self.report.exported_components = exported[:50]

        # Dangerous permissions findings
        for p in self.report.dangerous_permissions:
            self._add_finding(Finding(
                category="manifest",
                severity="MEDIUM",
                name="Dangerous Permission",
                description=f"App requests dangerous permission: {p}",
                value=p,
                source_file="AndroidManifest.xml",
                cve_cwe="CWE-250",
                cvss=4.3,
                remediation="Verify this permission is necessary; request at runtime with explanation.",
                confidence="high",
            ))

        if self.report.debuggable:
            self._add_finding(Finding(
                category="manifest",
                severity="HIGH",
                name="Debuggable Application",
                description="android:debuggable is referenced in manifest. If true in production, allows debugger attachment.",
                value="android:debuggable=true",
                source_file="AndroidManifest.xml",
                cve_cwe="CWE-489",
                cvss=7.5,
                remediation="Set android:debuggable=\"false\" for release builds.",
                confidence="high",
            ))

        if self.report.allow_backup:
            self._add_finding(Finding(
                category="manifest",
                severity="MEDIUM",
                name="Backup Allowed",
                description="allowBackup enables data extraction via adb backup on non-rooted devices.",
                value="android:allowBackup=true",
                source_file="AndroidManifest.xml",
                cve_cwe="CWE-921",
                cvss=5.3,
                remediation="Set android:allowBackup=\"false\" or implement encrypted BackupAgent.",
                confidence="high",
            ))

        if self.report.uses_cleartext:
            self._add_finding(Finding(
                category="manifest",
                severity="MEDIUM",
                name="Cleartext Traffic Allowed",
                description="usesCleartextTraffic allows HTTP connections, enabling MITM attacks.",
                value="usesCleartextTraffic=true",
                source_file="AndroidManifest.xml",
                cve_cwe="CWE-319",
                cvss=5.9,
                remediation="Set usesCleartextTraffic=\"false\" and use HTTPS for all connections.",
                confidence="medium",
            ))

        # Scan manifest strings for secrets
        for s in strings:
            self._scan_string_for_secrets(s, "AndroidManifest.xml")

    # ------------------------------------------------------------------
    # DEX DEEP ANALYSIS
    # ------------------------------------------------------------------
    def _analyze_dex(self, data: bytes, filename: str):
        """Parse DEX file structure and extract intelligence."""
        parser = DexParser(data)
        if not parser.parse():
            # Fallback: just extract strings
            self._scan_resource_blob(data, filename)
            return

        self._dex_parsers.append(parser)

        # Collect all info
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
        )
        self.report.dex_info.append(dex_info)

        # Store for vulnerability detection
        self._all_class_names.update(parser.class_names)
        self._all_method_refs.update(parser.full_method_refs)
        self._all_field_refs.update(parser.full_field_refs)
        self._all_dex_strings.update(parser.string_table)

        # Also scan string table for secrets
        for s in parser.string_table:
            if len(s) >= self.min_str_len:
                self._scan_string_for_secrets(s, filename)

        # Scan for URLs/IPs in raw DEX data
        self._extract_urls_ips(data, filename)

    # ------------------------------------------------------------------
    # VULNERABILITY DETECTION
    # ------------------------------------------------------------------
    def _detect_vulnerabilities(self):
        """Run all vulnerability patterns against collected DEX data."""
        for pattern in VULN_PATTERNS:
            matches = []

            # Check class patterns
            for cp in pattern.class_patterns:
                for cn in self._all_class_names:
                    if cp in cn:
                        matches.append(f"class:{cn}")

            # Check method patterns
            for mp in pattern.method_patterns:
                for mr in self._all_method_refs:
                    if mp in mr:
                        matches.append(f"method:{mr}")

            # Check string patterns
            for sp in pattern.string_patterns:
                for ds in self._all_dex_strings:
                    if sp in ds:
                        matches.append(f"string:{ds[:100]}")
                        break  # One match per pattern is enough

            # Check field patterns
            for fp in pattern.field_patterns:
                for fr in self._all_field_refs:
                    if fp in fr:
                        matches.append(f"field:{fr}")

            if matches:
                # Determine affected class/method from matches
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
                ))

    # ------------------------------------------------------------------
    # VULNERABLE LIBRARY DETECTION
    # ------------------------------------------------------------------
    def _detect_vulnerable_libraries(self):
        """Detect known vulnerable libraries from class paths and type references."""
        # Check both defined classes AND referenced types (libraries are usually referenced)
        all_types = self._all_class_names.copy()
        for dp in self._dex_parsers:
            all_types.update(dp.type_table)
        # Also check string table for library paths
        all_searchable = all_types | self._all_dex_strings

        for lib in VULN_LIBRARIES:
            regex = re.compile(lib.package_pattern)
            found_refs = []
            for item in all_searchable:
                if regex.search(item):
                    found_refs.append(item)

            if found_refs:
                self.report.detected_libraries.append(lib.name)
                self._add_finding(Finding(
                    category="library",
                    severity=lib.severity,
                    name=f"Potentially Vulnerable: {lib.name}",
                    description=lib.description,
                    value=f"Found {len(found_refs)} references matching {lib.package_pattern}",
                    source_file="DEX type/string table",
                    cve_cwe=lib.cve,
                    cvss=lib.cvss,
                    affected_class=found_refs[0] if found_refs else "",
                    remediation=lib.remediation,
                    confidence="medium",
                ))

    # ------------------------------------------------------------------
    # TRACKING SDK DETECTION
    # ------------------------------------------------------------------
    def _detect_tracking_sdks(self):
        """Detect analytics and tracking SDKs."""
        # Check types, classes, and string table
        all_types = self._all_class_names.copy()
        for dp in self._dex_parsers:
            all_types.update(dp.type_table)
        all_searchable = all_types | self._all_dex_strings

        for pattern, sdk_name in TRACKING_SDKS.items():
            for item in all_searchable:
                if pattern in item:
                    if sdk_name not in self.report.tracking_sdks:
                        self.report.tracking_sdks.append(sdk_name)
                    break

    # ------------------------------------------------------------------
    # SECURITY CHECKS DETECTION
    # ------------------------------------------------------------------
    def _detect_security_checks(self):
        """Detect anti-debugging and root detection mechanisms."""
        for pattern, check_name in SECURITY_CHECKS.items():
            found = False
            for s in self._all_dex_strings:
                if pattern.lower() in s.lower():
                    found = True
                    break
            if not found:
                for mr in self._all_method_refs:
                    if pattern in mr:
                        found = True
                        break
            if found and check_name not in self.report.security_checks:
                self.report.security_checks.append(check_name)

    # ------------------------------------------------------------------
    # OBFUSCATION SCORE
    # ------------------------------------------------------------------
    def _calculate_obfuscation_score(self):
        """Calculate how obfuscated the APK code is (0-100)."""
        if not self._dex_parsers:
            return
        total_classes = 0
        obfuscated_classes = 0
        for dp in self._dex_parsers:
            java_names = dp.get_java_class_names()
            total_classes += len(java_names)
            obfuscated_classes += sum(1 for n in java_names if dp.is_obfuscated(n))
        if total_classes > 0:
            self.report.obfuscation_score = round(
                (obfuscated_classes / total_classes) * 100, 1
            )

    # ------------------------------------------------------------------
    # CERTIFICATE EXTRACTION
    # ------------------------------------------------------------------
    def _extract_cert_info(self, z: zipfile.ZipFile, names: list[str]):
        """Extract signing certificate information from META-INF/."""
        cert_files = [n for n in names if n.startswith("META-INF/") and
                      n.upper().endswith((".RSA", ".DSA", ".EC"))]
        if not cert_files:
            return

        cert_file = cert_files[0]
        try:
            cert_data = z.read(cert_file)
            # Calculate fingerprints of the raw cert file
            sha256_fp = hashlib.sha256(cert_data).hexdigest()
            md5_fp = hashlib.md5(cert_data).hexdigest()

            # Try to extract readable strings from DER-encoded cert
            cert_strings = list(extract_ascii_strings(cert_data, 4))
            issuer = ""
            subject = ""
            for s in cert_strings:
                if "CN=" in s or "O=" in s or "OU=" in s:
                    if not issuer:
                        issuer = s
                    elif not subject:
                        subject = s

            self.report.cert_info = CertInfo(
                filename=cert_file,
                issuer=issuer,
                subject=subject,
                fingerprint_sha256=sha256_fp,
                fingerprint_md5=md5_fp,
            )
        except Exception:
            pass

    # ------------------------------------------------------------------
    # RESOURCE/STRING SCANNING
    # ------------------------------------------------------------------
    def _scan_resource_blob(self, data: bytes, source: str):
        """Scan a resource file for secrets and URLs."""
        for s in extract_ascii_strings(data, self.min_str_len):
            self._scan_string_for_secrets(s, source)
        for s in extract_utf16le_strings(data, self.min_str_len):
            self._scan_string_for_secrets(s, source)
        self._extract_urls_ips(data, source)

    def _scan_string_for_secrets(self, s: str, source: str):
        """Check a string against all secret patterns."""
        if not s or len(s) < 6:
            return
        for name, sev, rx in self._compiled_secrets:
            for m in rx.finditer(s):
                val = m.group(0)
                if len(val) > 400:
                    val = val[:400] + "..."
                ctx = s.strip()
                if len(ctx) > 200:
                    start = max(0, m.start() - 60)
                    end = min(len(s), m.end() + 60)
                    ctx = s[start:end].strip()
                self._add_finding(Finding(
                    category="secret",
                    severity=sev,
                    name=name,
                    description=f"Detected hardcoded {name} in application.",
                    value=val,
                    source_file=source,
                    cve_cwe="CWE-798",
                    cvss=7.5 if sev in ("CRITICAL", "HIGH") else 4.3,
                    remediation="Remove hardcoded secrets; use environment variables or secure vault.",
                    confidence="high",
                    context=ctx,
                ))

    def _extract_urls_ips(self, data: bytes, source: str):
        """Extract URLs and IPs from binary data."""
        for m in URL_PATTERN.finditer(data):
            try:
                url = m.group(0).decode("ascii", "ignore").rstrip(".,);:'\"")
            except Exception:
                continue
            if not url or any(h in url for h in NOISE_HOSTS):
                continue
            sev = "LOW"
            if url.lower().startswith("http://"):
                sev = "MEDIUM"
            self._add_finding(Finding(
                category="network",
                severity=sev,
                name="Hardcoded URL",
                description="Hardcoded URL found in application binary.",
                value=url[:300],
                source_file=source,
                cve_cwe="CWE-319" if sev == "MEDIUM" else "",
                cvss=5.9 if sev == "MEDIUM" else 2.0,
                remediation="Use HTTPS and externalize configuration.",
                confidence="high" if sev == "MEDIUM" else "low",
            ))

        for m in IP_PATTERN.finditer(data):
            ip = m.group(0).decode("ascii", "ignore")
            if ip.startswith(("0.", "127.", "255.", "240.", "10.", "192.168.")):
                continue
            self._add_finding(Finding(
                category="network",
                severity="LOW",
                name="Hardcoded IP Address",
                description="Hardcoded IP address may indicate backend infrastructure.",
                value=ip,
                source_file=source,
                remediation="Use domain names with proper DNS resolution.",
                confidence="low",
            ))

    # ------------------------------------------------------------------
    # HELPER
    # ------------------------------------------------------------------
    def _add_finding(self, f: Finding):
        k = f.key()
        if k in self._seen:
            return
        self._seen.add(k)
        self.report.findings.append(f)

    def _build_summary(self):
        """Build executive summary statistics."""
        by_sev = defaultdict(int)
        by_cat = defaultdict(int)
        for f in self.report.findings:
            by_sev[f.severity] += 1
            by_cat[f.category] += 1

        total_dex_classes = sum(d.class_count for d in self.report.dex_info)
        total_dex_methods = sum(d.method_count for d in self.report.dex_info)
        total_dex_fields = sum(d.field_count for d in self.report.dex_info)
        total_dex_strings = sum(d.string_count for d in self.report.dex_info)

        self.report.summary = {
            "total_findings": len(self.report.findings),
            "by_severity": dict(by_sev),
            "by_category": dict(by_cat),
            "risk_score": self._calculate_risk_score(by_sev),
            "dex_files_analyzed": len(self.report.dex_info),
            "total_classes": total_dex_classes,
            "total_methods": total_dex_methods,
            "total_fields": total_dex_fields,
            "total_strings": total_dex_strings,
            "vulnerable_libraries": len(self.report.detected_libraries),
            "tracking_sdks": len(self.report.tracking_sdks),
            "obfuscation_percent": self.report.obfuscation_score,
            "has_root_detection": "Root detection" in " ".join(self.report.security_checks),
            "has_debug_detection": "Debugger detection" in " ".join(self.report.security_checks),
        }

    def _calculate_risk_score(self, by_sev: dict) -> int:
        """Calculate overall risk score 0-100."""
        score = 0
        score += by_sev.get("CRITICAL", 0) * 25
        score += by_sev.get("HIGH", 0) * 15
        score += by_sev.get("MEDIUM", 0) * 7
        score += by_sev.get("LOW", 0) * 2
        return min(100, score)


# ===========================================================================
# OUTPUT FORMATTERS
# ===========================================================================

SEV_COLOR = {"CRITICAL": C_RED, "HIGH": C_RED, "MEDIUM": C_YEL, "LOW": C_CYN, "INFO": C_GRN}


def print_report(rep: Report):
    """Print colored report to terminal."""
    print(f"\n{C_BLD}{C_MAG}{'='*70}{C_RST}")
    print(f"{C_BLD}{C_MAG}  APK DEEP ANALYZER v{VERSION} - Security Assessment Report{C_RST}")
    print(f"{C_BLD}{C_MAG}{'='*70}{C_RST}")

    print(f"\n{C_BLD}[TARGET]{C_RST}")
    print(f"  File     : {rep.apk_path}")
    print(f"  Size     : {rep.apk_size:,} bytes")
    print(f"  MD5      : {rep.apk_md5}")
    print(f"  SHA-256  : {rep.apk_sha256}")
    print(f"  Scan Time: {rep.scan_duration}s")

    # Risk Score
    risk = rep.summary.get("risk_score", 0)
    risk_color = C_GRN if risk < 25 else C_YEL if risk < 50 else C_RED
    print(f"\n{C_BLD}[RISK SCORE]{C_RST} {risk_color}{C_BLD}{risk}/100{C_RST}")

    # DEX Info
    if rep.dex_info:
        print(f"\n{C_BLD}[DEX ANALYSIS]{C_RST}")
        for di in rep.dex_info:
            print(f"  {di.filename}: {di.class_count} classes, "
                  f"{di.method_count} methods, {di.field_count} fields, "
                  f"{di.string_count} strings")
        print(f"  Obfuscation: {rep.obfuscation_score:.1f}%")

    # Certificate
    if rep.cert_info:
        print(f"\n{C_BLD}[CERTIFICATE]{C_RST}")
        print(f"  File    : {rep.cert_info.filename}")
        print(f"  SHA-256 : {rep.cert_info.fingerprint_sha256}")
        if rep.cert_info.issuer:
            print(f"  Issuer  : {rep.cert_info.issuer}")

    # Manifest flags
    flags = []
    if rep.debuggable:
        flags.append(f"{C_RED}DEBUGGABLE{C_RST}")
    if rep.allow_backup:
        flags.append(f"{C_YEL}BACKUP_ALLOWED{C_RST}")
    if rep.uses_cleartext:
        flags.append(f"{C_YEL}CLEARTEXT_TRAFFIC{C_RST}")
    if flags:
        print(f"\n{C_BLD}[MANIFEST FLAGS]{C_RST} {' | '.join(flags)}")

    # Dangerous permissions
    if rep.dangerous_permissions:
        print(f"\n{C_BLD}[DANGEROUS PERMISSIONS] ({len(rep.dangerous_permissions)}){C_RST}")
        for p in rep.dangerous_permissions[:15]:
            print(f"  {C_YEL}- {p}{C_RST}")
        if len(rep.dangerous_permissions) > 15:
            print(f"  ... +{len(rep.dangerous_permissions) - 15} more")

    # Vulnerable libraries
    if rep.detected_libraries:
        print(f"\n{C_BLD}[VULNERABLE LIBRARIES]{C_RST}")
        for lib in rep.detected_libraries:
            print(f"  {C_RED}- {lib}{C_RST}")

    # Tracking SDKs
    if rep.tracking_sdks:
        print(f"\n{C_BLD}[TRACKING SDKs]{C_RST}")
        for sdk in rep.tracking_sdks:
            print(f"  {C_CYN}- {sdk}{C_RST}")

    # Security checks
    if rep.security_checks:
        print(f"\n{C_BLD}[SECURITY PROTECTIONS]{C_RST}")
        for sc in rep.security_checks:
            print(f"  {C_GRN}+ {sc}{C_RST}")

    # Findings summary
    by_sev = rep.summary.get("by_severity", {})
    print(f"\n{C_BLD}[FINDINGS SUMMARY]{C_RST}")
    print(f"  Total: {len(rep.findings)}  "
          f"{C_RED}CRITICAL={by_sev.get('CRITICAL', 0)}{C_RST}  "
          f"{C_RED}HIGH={by_sev.get('HIGH', 0)}{C_RST}  "
          f"{C_YEL}MEDIUM={by_sev.get('MEDIUM', 0)}{C_RST}  "
          f"{C_CYN}LOW={by_sev.get('LOW', 0)}{C_RST}  "
          f"{C_GRN}INFO={by_sev.get('INFO', 0)}{C_RST}")

    # Detail findings by severity
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        items = [f for f in rep.findings if f.severity == sev]
        if not items:
            continue
        col = SEV_COLOR.get(sev, "")
        print(f"\n{C_BLD}{col}--- [{sev}] {len(items)} finding(s) ---{C_RST}")

        groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        for it in items:
            groups[(it.category, it.name)].append(it)

        for (cat, name), arr in groups.items():
            cve_str = f" [{arr[0].cve_cwe}]" if arr[0].cve_cwe else ""
            cvss_str = f" CVSS:{arr[0].cvss}" if arr[0].cvss else ""
            print(f"  {col}{C_BLD}{name}{C_RST}{cve_str}{cvss_str} ({cat}, x{len(arr)})")
            for it in arr[:10]:
                val_short = it.value[:120] + "..." if len(it.value) > 120 else it.value
                print(f"    {val_short}")
                if it.affected_class:
                    print(f"      {C_MAG}Class: {it.affected_class}{C_RST}")
            if len(arr) > 10:
                print(f"    ... +{len(arr) - 10} more")


def save_json_report(rep: Report, path: str):
    """Save JSON report."""
    with open(path, "w", encoding="utf-8") as f:
        json.dump(rep.to_dict(), f, indent=2, ensure_ascii=False)


def save_txt_report(rep: Report, path: str):
    """Save plain text report."""
    lines = []
    lines.append("=" * 70)
    lines.append(f"  APK DEEP ANALYZER v{VERSION} - Security Assessment Report")
    lines.append("=" * 70)
    lines.append("")
    lines.append("[TARGET]")
    lines.append(f"  File     : {rep.apk_path}")
    lines.append(f"  Size     : {rep.apk_size:,} bytes")
    lines.append(f"  MD5      : {rep.apk_md5}")
    lines.append(f"  SHA-256  : {rep.apk_sha256}")
    lines.append(f"  Scan Time: {rep.scan_duration}s")
    lines.append("")

    risk = rep.summary.get("risk_score", 0)
    lines.append(f"[RISK SCORE] {risk}/100")
    lines.append("")

    if rep.dex_info:
        lines.append("[DEX ANALYSIS]")
        for di in rep.dex_info:
            lines.append(f"  {di.filename}: {di.class_count} classes, "
                        f"{di.method_count} methods, {di.field_count} fields")
        lines.append(f"  Obfuscation: {rep.obfuscation_score:.1f}%")
        lines.append("")

    if rep.cert_info:
        lines.append("[CERTIFICATE]")
        lines.append(f"  File    : {rep.cert_info.filename}")
        lines.append(f"  SHA-256 : {rep.cert_info.fingerprint_sha256}")
        lines.append("")

    if rep.dangerous_permissions:
        lines.append(f"[DANGEROUS PERMISSIONS] ({len(rep.dangerous_permissions)})")
        for p in rep.dangerous_permissions:
            lines.append(f"  - {p}")
        lines.append("")

    if rep.detected_libraries:
        lines.append("[POTENTIALLY VULNERABLE LIBRARIES]")
        for lib in rep.detected_libraries:
            lines.append(f"  - {lib}")
        lines.append("")

    if rep.tracking_sdks:
        lines.append("[TRACKING SDKs]")
        for sdk in rep.tracking_sdks:
            lines.append(f"  - {sdk}")
        lines.append("")

    if rep.security_checks:
        lines.append("[SECURITY PROTECTIONS]")
        for sc in rep.security_checks:
            lines.append(f"  + {sc}")
        lines.append("")

    lines.append(f"[FINDINGS] ({len(rep.findings)} total)")
    lines.append("-" * 70)

    for f in rep.findings:
        lines.append(f"[{f.severity:8}] {f.name}")
        if f.cve_cwe:
            lines.append(f"           CVE/CWE : {f.cve_cwe}")
        if f.cvss:
            lines.append(f"           CVSS    : {f.cvss}")
        lines.append(f"           Category: {f.category}")
        lines.append(f"           Value   : {f.value[:200]}")
        lines.append(f"           Source  : {f.source_file}")
        if f.affected_class:
            lines.append(f"           Class   : {f.affected_class}")
        if f.affected_method:
            lines.append(f"           Method  : {f.affected_method}")
        if f.description:
            lines.append(f"           Desc    : {f.description}")
        if f.remediation:
            lines.append(f"           Fix     : {f.remediation}")
        lines.append(f"           Conf    : {f.confidence}")
        lines.append("")

    # Executive Summary
    lines.append("=" * 70)
    lines.append("EXECUTIVE SUMMARY (Bug Bounty)")
    lines.append("=" * 70)
    by_sev = rep.summary.get("by_severity", {})
    lines.append(f"Risk Score: {risk}/100")
    lines.append(f"Critical: {by_sev.get('CRITICAL', 0)} | High: {by_sev.get('HIGH', 0)} | "
                f"Medium: {by_sev.get('MEDIUM', 0)} | Low: {by_sev.get('LOW', 0)}")
    lines.append(f"Vulnerable Libraries: {len(rep.detected_libraries)}")
    lines.append(f"Tracking SDKs: {len(rep.tracking_sdks)}")
    lines.append(f"Obfuscation Level: {rep.obfuscation_score:.1f}%")
    lines.append("")

    # Top actionable findings
    critical_high = [f for f in rep.findings if f.severity in ("CRITICAL", "HIGH")]
    if critical_high:
        lines.append("TOP PRIORITY FINDINGS:")
        for i, f in enumerate(critical_high[:10], 1):
            lines.append(f"  {i}. [{f.severity}] {f.name} - {f.cve_cwe} (CVSS {f.cvss})")
            lines.append(f"     {f.description}")
    lines.append("")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(lines))



def save_html_report(rep: Report, path: str):
    """Save HTML report with colored severity badges."""
    h = html_module.escape

    sev_colors = {
        "CRITICAL": "#dc3545",
        "HIGH": "#e85d04",
        "MEDIUM": "#ffc107",
        "LOW": "#17a2b8",
        "INFO": "#28a745",
    }

    risk = rep.summary.get("risk_score", 0)
    by_sev = rep.summary.get("by_severity", {})
    risk_color = "#28a745" if risk < 25 else "#ffc107" if risk < 50 else "#dc3545"

    html_parts = []
    html_parts.append(f"""<!DOCTYPE html>
<html lang="en">
<head>
<meta charset="UTF-8">
<meta name="viewport" content="width=device-width, initial-scale=1.0">
<title>APK Security Report - {h(os.path.basename(rep.apk_path))}</title>
<style>
body {{ font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', Roboto, sans-serif; margin: 0; padding: 20px; background: #1a1a2e; color: #eee; }}
.container {{ max-width: 1200px; margin: 0 auto; }}
h1 {{ color: #e94560; border-bottom: 2px solid #e94560; padding-bottom: 10px; }}
h2 {{ color: #0f3460; background: #16213e; padding: 10px 15px; border-radius: 5px; margin-top: 30px; color: #eee; }}
.badge {{ display: inline-block; padding: 3px 10px; border-radius: 12px; color: #fff; font-weight: bold; font-size: 12px; margin-right: 5px; }}
.risk-score {{ font-size: 48px; font-weight: bold; text-align: center; padding: 20px; border-radius: 10px; }}
.meta-table {{ width: 100%; border-collapse: collapse; margin: 10px 0; }}
.meta-table td {{ padding: 8px 12px; border-bottom: 1px solid #333; }}
.meta-table td:first-child {{ font-weight: bold; width: 150px; color: #aaa; }}
.finding-card {{ background: #16213e; border-radius: 8px; padding: 15px; margin: 10px 0; border-left: 4px solid; }}
.finding-card .title {{ font-weight: bold; font-size: 16px; }}
.finding-card .details {{ margin-top: 8px; font-size: 13px; color: #aaa; }}
.finding-card .value {{ font-family: monospace; background: #0f3460; padding: 4px 8px; border-radius: 4px; margin: 5px 0; display: inline-block; word-break: break-all; }}
.stat-grid {{ display: grid; grid-template-columns: repeat(auto-fit, minmax(150px, 1fr)); gap: 15px; margin: 15px 0; }}
.stat-box {{ background: #16213e; padding: 15px; border-radius: 8px; text-align: center; }}
.stat-box .number {{ font-size: 28px; font-weight: bold; }}
.stat-box .label {{ font-size: 12px; color: #aaa; margin-top: 5px; }}
.lib-list, .sdk-list {{ list-style: none; padding: 0; }}
.lib-list li, .sdk-list li {{ padding: 8px 12px; border-bottom: 1px solid #333; }}
</style>
</head>
<body>
<div class="container">
<h1>APK Deep Analyzer v{VERSION} - Security Report</h1>
""")

    # Meta info
    html_parts.append(f"""
<table class="meta-table">
<tr><td>File</td><td>{h(os.path.basename(rep.apk_path))}</td></tr>
<tr><td>Size</td><td>{rep.apk_size:,} bytes</td></tr>
<tr><td>MD5</td><td><code>{rep.apk_md5}</code></td></tr>
<tr><td>SHA-256</td><td><code>{rep.apk_sha256}</code></td></tr>
<tr><td>Scan Duration</td><td>{rep.scan_duration}s</td></tr>
</table>
""")

    # Risk Score
    html_parts.append(f"""
<h2>Risk Assessment</h2>
<div class="risk-score" style="color: {risk_color}; border: 3px solid {risk_color};">
    {risk} / 100
</div>
<div class="stat-grid">
    <div class="stat-box"><div class="number" style="color:#dc3545">{by_sev.get('CRITICAL', 0)}</div><div class="label">CRITICAL</div></div>
    <div class="stat-box"><div class="number" style="color:#e85d04">{by_sev.get('HIGH', 0)}</div><div class="label">HIGH</div></div>
    <div class="stat-box"><div class="number" style="color:#ffc107">{by_sev.get('MEDIUM', 0)}</div><div class="label">MEDIUM</div></div>
    <div class="stat-box"><div class="number" style="color:#17a2b8">{by_sev.get('LOW', 0)}</div><div class="label">LOW</div></div>
    <div class="stat-box"><div class="number" style="color:#28a745">{by_sev.get('INFO', 0)}</div><div class="label">INFO</div></div>
</div>
""")

    # DEX Analysis
    if rep.dex_info:
        html_parts.append("<h2>DEX Binary Analysis</h2>")
        html_parts.append('<div class="stat-grid">')
        total_c = sum(d.class_count for d in rep.dex_info)
        total_m = sum(d.method_count for d in rep.dex_info)
        total_f = sum(d.field_count for d in rep.dex_info)
        total_s = sum(d.string_count for d in rep.dex_info)
        html_parts.append(f'<div class="stat-box"><div class="number">{total_c}</div><div class="label">Classes</div></div>')
        html_parts.append(f'<div class="stat-box"><div class="number">{total_m}</div><div class="label">Methods</div></div>')
        html_parts.append(f'<div class="stat-box"><div class="number">{total_f}</div><div class="label">Fields</div></div>')
        html_parts.append(f'<div class="stat-box"><div class="number">{total_s}</div><div class="label">Strings</div></div>')
        html_parts.append(f'<div class="stat-box"><div class="number">{rep.obfuscation_score:.0f}%</div><div class="label">Obfuscation</div></div>')
        html_parts.append('</div>')

    # Vulnerable Libraries
    if rep.detected_libraries:
        html_parts.append("<h2>Potentially Vulnerable Libraries</h2>")
        html_parts.append('<ul class="lib-list">')
        for lib in rep.detected_libraries:
            html_parts.append(f'<li><span class="badge" style="background:#e85d04">VULN</span> {h(lib)}</li>')
        html_parts.append('</ul>')

    # Tracking SDKs
    if rep.tracking_sdks:
        html_parts.append("<h2>Tracking / Analytics SDKs</h2>")
        html_parts.append('<ul class="sdk-list">')
        for sdk in rep.tracking_sdks:
            html_parts.append(f'<li>{h(sdk)}</li>')
        html_parts.append('</ul>')

    # Security Protections
    if rep.security_checks:
        html_parts.append("<h2>Security Protections Detected</h2>")
        html_parts.append('<ul class="sdk-list">')
        for sc in rep.security_checks:
            html_parts.append(f'<li style="color:#28a745">+ {h(sc)}</li>')
        html_parts.append('</ul>')

    # Findings
    html_parts.append("<h2>Detailed Findings</h2>")
    for sev in ("CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO"):
        items = [f for f in rep.findings if f.severity == sev]
        if not items:
            continue
        color = sev_colors.get(sev, "#666")
        html_parts.append(f'<h3 style="color:{color}">{sev} ({len(items)})</h3>')
        for item in items[:50]:
            html_parts.append(f"""
<div class="finding-card" style="border-left-color: {color};">
    <div class="title">
        <span class="badge" style="background:{color}">{item.severity}</span>
        {h(item.name)}
        {"<code>" + h(item.cve_cwe) + "</code>" if item.cve_cwe else ""}
        {"CVSS:" + str(item.cvss) if item.cvss else ""}
    </div>
    <div class="details">
        <div><strong>Category:</strong> {h(item.category)} | <strong>Confidence:</strong> {h(item.confidence)}</div>
        <div class="value">{h(item.value[:200])}</div>
        <div><strong>Source:</strong> {h(item.source_file)}</div>
        {"<div><strong>Class:</strong> " + h(item.affected_class) + "</div>" if item.affected_class else ""}
        {"<div><strong>Description:</strong> " + h(item.description) + "</div>" if item.description else ""}
        {"<div><strong>Remediation:</strong> " + h(item.remediation) + "</div>" if item.remediation else ""}
    </div>
</div>""")
        if len(items) > 50:
            html_parts.append(f'<p>... and {len(items) - 50} more {sev} findings</p>')

    # Footer
    html_parts.append(f"""
<hr style="margin-top:40px; border-color:#333">
<p style="text-align:center; color:#666; font-size:12px;">
    Generated by APK Deep Analyzer v{VERSION} | {rep.scan_time}
</p>
</div></body></html>""")

    with open(path, "w", encoding="utf-8") as f:
        f.write("\n".join(html_parts))


# ===========================================================================
# CLI ENTRY POINT
# ===========================================================================

def main() -> int:
    ap = argparse.ArgumentParser(
        description=f"APK Deep Analyzer v{VERSION} - Advanced APK Security Scanner with CVE/CWE mapping.",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog="""
Examples:
  python analyze.py app.apk
  python analyze.py app.apk -o my_report --format all
  python analyze.py app.apk --format html --quiet
  python analyze.py app.apk --min-len 8

Output formats:
  json  - Machine-readable JSON report
  txt   - Human-readable text report with executive summary
  html  - Visual HTML report with colored severity badges
  all   - Generate all formats (default)
        """
    )
    ap.add_argument("apk", help="Path to the APK file")
    ap.add_argument("-o", "--output", default=None,
                    help="Output prefix for reports (default: <apk_name>.report)")
    ap.add_argument("--format", choices=["json", "txt", "html", "all"], default="all",
                    help="Output format (default: all)")
    ap.add_argument("--min-len", type=int, default=6,
                    help="Minimum string length to extract (default: 6)")
    ap.add_argument("--quiet", action="store_true",
                    help="Suppress terminal output")
    ap.add_argument("--version", action="version", version=f"APK Deep Analyzer v{VERSION}")
    args = ap.parse_args()

    if not os.path.isfile(args.apk):
        print(f"{C_RED}[-] File not found: {args.apk}{C_RST}", file=sys.stderr)
        return 2
    if not zipfile.is_zipfile(args.apk):
        print(f"{C_RED}[-] Not a valid ZIP/APK file: {args.apk}{C_RST}", file=sys.stderr)
        return 2

    out_prefix = args.output or (os.path.splitext(args.apk)[0] + ".report")

    if not args.quiet:
        print(f"{C_CYN}{C_BLD}")
        print(f"    _    ____  _  __   ____                  ")
        print(f"   / \\  |  _ \\| |/ /  |  _ \\  ___  ___ _ __ ")
        print(f"  / _ \\ | |_) | ' /   | | | |/ _ \\/ _ \\ '_ \\")
        print(f" / ___ \\|  __/| . \\   | |_| |  __/  __/ |_) |")
        print(f"/_/   \\_\\_|   |_|\\_\\  |____/ \\___|\\___| .__/ ")
        print(f"                                      |_|    ")
        print(f"  Analyzer v{VERSION} - No Decompilation Required")
        print(f"{C_RST}")
        print(f"{C_CYN}[*] Analyzing: {args.apk}{C_RST}")
        print(f"{C_CYN}[*] This may take a moment for large APKs...{C_RST}")

    analyzer = APKDeepAnalyzer(args.apk, min_str_len=args.min_len)
    report = analyzer.analyze()

    if not args.quiet:
        print_report(report)

    # Save reports
    saved_files = []
    if args.format in ("json", "all"):
        json_path = out_prefix + ".json"
        save_json_report(report, json_path)
        saved_files.append(json_path)

    if args.format in ("txt", "all"):
        txt_path = out_prefix + ".txt"
        save_txt_report(report, txt_path)
        saved_files.append(txt_path)

    if args.format in ("html", "all"):
        html_path = out_prefix + ".html"
        save_html_report(report, html_path)
        saved_files.append(html_path)

    if not args.quiet:
        print(f"\n{C_GRN}{C_BLD}[+] Reports saved:{C_RST}")
        for fp in saved_files:
            print(f"    {C_GRN}{fp}{C_RST}")

        # Quick summary
        risk = report.summary.get("risk_score", 0)
        by_sev = report.summary.get("by_severity", {})
        print(f"\n{C_BLD}[VERDICT]{C_RST} ", end="")
        if risk >= 75:
            print(f"{C_RED}HIGH RISK - Critical vulnerabilities detected!{C_RST}")
        elif risk >= 50:
            print(f"{C_YEL}MODERATE RISK - Several security issues found.{C_RST}")
        elif risk >= 25:
            print(f"{C_YEL}LOW-MODERATE RISK - Some issues worth investigating.{C_RST}")
        else:
            print(f"{C_GRN}LOW RISK - Few issues detected.{C_RST}")

    return 0


if __name__ == "__main__":
    sys.exit(main())
