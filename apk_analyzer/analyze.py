#!/usr/bin/env python3
"""
APK Secret/Risk Scanner — dekompilyatsiyasiz.

APK fayli aslida ZIP arxiv. Bu skript:
  1. APK ni ZIP sifatida ochadi
  2. classes*.dex ichidan UTF-8 / UTF-16 stringlarni `strings` uslubida sug'urib oladi
  3. AndroidManifest.xml (binary AXML) ichidagi stringlarni o'qiydi
  4. resources.arsc, assets/*, res/raw/* ichidagi matnlarni skanerlaydi
  5. Regex orqali xavfli narsalarni topadi:
       - API key'lar (Google, AWS, Firebase, Stripe, Slack, GitHub, ...)
       - JWT tokenlar
       - Hardcoded parollar / Authorization header'lar
       - Cookie qiymatlari (Set-Cookie, sessionid, JSESSIONID, ...)
       - Private key'lar (PEM)
       - Hardcoded URL / IP / endpoint'lar
       - Xavfli ruxsatlar (permissions)
       - Cleartext traffic / debuggable / backup yoqilgan bo'lsa
  6. Topilganlarni JSON va matn ko'rinishida hisobot qiladi.

Foydalanish:
  python analyze.py <path-to.apk> [-o report] [--min-len 6]
"""

from __future__ import annotations

import argparse
import hashlib
import json
import os
import re
import sys
import zipfile
from collections import defaultdict
from dataclasses import dataclass, field, asdict
from typing import Iterable, Iterator

# ---------------------------------------------------------------------------
# Rangli chiqish (colorama bo'lmasa ham ishlaydi)
# ---------------------------------------------------------------------------
try:
    from colorama import Fore, Style, init as _color_init
    _color_init()
    C_RED = Fore.RED
    C_YEL = Fore.YELLOW
    C_GRN = Fore.GREEN
    C_CYN = Fore.CYAN
    C_MAG = Fore.MAGENTA
    C_RST = Style.RESET_ALL
    C_BLD = Style.BRIGHT
except Exception:
    C_RED = C_YEL = C_GRN = C_CYN = C_MAG = C_RST = C_BLD = ""


# ---------------------------------------------------------------------------
# Maxfiy ma'lumot patternlari
#   severity:  high | medium | low | info
# ---------------------------------------------------------------------------
SECRET_PATTERNS: list[tuple[str, str, str]] = [
    # name, severity, regex
    ("Google API Key",            "high",   r"AIza[0-9A-Za-z_\-]{35}"),
    ("Google OAuth Access Token", "high",   r"ya29\.[0-9A-Za-z_\-]+"),
    ("Firebase URL",              "medium", r"https?://[a-z0-9\-]+\.firebaseio\.com"),
    ("Firebase Cloud Messaging",  "medium", r"AAAA[A-Za-z0-9_\-]{7}:[A-Za-z0-9_\-]{140}"),
    ("AWS Access Key ID",         "high",   r"\b(?:AKIA|ASIA|AGPA|AIDA|AROA|AIPA|ANPA|ANVA|ASCA)[0-9A-Z]{16}\b"),
    ("AWS Secret Access Key",     "high",   r"(?i)aws(.{0,20})?(secret|sk)[\"'\s:=]{1,5}[A-Za-z0-9/+=]{40}"),
    ("AWS S3 URL",                "low",    r"[a-z0-9.\-]+\.s3[\.\-][a-z0-9\-]*\.amazonaws\.com"),
    ("Slack Token",               "high",   r"xox[abprs]-[0-9A-Za-z\-]{10,}"),
    ("Slack Webhook",             "high",   r"https://hooks\.slack\.com/services/T[A-Z0-9]+/B[A-Z0-9]+/[A-Za-z0-9]+"),
    ("GitHub Token",              "high",   r"\bghp_[A-Za-z0-9]{36}\b|\bgho_[A-Za-z0-9]{36}\b|\bghs_[A-Za-z0-9]{36}\b"),
    ("Stripe Secret Key",         "high",   r"\bsk_live_[0-9a-zA-Z]{24,}\b"),
    ("Stripe Publishable Key",    "medium", r"\bpk_live_[0-9a-zA-Z]{24,}\b"),
    ("Twilio Account SID",        "high",   r"\bAC[a-f0-9]{32}\b"),
    ("Twilio Auth Token",         "high",   r"(?i)twilio.{0,20}[\"'\s:=]{1,5}[a-f0-9]{32}"),
    ("SendGrid API Key",          "high",   r"\bSG\.[A-Za-z0-9_\-]{22}\.[A-Za-z0-9_\-]{43}\b"),
    ("Mapbox Token",              "medium", r"\bpk\.eyJ[A-Za-z0-9_\-]+\.[A-Za-z0-9_\-]+"),
    ("Square Access Token",       "high",   r"\bsq0atp-[0-9A-Za-z_\-]{22}\b"),
    ("PayPal Braintree Token",    "high",   r"\baccess_token\$production\$[0-9a-z]{16}\$[0-9a-f]{32}\b"),
    ("Heroku API Key",            "high",   r"(?i)heroku.{0,20}[\"'\s:=]{1,5}[0-9a-f]{8}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{4}-[0-9a-f]{12}"),
    ("Generic Bearer JWT",        "medium", r"\beyJ[A-Za-z0-9_\-]{10,}\.eyJ[A-Za-z0-9_\-]{10,}\.[A-Za-z0-9_\-]{10,}"),
    ("PEM Private Key",           "high",   r"-----BEGIN (?:RSA |DSA |EC |OPENSSH |PGP |ENCRYPTED )?PRIVATE KEY-----"),
    ("Authorization Header",      "high",   r"(?i)Authorization:\s*(?:Bearer|Basic|Token)\s+[A-Za-z0-9._\-=/+]{8,}"),
    ("Basic Auth in URL",         "high",   r"https?://[^/\s:@]+:[^/\s:@]+@[A-Za-z0-9.\-]+"),
    ("Hardcoded Password",        "medium", r"(?i)(?:password|passwd|pwd)\s*[:=]\s*[\"'][^\"'\s]{4,}[\"']"),
    ("Hardcoded Secret",          "medium", r"(?i)(?:secret|api[_\-]?key|apikey|access[_\-]?key|client[_\-]?secret)\s*[:=]\s*[\"'][A-Za-z0-9._\-]{8,}[\"']"),
    ("Cookie Header",             "medium", r"(?i)(?:Set-Cookie|Cookie):\s*[A-Za-z0-9_\-]+=[^\s;]{3,}"),
    ("Session-like Cookie name",  "low",    r"(?i)\b(?:JSESSIONID|PHPSESSID|sessionid|sess_id|auth_token|access_token|refresh_token|csrftoken|XSRF-TOKEN)\b"),
]

URL_PATTERN  = re.compile(rb"https?://[A-Za-z0-9._\-:/?#\[\]@!$&'()*+,;=%~]+", re.IGNORECASE)
IP_PATTERN   = re.compile(rb"\b(?:(?:25[0-5]|2[0-4]\d|[01]?\d?\d)\.){3}(?:25[0-5]|2[0-4]\d|[01]?\d?\d)(?::\d{2,5})?\b")
EMAIL_PATTERN = re.compile(rb"[A-Za-z0-9._%+\-]+@[A-Za-z0-9.\-]+\.[A-Za-z]{2,}")

# Xavfli ruxsatlar — APK juda ko'p ruxsat so'rasa diqqat qilish kerak
DANGEROUS_PERMISSIONS = {
    "android.permission.READ_SMS", "android.permission.SEND_SMS", "android.permission.RECEIVE_SMS",
    "android.permission.READ_CONTACTS", "android.permission.WRITE_CONTACTS",
    "android.permission.READ_CALL_LOG", "android.permission.WRITE_CALL_LOG",
    "android.permission.RECORD_AUDIO", "android.permission.CAMERA",
    "android.permission.ACCESS_FINE_LOCATION", "android.permission.ACCESS_BACKGROUND_LOCATION",
    "android.permission.READ_EXTERNAL_STORAGE", "android.permission.WRITE_EXTERNAL_STORAGE",
    "android.permission.MANAGE_EXTERNAL_STORAGE",
    "android.permission.READ_PHONE_STATE", "android.permission.READ_PHONE_NUMBERS",
    "android.permission.SYSTEM_ALERT_WINDOW", "android.permission.REQUEST_INSTALL_PACKAGES",
    "android.permission.PACKAGE_USAGE_STATS", "android.permission.QUERY_ALL_PACKAGES",
    "android.permission.BIND_ACCESSIBILITY_SERVICE",
    "android.permission.READ_CALENDAR", "android.permission.WRITE_CALENDAR",
    "android.permission.GET_ACCOUNTS", "android.permission.USE_FINGERPRINT",
}

# Whitelist domenlar — odatda xavfsiz, shovqinni kamaytirish uchun
NOISE_HOSTS = (
    "schemas.android.com", "schemas.google.com",
    "www.w3.org", "ns.adobe.com",
    "play.google.com", "developer.android.com",
    "fonts.google.com", "fonts.gstatic.com",
)


# ---------------------------------------------------------------------------
# String ekstraktor — `strings(1)` ga o'xshash, lekin Python da
# ---------------------------------------------------------------------------
def extract_ascii_strings(buf: bytes, min_len: int = 6) -> Iterator[str]:
    pat = re.compile(rb"[\x20-\x7e]{%d,}" % min_len)
    for m in pat.finditer(buf):
        try:
            yield m.group(0).decode("ascii", errors="ignore")
        except Exception:
            continue


def extract_utf16le_strings(buf: bytes, min_len: int = 6) -> Iterator[str]:
    # UTF-16LE: har bir ASCII bayt orqasidan 0x00 keladi
    pat = re.compile((rb"(?:[\x20-\x7e]\x00){%d,}" % min_len))
    for m in pat.finditer(buf):
        try:
            yield m.group(0).decode("utf-16-le", errors="ignore")
        except Exception:
            continue


# ---------------------------------------------------------------------------
# Binary AndroidManifest.xml (AXML) parseri — minimal, faqat stringlar va
# ba'zi atributlarni chiqaradi. Faqat string pool va resource map o'qiladi.
# ---------------------------------------------------------------------------
def parse_axml_strings(data: bytes) -> list[str]:
    """AXML ichidagi string pool dan barcha stringlarni qaytaradi."""
    if len(data) < 8:
        return []
    # AXML chunk: 0x00080003
    if data[:4] != b"\x03\x00\x08\x00":
        return []
    # String pool chunk header'ini topamiz: type 0x001C
    # AXML format: header (8) -> chunks. Birinchi chunk odatda String Pool.
    pos = 8
    if pos + 8 > len(data):
        return []
    chunk_type = int.from_bytes(data[pos:pos+2], "little")
    if chunk_type != 0x0001:  # RES_STRING_POOL_TYPE
        return []
    header_size = int.from_bytes(data[pos+2:pos+4], "little")
    chunk_size  = int.from_bytes(data[pos+4:pos+8], "little")
    string_count = int.from_bytes(data[pos+8:pos+12], "little")
    flags        = int.from_bytes(data[pos+16:pos+20], "little")
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
                # u16len, u8len, bytes, 0x00
                # birinchi bayt(lar) — char count, keyin byte count
                p = sp
                # char count
                if data[p] & 0x80:
                    p += 2
                else:
                    p += 1
                # byte count
                if data[p] & 0x80:
                    bl = ((data[p] & 0x7F) << 8) | data[p+1]
                    p += 2
                else:
                    bl = data[p]
                    p += 1
                s = data[p:p+bl].decode("utf-8", errors="replace")
            else:
                # UTF-16
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


# ---------------------------------------------------------------------------
# Topilma (finding) tuzilmasi
# ---------------------------------------------------------------------------
@dataclass
class Finding:
    category: str
    severity: str          # high | medium | low | info
    name: str
    value: str
    source_file: str
    context: str = ""

    def key(self) -> str:
        return f"{self.category}|{self.name}|{self.value}|{self.source_file}"


@dataclass
class Report:
    apk_path: str
    apk_size: int
    apk_md5: str
    apk_sha256: str
    package: str = ""
    version_name: str = ""
    version_code: str = ""
    min_sdk: str = ""
    target_sdk: str = ""
    debuggable: bool = False
    allow_backup: bool = True
    uses_cleartext: bool = False
    permissions: list[str] = field(default_factory=list)
    dangerous_permissions: list[str] = field(default_factory=list)
    exported_components: list[str] = field(default_factory=list)
    findings: list[Finding] = field(default_factory=list)

    def to_dict(self) -> dict:
        d = asdict(self)
        d["findings"] = [asdict(f) for f in self.findings]
        return d


# ---------------------------------------------------------------------------
# Skaner
# ---------------------------------------------------------------------------
class APKScanner:
    def __init__(self, apk_path: str, min_str_len: int = 6) -> None:
        self.apk_path = apk_path
        self.min_str_len = min_str_len
        self.report = Report(
            apk_path=apk_path,
            apk_size=os.path.getsize(apk_path),
            apk_md5=self._hash("md5"),
            apk_sha256=self._hash("sha256"),
        )
        self._compiled = [(n, s, re.compile(p)) for n, s, p in SECRET_PATTERNS]
        self._seen: set[str] = set()

    def _hash(self, algo: str) -> str:
        h = hashlib.new(algo)
        with open(self.apk_path, "rb") as f:
            for chunk in iter(lambda: f.read(1 << 20), b""):
                h.update(chunk)
        return h.hexdigest()

    # ---- public ----
    def scan(self) -> Report:
        with zipfile.ZipFile(self.apk_path, "r") as z:
            names = z.namelist()
            # 1) Manifest
            if "AndroidManifest.xml" in names:
                self._scan_manifest(z.read("AndroidManifest.xml"))
            # 2) DEX fayllar
            for n in names:
                if n.startswith("classes") and n.endswith(".dex"):
                    self._scan_text_blob(z.read(n), n)
            # 3) Resurslar va boshqa matnli fayllar
            for n in names:
                if n in ("AndroidManifest.xml",) or (n.startswith("classes") and n.endswith(".dex")):
                    continue
                lower = n.lower()
                # Faqat foydali bo'ladigan fayllar
                if (
                    lower.endswith((".xml", ".json", ".txt", ".properties",
                                    ".js", ".html", ".htm", ".css",
                                    ".cfg", ".conf", ".ini", ".yml", ".yaml",
                                    ".pem", ".key", ".cer", ".crt"))
                    or lower.startswith("assets/")
                    or lower.startswith("res/raw/")
                    or lower == "resources.arsc"
                ):
                    try:
                        data = z.read(n)
                    except Exception:
                        continue
                    self._scan_text_blob(data, n)

        self._dedupe()
        return self.report

    # ---- internals ----
    def _scan_manifest(self, data: bytes) -> None:
        strings = parse_axml_strings(data)
        # Stringlardan ma'lumot olishga harakat
        # package, version, permissions, exported komponentlar — heuristic
        joined = "\n".join(strings)

        # Permissions
        perms = sorted({s for s in strings if s.startswith("android.permission.") or s.startswith("com.")
                        and ".permission." in s})
        self.report.permissions = perms
        self.report.dangerous_permissions = sorted(set(perms) & DANGEROUS_PERMISSIONS)

        # Cleartext / debuggable / backup — string pool ichida bayroqlar bo'lmaydi,
        # lekin tegishli string'lar ko'pincha bo'ladi.
        if "usesCleartextTraffic" in joined:
            # Ehtimol true — manifestda atribut bor, real qiymatni axml binary'dan
            # to'liq parser orqali olish kerak. Bu yerda flag sifatida ko'rsatamiz.
            self.report.uses_cleartext = True
        if "debuggable" in joined:
            # debuggable atributi bor — ko'pincha debug build qoldigi
            self.report.debuggable = True

        # Permissionlar bo'yicha topilma
        for p in self.report.dangerous_permissions:
            self._add(Finding(
                category="permission",
                severity="medium",
                name="Dangerous Permission",
                value=p,
                source_file="AndroidManifest.xml",
            ))

        # Manifest stringlarini ham secret patternlar bo'yicha tekshiramiz
        for s in strings:
            self._scan_string(s, "AndroidManifest.xml")

        # URL / IP'larni ham manifestdan
        for s in strings:
            self._extract_urls_ips(s.encode("utf-8", "ignore"), "AndroidManifest.xml")

    def _scan_text_blob(self, data: bytes, source: str) -> None:
        # 1) ASCII stringlar
        for s in extract_ascii_strings(data, self.min_str_len):
            self._scan_string(s, source)
        # 2) UTF-16LE stringlar (Java/Android ko'pincha shuni ishlatadi)
        for s in extract_utf16le_strings(data, self.min_str_len):
            self._scan_string(s, source)
        # 3) URL / IP / Email — to'g'ridan-to'g'ri binary ustida
        self._extract_urls_ips(data, source)

    def _scan_string(self, s: str, source: str) -> None:
        if not s:
            return
        for name, sev, rx in self._compiled:
            for m in rx.finditer(s):
                val = m.group(0)
                if len(val) > 400:
                    val = val[:400] + "..."
                ctx = s.strip()
                if len(ctx) > 200:
                    # Match atrofidagi kontekst
                    start = max(0, m.start() - 60)
                    end = min(len(s), m.end() + 60)
                    ctx = s[start:end].strip()
                self._add(Finding(
                    category="secret",
                    severity=sev,
                    name=name,
                    value=val,
                    source_file=source,
                    context=ctx,
                ))

    def _extract_urls_ips(self, data: bytes, source: str) -> None:
        for m in URL_PATTERN.finditer(data):
            try:
                url = m.group(0).decode("ascii", "ignore").rstrip(".,);:'\"")
            except Exception:
                continue
            if not url or any(h in url for h in NOISE_HOSTS):
                continue
            sev = "low"
            lo = url.lower()
            if lo.startswith("http://"):
                sev = "medium"  # cleartext
            self._add(Finding(
                category="network",
                severity=sev,
                name="Hardcoded URL",
                value=url[:300],
                source_file=source,
            ))
        for m in IP_PATTERN.finditer(data):
            ip = m.group(0).decode("ascii", "ignore")
            # 0.0.0.0, 127.x, 255.x kabilarni filtrlash
            if ip.startswith(("0.", "127.", "255.", "240.")):
                continue
            self._add(Finding(
                category="network",
                severity="low",
                name="Hardcoded IP",
                value=ip,
                source_file=source,
            ))

    def _add(self, f: Finding) -> None:
        k = f.key()
        if k in self._seen:
            return
        self._seen.add(k)
        self.report.findings.append(f)

    def _dedupe(self) -> None:
        # severity bo'yicha tartibga solamiz
        order = {"high": 0, "medium": 1, "low": 2, "info": 3}
        self.report.findings.sort(key=lambda x: (order.get(x.severity, 9), x.category, x.name))


# ---------------------------------------------------------------------------
# Hisobotni chiqarish
# ---------------------------------------------------------------------------
SEV_COLOR = {"high": C_RED, "medium": C_YEL, "low": C_CYN, "info": C_GRN}

def print_report(rep: Report) -> None:
    print(f"\n{C_BLD}{C_MAG}=== APK Risk Scan Report ==={C_RST}")
    print(f"{C_BLD}File   :{C_RST} {rep.apk_path}")
    print(f"{C_BLD}Size   :{C_RST} {rep.apk_size:,} bytes")
    print(f"{C_BLD}MD5    :{C_RST} {rep.apk_md5}")
    print(f"{C_BLD}SHA256 :{C_RST} {rep.apk_sha256}")
    if rep.uses_cleartext:
        print(f"{C_YEL}[!] Manifest references usesCleartextTraffic{C_RST}")
    if rep.debuggable:
        print(f"{C_YEL}[!] Manifest references android:debuggable{C_RST}")

    if rep.dangerous_permissions:
        print(f"\n{C_BLD}Dangerous permissions ({len(rep.dangerous_permissions)}):{C_RST}")
        for p in rep.dangerous_permissions:
            print(f"  {C_YEL}- {p}{C_RST}")

    # Topilmalarni guruhlab chiqaramiz
    by_sev: dict[str, list[Finding]] = defaultdict(list)
    for f in rep.findings:
        by_sev[f.severity].append(f)

    total = len(rep.findings)
    print(f"\n{C_BLD}Findings: {total}  "
          f"{C_RED}high={len(by_sev['high'])}{C_RST}  "
          f"{C_YEL}medium={len(by_sev['medium'])}{C_RST}  "
          f"{C_CYN}low={len(by_sev['low'])}{C_RST}")

    for sev in ("high", "medium", "low", "info"):
        items = by_sev.get(sev, [])
        if not items:
            continue
        col = SEV_COLOR.get(sev, "")
        print(f"\n{C_BLD}{col}[{sev.upper()}] {len(items)} item(s){C_RST}")
        # Bir xil name'larni guruhlash
        groups: dict[tuple[str, str], list[Finding]] = defaultdict(list)
        for it in items:
            groups[(it.category, it.name)].append(it)
        for (cat, name), arr in groups.items():
            print(f"  {C_BLD}{name}{C_RST}  ({cat}, {len(arr)})")
            for it in arr[:20]:
                print(f"    - {it.value}   {C_MAG}<- {it.source_file}{C_RST}")
            if len(arr) > 20:
                print(f"    ... +{len(arr) - 20} more")


def save_reports(rep: Report, out_prefix: str) -> tuple[str, str]:
    json_path = out_prefix + ".json"
    txt_path  = out_prefix + ".txt"
    with open(json_path, "w", encoding="utf-8") as f:
        json.dump(rep.to_dict(), f, indent=2, ensure_ascii=False)
    with open(txt_path, "w", encoding="utf-8") as f:
        f.write(f"APK Risk Scan Report\n")
        f.write(f"====================\n")
        f.write(f"File   : {rep.apk_path}\n")
        f.write(f"Size   : {rep.apk_size}\n")
        f.write(f"MD5    : {rep.apk_md5}\n")
        f.write(f"SHA256 : {rep.apk_sha256}\n\n")
        if rep.dangerous_permissions:
            f.write("Dangerous permissions:\n")
            for p in rep.dangerous_permissions:
                f.write(f"  - {p}\n")
            f.write("\n")
        f.write(f"Findings ({len(rep.findings)}):\n")
        for it in rep.findings:
            f.write(f"[{it.severity.upper():6}] {it.category:10} {it.name}\n")
            f.write(f"        value : {it.value}\n")
            f.write(f"        file  : {it.source_file}\n")
            if it.context:
                f.write(f"        ctx   : {it.context[:200]}\n")
            f.write("\n")
    return json_path, txt_path


# ---------------------------------------------------------------------------
# CLI
# ---------------------------------------------------------------------------
def main() -> int:
    ap = argparse.ArgumentParser(description="APK secret/risk scanner (no decompilation).")
    ap.add_argument("apk", help="Path to the .apk file")
    ap.add_argument("-o", "--output", default=None,
                    help="Output prefix for .json / .txt report (default: <apk>.report)")
    ap.add_argument("--min-len", type=int, default=6,
                    help="Minimum string length to extract from binary blobs (default: 6)")
    ap.add_argument("--quiet", action="store_true", help="Faqat fayllarga yozsin, terminalga chiqarmasin")
    args = ap.parse_args()

    if not os.path.isfile(args.apk):
        print(f"{C_RED}[-] APK topilmadi: {args.apk}{C_RST}", file=sys.stderr)
        return 2
    if not zipfile.is_zipfile(args.apk):
        print(f"{C_RED}[-] Bu fayl ZIP/APK emas: {args.apk}{C_RST}", file=sys.stderr)
        return 2

    out_prefix = args.output or (os.path.splitext(args.apk)[0] + ".report")

    print(f"{C_CYN}[*] Skanerlanmoqda: {args.apk}{C_RST}")
    scanner = APKScanner(args.apk, min_str_len=args.min_len)
    report = scanner.scan()
    if not args.quiet:
        print_report(report)

    json_path, txt_path = save_reports(report, out_prefix)
    print(f"\n{C_GRN}[+] Hisobot saqlandi:{C_RST}")
    print(f"    {json_path}")
    print(f"    {txt_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
