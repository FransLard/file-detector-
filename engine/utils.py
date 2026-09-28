from __future__ import annotations
import hashlib
import math
import mimetypes
from collections import Counter
from pathlib import Path
DANGEROUS_EXTS = {
    ".exe": 15, ".scr": 15, ".msi": 15, ".bat": 14, ".cmd": 14,
    ".ps1": 14, ".vbs": 14, ".vbe": 14, ".js": 12, ".jse": 14,
    ".wsf": 14, ".hta": 14, ".jar": 12, ".dll": 10, ".com": 15,
    ".pif": 15, ".lnk": 13, ".iso": 10, ".img": 10, ".cab": 8,
    ".html": 5, ".htm": 5, ".svg": 5,
}
SPOOFABLE_DOC_EXTS = {".pdf", ".doc", ".docx", ".xls", ".xlsx", ".ppt", ".pptx", ".jpg", ".jpeg", ".png", ".gif", ".mp4", ".mp3", ".txt", ".csv"}

def hashes(data: bytes) -> dict:
    return {"md5": hashlib.md5(data).hexdigest(), "sha1": hashlib.sha1(data).hexdigest(), "sha256": hashlib.sha256(data).hexdigest(), "size": len(data)}

def entropy(data: bytes) -> float:
    if not data:
        return 0.0
    sample = data[:2_000_000]
    freq = Counter(sample)
    n = len(sample)
    return -sum((c / n) * math.log2(c / n) for c in freq.values())

def magic_kind(data: bytes, filename: str) -> dict:
    sigs = [
        (b"MZ", "PE executable (exe/dll)"),
        (b"%PDF", "PDF document"),
        (b"\x50\x4b\x03\x04", "ZIP container (docx/xlsx/apk/jar)"),
        (b"\xd0\xcf\x11\xe0", "OLE container (doc/xls/ppt lama, macro-enabled)"),
        (b"\x7fELF", "ELF executable (linux)"),
        (b"\x89PNG", "PNG image"),
        (b"\xff\xd8\xff", "JPEG image"),
        (b"GIF8", "GIF image"),
        (b"PK\x03\x04", "ZIP archive"),
        (b"Rar!", "RAR archive"),
        (b"7z\xbc\xaf", "7-Zip archive"),
        (b"MZ", "MS-DOS executable"),
    ]
    kind = "unknown/generic binary"
    for magic, label in sigs:
        if data.startswith(magic):
            kind = label
            break
    if data.startswith(b"#!/"):
        kind = "Script (shebang)"
    elif data.lstrip().startswith(b"<html") or data.lstrip().lower().startswith(b"<!doctype html"):
        kind = "HTML document"
    elif data.startswith(b"{\\rtf"):
        kind = "RTF document"
    guessed_mime, _ = mimetypes.guess_type(filename)
    return {"magic": kind, "is_pe": data.startswith(b"MZ"), "is_elf": data.startswith(b"\x7fELF"), "guessed_mime": guessed_mime or "application/octet-stream"}

def extension_analysis(filename: str) -> dict:
    import re
    name = Path(filename).name
    raw = Path(name.lower()).suffixes
    suffixes = [s for s in raw if re.fullmatch(r"\.[a-z]{1,5}[a-z0-9]?", s)]
    if not suffixes and raw:
        suffixes = [raw[-1]]
    ext = suffixes[-1] if suffixes else ""
    double_ext = len(suffixes) >= 2
    spoofed = double_ext and suffixes[-2] in SPOOFABLE_DOC_EXTS and ext in DANGEROUS_EXTS
    danger = DANGEROUS_EXTS.get(ext, 0)
    rlo = "\u202e" in name
    long_spaces = "  " in Path(name).stem and ext in DANGEROUS_EXTS
    return {"filename": name, "ext": ext, "all_exts": suffixes, "double_ext": double_ext, "spoofed_double_ext": spoofed, "danger_score": danger, "has_rlo": rlo, "hidden_ext_trick": long_spaces}

def is_eicar(data: bytes) -> bool:
    return b"EICAR-STANDARD-ANTIVIRUS-TEST-FILE" in data
