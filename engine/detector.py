from __future__ import annotations
import re
import zipfile
from io import BytesIO
from . import utils, signatures
from .pe_analyzer import analyze_pe
from .reputation import lookup_sha256
MAX_SCAN_BYTES = 100 * 1024 * 1024

def score_to_verdict(score: int) -> dict:
    if score >= 85:
        return {"level": "MALICIOUS", "color": "red", "action": "BLOKIR — jangan upload / karantina file ini."}
    if score >= 70:
        return {"level": "HIGH", "color": "orange", "action": "BERBAHAYA — sangat disarankan diblokir."}
    if score >= 40:
        return {"level": "MEDIUM", "color": "yellow", "action": "MENCURIGAKAN — verifikasi manual sebelum diizinkan."}
    if score >= 20:
        return {"level": "LOW", "color": "blue", "action": "WASPADA — rendah, tapi catat & awasi."}
    return {"level": "CLEAN", "color": "green", "action": "AMAN — boleh diupload."}

def _zip_inspection(data: bytes) -> list[dict]:
    out: list[dict] = []
    if not data.startswith(b"PK\x03\x04"):
        return out
    try:
        zf = zipfile.ZipFile(BytesIO(data))
        names = zf.namelist()
        if "word/vbaProject.bin" in names or "xl/vbaProject.bin" in names:
            out.append({"label": "DOC:macro-inside", "weight": 25, "category": "obfuscation", "family": "Obfuscated/Macro", "description": "Dokumen Office berisi VBA macro (vbaProject.bin)"})
        for n in names:
            ln = n.lower()
            if ln.endswith((".exe", ".scr", ".bat", ".ps1", ".vbs", ".dll", ".com")):
                out.append({"label": f"ZIP:exe-inside:{n[:60]}", "weight": 22, "category": "dropper", "family": "Dropper/Downloader", "description": f"Arsip berisi executable: {n[:80]}"})
                break
        if any("androidmanifest.xml" in n for n in names):
            out.append({"label": "APK:android-package", "weight": 8, "category": "dropper", "family": "Dropper/Downloader", "description": "Paket Android (APK) — pastikan sumber tepercaya"})
    except Exception:
        pass
    return out

def _ole_inspection(data: bytes) -> list[dict]:
    out: list[dict] = []
    if data.startswith(b"\xd0\xcf\x11\xe0"):
        out.append({"label": "DOC:ole-legacy", "weight": 8, "category": "obfuscation", "family": "Obfuscated/Macro", "description": "Dokumen Office lama (OLE) — sering disalahgunakan untuk macro"})
    if data.lstrip().startswith(b"{\\rtf"):
        if b"\\objdata" in data.lower():
            out.append({"label": "RTF:embedded-object", "weight": 18, "category": "dropper", "family": "Dropper/Downloader", "description": "RTF berisi objek embedded (vektor exploit klasik)"})
    return out

def scan_file(data: bytes, filename: str, check_reputation: bool = True) -> dict:
    reasons: list[dict] = []
    score = 0
    def add(label: str, weight: int, description: str, category: str = "heuristic", family: str = "Heuristic"):
        nonlocal score
        score += weight
        reasons.append({"label": label, "weight": weight, "description": description, "category": category, "family": family})
    h = utils.hashes(data)
    ent = utils.entropy(data)
    kind = utils.magic_kind(data, filename)
    ext = utils.extension_analysis(filename)
    if utils.is_eicar(data):
        add("EICAR-Test-File", 100, "String uji antivirus standar (terdeteksi semua AV)", "test", "Test File (EICAR)")
    if ext["danger_score"]:
        add(f"EXT:{ext['ext']}-executable", ext["danger_score"], f"Ekstensi dapat dieksekusi ({ext['ext']}) — hati-hati, bukan vonis tunggal")
    if ext["spoofed_double_ext"]:
        add("EXT:double-extension-spoof", 35, f"Ekstensi ganda menipu: {'.'.join(ext['all_exts'])} (mis. invoice.pdf.exe)", "heuristic", "Trojan")
    elif ext["double_ext"] and ext["ext"] in (".exe", ".scr", ".bat"):
        add("EXT:double-extension", 15, f"Ekstensi ganda: {'.'.join(ext['all_exts'])}")
    if ext["has_rlo"]:
        add("EXT:rlo-trick", 25, "Mengandung karakter Right-to-Left Override (U+202E) untuk menyamarkan ekstensi", "heuristic", "Trojan")
    if ext["hidden_ext_trick"]:
        add("EXT:hidden-spaces", 12, "Spasi berlebih untuk menyembunyikan ekstensi asli")
    doc_exts = {".pdf", ".jpg", ".jpeg", ".png", ".gif", ".docx", ".xlsx", ".txt", ".mp3", ".mp4"}
    if kind["is_pe"] and ext["ext"] in doc_exts:
        add("SPOOF:exe-disguised-as-doc", 40, f"Konten PE-executable tapi ekstensi {ext['ext']} — penyamaran klasik malware", "heuristic", "Trojan")
    if kind["is_elf"] and ext["ext"] in doc_exts:
        add("SPOOF:elf-disguised", 30, "Konten ELF-executable menyamar sebagai dokumen", "heuristic", "Trojan")
    if ent > 7.6:
        add("ENTROPY:very-high", 15, f"Entropi sangat tinggi ({ent:.2f}) — indikasi packer/enkripsi")
    elif ent > 7.0:
        add("ENTROPY:high", 8, f"Entropi tinggi ({ent:.2f})")
    for hit in signatures.scan_bytes(data[:4_000_000]):
        if hit["label"] == "EICAR-Test-File" and any(r["label"] == "EICAR-Test-File" for r in reasons):
            continue
        add(hit["label"], hit["weight"], hit["description"], hit["category"], hit["family"])
    yara_hits = _try_yara(data)
    for yh in yara_hits:
        add(yh["label"], yh["weight"], yh["description"], "yara", yh.get("family", "YARA"))
    for f in _zip_inspection(data) + _ole_inspection(data):
        add(f["label"], f["weight"], f["description"], f.get("category", "heuristic"), f.get("family", "Heuristic"))
    if kind["is_pe"]:
        pe = analyze_pe(data)
        for f in pe["findings"]:
            add(f["label"], f["weight"], f["description"], "pe", "Trojan")
    reputation: dict = {"available": False, "found": False, "reason": "skipped"}
    if check_reputation and not utils.is_eicar(data):
        reputation = lookup_sha256(h["sha256"])
        if reputation.get("found"):
            add(f"REPUTATION:known-malware:{reputation.get('family', '?')}", 85, f"SHA256 dikenal di MalwareBazaar sebagai {reputation.get('family')} ({reputation.get('vendor_hits', '?')} vendor). {reputation.get('link', '')}", "reputation", str(reputation.get("family", "Known Malware")))
    score = max(0, min(100, score))
    verdict = score_to_verdict(score)
    fam_scores: dict[str, int] = {}
    for r in reasons:
        fam_scores[r.get("family", "?")] = fam_scores.get(r.get("family", "?"), 0) + r["weight"]
    family = max(fam_scores, key=fam_scores.get) if fam_scores else ("Clean" if score < 20 else "Suspicious")
    return {"filename": ext["filename"], "hashes": h, "size_human": _human(h["size"]), "entropy": round(ent, 2), "magic": kind["magic"], "mime": kind["guessed_mime"], "ext": ext, "score": score, "verdict": verdict, "family": family, "reasons": sorted(reasons, key=lambda r: -r["weight"]), "reputation": reputation}

def _try_yara(data: bytes) -> list[dict]:
    try:
        import yara, pathlib
        rule_path = pathlib.Path(__file__).resolve().parent.parent / "yara_rules" / "malware.yar"
        if not rule_path.exists():
            return []
        rules = yara.compile(filepath=str(rule_path))
        matches = rules.match(data=data[:8_000_000])
        out = []
        for m in matches:
            out.append({"label": f"YARA:{m.rule}", "weight": int((m.meta or {}).get("weight", 20)), "description": str((m.meta or {}).get("description", m.rule)), "family": str((m.meta or {}).get("family", "YARA"))})
        return out
    except Exception:
        return []

def _human(n: int) -> str:
    for unit in ("B", "KB", "MB", "GB"):
        if n < 1024:
            return f"{n:.1f} {unit}"
        n /= 1024
    return f"{n:.1f} TB"
