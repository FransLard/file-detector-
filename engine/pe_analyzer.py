from __future__ import annotations
SUSPICIOUS_IMPORTS = {
    "createremotethread": 12, "writeprocessmemory": 12, "virtualallocex": 10,
    "ntunmapviewofsection": 12, "setwindowshookexa": 10, "setwindowshookexw": 10,
    "getasynckeystate": 12, "urldownloadtofilea": 12, "urldownloadtofilew": 12,
    "winexec": 8, "shellexecutea": 6, "cryptencrypt": 10, "adjusttokenprivileges": 8,
    "iscaladmin": 4, "samconnect": 10, "netuseradd": 8,
}
PACKER_SECTIONS = ("upx", "mpress", "aspack", "themida", "vmp", "enigma", "petite")

def analyze_pe(data: bytes) -> dict:
    findings: list[dict] = []
    score = 0
    meta: dict = {"is_pe": False}
    if not data.startswith(b"MZ"):
        return {"score": 0, "findings": findings, "meta": meta}
    meta["is_pe"] = True
    try:
        import pefile
    except ImportError:
        findings.append({"label": "PE:pefile-missing", "weight": 0, "description": "pefile belum diinstall — analisis PE dilewati (pip install pefile)"})
        return {"score": 0, "findings": findings, "meta": meta}
    try:
        pe = pefile.PE(data=data, fast_load=False)
    except Exception as e:
        findings.append({"label": "PE:invalid-header", "weight": 10, "description": f"Header MZ tapi bukan PE valid: {e}"})
        return {"score": 10, "findings": findings, "meta": meta}
    try:
        imports: set[str] = set()
        if hasattr(pe, "DIRECTORY_ENTRY_IMPORT"):
            for entry in pe.DIRECTORY_ENTRY_IMPORT:
                for imp in entry.imports or []:
                    if imp.name:
                        imports.add(imp.name.decode(errors="ignore").lower())
        for name in sorted(imports):
            base = name.strip().lower()
            if base in SUSPICIOUS_IMPORTS:
                w = SUSPICIOUS_IMPORTS[base]
                score += w
                findings.append({"label": f"PE:import:{name}", "weight": w, "description": f"Import API berisiko: {name}"})
        meta["import_count"] = len(imports)
    except Exception:
        pass
    try:
        for s in pe.FILE_HEADER and pe.sections or []:
            sname = s.Name.decode(errors="ignore").strip("\x00").lower()
            ent = s.get_entropy()
            if any(p in sname for p in PACKER_SECTIONS):
                score += 18
                findings.append({"label": f"PE:packed:{sname}", "weight": 18, "description": f"Section packer terdeteksi ({sname}), entropi {ent:.1f}"})
            elif ent > 7.2:
                score += 8
                findings.append({"label": f"PE:high-entropy:{sname}", "weight": 8, "description": f"Section entropi tinggi ({sname}={ent:.1f}), indikasi packer/enkripsi"})
        meta["sections"] = [s.Name.decode(errors="ignore").strip("\x00") for s in pe.sections]
        ts = pe.FILE_HEADER.TimeDateStamp
        meta["timestamp"] = ts
        if ts == 0 or ts > 1893456000:
            score += 6
            findings.append({"label": "PE:bad-timestamp", "weight": 6, "description": "Timestamp kompilasi nol / tidak wajar"})
    except Exception:
        pass
    try:
        pe.close()
    except Exception:
        pass
    return {"score": min(score, 45), "findings": findings, "meta": meta}
