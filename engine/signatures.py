from __future__ import annotations
PATTERNS: list[tuple[str, str, bytes, int, str]] = [
    ("test", "EICAR-Test-File", b"eicar-standard-antivirus-test-file", 100, "String uji EICAR standar industri"),
    ("trojan", "Trojan:CreateRemoteThread", b"createremotethread", 18, "API injeksi proses khas trojan"),
    ("trojan", "Trojan:WriteProcessMemory", b"writeprocessmemory", 18, "API tulis memori proses lain"),
    ("trojan", "Trojan:VirtualAllocEx", b"virtualallocex", 14, "Alokasi memori di proses remote"),
    ("trojan", "Trojan:SetWindowsHookEx", b"setwindowshookex", 12, "Hook keyboard/mouse global"),
    ("trojan", "Trojan:ProcessHollowing", b"ntunmapviewofsection", 16, "Teknik process hollowing"),
    ("trojan", "Trojan:RunKeyPersistence", b"software\\microsoft\\windows\\currentversion\\run", 12, "Persistensi via registry Run"),
    ("trojan", "Trojan:AMSI-Bypass", b"amsiutils", 16, "Upaya bypass AMSI Defender"),
    ("trojan", "Trojan:AMSI-Bypass2", b"amsiscanbuffer", 16, "Upaya bypass AMSI scan"),
    ("ransomware", "Ransom:CryptEncrypt", b"cryptencrypt", 14, "API enkripsi file massal"),
    ("ransomware", "Ransom:CryptGenKey", b"cryptgenkey", 14, "Pembangkit kunci enkripsi"),
    ("ransomware", "Ransom:vssadmin-delete", b"vssadmin", 16, "Hapus shadow copy (hambat recovery)"),
    ("ransomware", "Ransom:wbadmin-delete", b"wbadmin delete", 16, "Hapus backup katalog"),
    ("ransomware", "Ransom:bcdedit-recovery", b"bcdedit", 12, "Ubah boot recovery"),
    ("ransomware", "Ransom:ransom-note", b"your files have been encrypted", 26, "Catatan tebusan khas ransomware"),
    ("ransomware", "Ransom:decrypt-instruction", b"send.*bitcoin.*decrypt", 18, "Instruksi pembayaran tebusan"),
    ("ransomware", "Ransom:onion-payment", b".onion", 8, "Alamat pembayaran hidden-service"),
    ("backdoor", "Backdoor:ReverseShell", b"reverse.*shell", 16, "String reverse shell"),
    ("backdoor", "Backdoor:Netcat", b"nc -e", 14, "Netcat dengan exec shell"),
    ("backdoor", "Backdoor:Meterpreter", b"meterpreter", 22, "Payload Metasploit Meterpreter"),
    ("backdoor", "Backdoor:Mimikatz", b"mimikatz", 22, "Tool pencuri kredensial"),
    ("backdoor", "Backdoor:PowershellDownload", b"invoke-mimikatz", 20, "Invoke-Mimikatz via PowerShell"),
    ("backdoor", "Backdoor:SocketConnect", b"socket.*connect", 8, "Koneksi socket keluar mentah"),
    ("keylogger", "Keylog:GetAsyncKeyState", b"getasynckeystate", 18, "API sadap tuts keyboard"),
    ("keylogger", "Keylog:GetKeyboardState", b"getkeyboardstate", 14, "API baca status keyboard"),
    ("keylogger", "Stealer:Clipboard", b"getclipboarddata", 10, "Akses clipboard"),
    ("keylogger", "Stealer:BrowserLogin", b"login data", 10, "Target file login browser"),
    ("keylogger", "Stealer:Cookies", b"cookies.sqlite", 10, "Target cookie browser"),
    ("worm", "Worm:autorun", b"autorun.inf", 12, "File autorun penyebar USB"),
    ("worm", "Worm:net-share", b"net share", 8, "Penyebaran via share jaringan"),
    ("worm", "Worm:task-scheduler", b"schtasks", 8, "Persistensi via Task Scheduler"),
    ("lolbin", "PS:BypassPolicy", b"bypass.*executionpolicy", 16, "Bypass ExecutionPolicy"),
    ("lolbin", "PS:HiddenWindow", b"-windowstyle hidden", 14, "PowerShell jendela tersembunyi"),
    ("lolbin", "PS:EncodedCommand", b"-encodedcommand", 14, "Perintah ter-encode (base64)"),
    ("lolbin", "PS:DownloadString", b"downloadstring", 14, "Unduh payload dari internet"),
    ("lolbin", "PS:InvokeExpression", b"invoke-expression", 12, "Eksekusi string dinamis (IEX)"),
    ("lolbin", "Certutil:Download", b"certutil.*-urlcache", 14, "certutil dipakai unduh file (LOLBin)"),
    ("lolbin", "Bitsadmin:Download", b"bitsadmin.*transfer", 12, "bitsadmin dipakai unduh payload"),
    ("obfuscation", "JS:eval+fromCharCode", b"fromcharcode", 12, "Deobfuscasi char-code khas JS jahat"),
    ("obfuscation", "JS:unescape-exec", b"unescape(", 10, "Decode + eksekusi JS"),
    ("obfuscation", "VBA:AutoOpen", b"autoopen", 16, "Macro auto-run saat dokumen dibuka"),
    ("obfuscation", "VBA:AutoExec", b"autoexec", 14, "Macro auto-exec"),
    ("obfuscation", "VBA:ShellExec", b"shell(", 10, "Macro panggil shell"),
    ("obfuscation", "VBA:PowershellCall", b"powershell", 12, "Macro panggil PowerShell"),
    ("obfuscation", "VBA:WMIExec", b"winmgmts", 12, "Macro akses WMI"),
    ("obfuscation", "Generic:Base64Blob", b"powershell.*-enc", 14, "Payload base64 via PowerShell"),
    ("dropper", "Dropper:URLDownloadToFile", b"urldownloadtofile", 16, "Unduh file kedua dari internet"),
    ("dropper", "Dropper:WinExec", b"winexec", 10, "Eksekusi payload di-drop"),
    ("dropper", "Dropper:ShellExecute", b"shellexecute", 8, "Jalankan file hasil drop"),
    ("phishing", "Phish:PasswordVerify", b"verify your password", 10, "Umpan verifikasi password"),
    ("phishing", "Phish:CredentialHarvest", b"document.forms.*password", 12, "Form panen kredensial"),
]
FAMILY_OF_CATEGORY = {
    "trojan": "Trojan", "ransomware": "Ransomware", "backdoor": "Backdoor",
    "keylogger": "Spyware/Keylogger", "worm": "Worm", "lolbin": "Suspicious Script (LOLBin)",
    "obfuscation": "Obfuscated/Macro", "dropper": "Dropper/Downloader",
    "phishing": "Phishing", "test": "Test File (EICAR)",
}

def scan_bytes(data: bytes) -> list[dict]:
    lowered = data.lower()
    hits: list[dict] = []
    seen: set[str] = set()
    for cat, label, pat, weight, desc in PATTERNS:
        if pat in lowered and label not in seen:
            seen.add(label)
            hits.append({"category": cat, "family": FAMILY_OF_CATEGORY.get(cat, cat), "label": label, "weight": weight, "description": desc})
    return hits
