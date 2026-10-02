# File Detector — Malware Upload Scanner
Pemindai file saat upload dengan **sistem skor berlapis** untuk meminimalkan false positive
namun tetap detail (Trojan, Ransomware, Backdoor, Keylogger, Worm, Dropper, dsb).

## Cara jalan (Windows PowerShell)

```powershell
cd D:\file-detector
pip install -r requirements.txt
python app.py
# buka http://127.0.0.1:5000
```

## Arsitektur deteksi (5 lapis)

1. **Hash + identitas** — MD5/SHA1/SHA256, ukuran, magic bytes, MIME vs ekstensi.
2. **Reputasi online (opsional, gratis tanpa API key)** — lookup SHA256 ke MalwareBazaar
   (`https://mb-api.abuse.ch/api/v1/`). Kalau offline, otomatis dilewati.
3. **Signature YARA-like lokal** (`engine/signatures.py` + `yara_rules/malware.yar`) —
   pola Trojan, Ransomware, Reverse shell, Keylogger, VBA macro, PowerShell bypass,
   obfuscasi JS, dsb. Tanpa `yara-python` agar mudah install di Windows, tapi
   rule `.yar` tetap disediakan dan otomatis dipakai jika `yara-python` terinstall.
4. **Analisis PE** (`engine/pe_analyzer.py`, pakai `pefile`) — import mencurigakan
   (`CreateRemoteThread`, `VirtualAlloc`, ...), section packer (UPX/MPRESS),
   entropi tinggi, timestamp aneh.
5. **Heuristik anti-false-positive** — skor 0–100 dengan bobot, bukan vonis tunggal:
   - `0–19` CLEAN, `20–39` LOW, `40–69` MEDIUM, `70–84` HIGH, `85+` MALICIOUS
   - Ekstensi berbahaya saja tidak langsung divonis (hanya +10..15).
   - Perlu kombinasi 2+ sinyal untuk naik ke HIGH/MALICIOUS.

## API

- `GET /` — UI drag & drop
- `POST /api/scan` — form-data `file=@...` → JSON laporan
- `GET /api/eicar` — download string uji EICAR (standar industri, aman)
- `GET /api/health` — status engine

Contoh:

```powershell
curl -F "file=@D:\file-detector\README.md" http://127.0.0.1:5000/api/scan
```

## Uji cepat EICAR (file uji standar, TIDAK berbahaya)

String EICAR dideteksi semua AV sebagai `EICAR-Test-File`. Proyek ini mendeteksinya
dengan skor 100 tanpa perlu internet.

```powershell
# buat file uji lalu scan (string sengaja diputus agar README ini tidak ikut terdeteksi)
"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-" + "STANDARD-ANTIVIRUS-TEST-FILE!$H+H*" | Out-File -Encoding ascii eicar.txt
curl -F "file=@eicar.txt" http://127.0.0.1:5000/api/scan
# atau paling mudah: unduh dari server lalu scan (tanpa mengetik manual)
# curl -o eicar.txt http://127.0.0.1:5000/api/eicar
```

## Struktur

```
app.py                  Flask + routes
engine/
  detector.py           Orkestrasi + skoring
  signatures.py         Pola Trojan/Ransomware/dsb
  pe_analyzer.py        Analisis PE dengan pefile
  reputation.py         Lookup MalwareBazaar (opsional)
  utils.py              Hash, entropi, MIME, ekstensi
yara_rules/malware.yar  Rule YARA asli (dipakai jika yara-python ada)
templates/index.html    UI drag-drop + laporan
static/app.js style.css Frontend
```

## Catatan akurasi & batasan

- Ini **bukan pengganti antivirus** (ClamAV / VirusTotal). Ini lapisan pra-upload
  yang cepat & explainable.
- Untuk produksi: tambahkan ClamAV daemon atau VirusTotal API (70+ engine),
  simpan karantina, batasi ukuran file, dan scan async via Celery/RQ.
- Lihat `engine/detector.py` fungsi `score_to_verdict()` untuk threshold.
