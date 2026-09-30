from __future__ import annotations
import os
from flask import Flask, request, jsonify, render_template, Response
from engine.detector import scan_file, MAX_SCAN_BYTES
from engine import __version__
app = Flask(__name__)
app.config["MAX_CONTENT_LENGTH"] = MAX_SCAN_BYTES + 1024 * 1024
EICAR_STRING = r"X5O!P%@AP[4\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"

@app.get("/")
def index():
    return render_template("index.html")

@app.get("/api/health")
def health():
    try:
        import pefile
        pe_ok = True
    except ImportError:
        pe_ok = False
    try:
        import yara
        yara_ok = True
    except ImportError:
        yara_ok = False
    return jsonify({"status": "ok", "pefile": pe_ok, "yara": yara_ok, "max_bytes": MAX_SCAN_BYTES, "version": __version__})

@app.get("/api/eicar")
def eicar():
    return Response(EICAR_STRING, mimetype="text/plain", headers={"Content-Disposition": "attachment; filename=eicar-test.txt"})

@app.post("/api/scan")
def scan():
    try:
        if "file" not in request.files:
            return jsonify({"error": "Field 'file' wajib (form-data)."}), 400
        f = request.files["file"]
        if not f.filename:
            return jsonify({"error": "Nama file kosong."}), 400
        data = f.read()
        if not data:
            return jsonify({"error": "File kosong."}), 400
        if len(data) > MAX_SCAN_BYTES:
            return jsonify({"error": f"File {len(data)/1048576:.1f} MB melebihi batas {MAX_SCAN_BYTES // 1048576} MB."}), 413
        check_rep = request.args.get("reputation", "1") != "0"
        result = scan_file(data, f.filename, check_reputation=check_rep)
        result["blocked"] = result["score"] >= 40
        return jsonify(result)
    except Exception as e:
        import traceback
        traceback.print_exc()
        return jsonify({"error": f"Gagal memindai: {e}"}), 500

@app.errorhandler(413)
def too_large(e):
    return jsonify({"error": f"File terlalu besar (maks {MAX_SCAN_BYTES // 1048576} MB)."}), 413

@app.errorhandler(500)
def internal(e):
    return jsonify({"error": "Error internal server saat memindai."}), 500

if __name__ == "__main__":
    port = int(os.environ.get("PORT", 5000))
    app.run(host="127.0.0.1", port=port, debug=False, threaded=True)
