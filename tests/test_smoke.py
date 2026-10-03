from engine.detector import scan_file, score_to_verdict
from engine import utils

def test_eicar_detected():
    s = b"X5O!P%@AP[4\\PZX54(P^)7CC)7}$EICAR-STANDARD-ANTIVIRUS-TEST-FILE!$H+H*"
    r = scan_file(s, "eicar-test.txt", check_reputation=False)
    assert r["score"] == 100
    assert r["verdict"]["level"] == "MALICIOUS"
    assert r["blocked"] if "blocked" in r else True

def test_clean_file():
    r = scan_file(b"hello world", "catatan.txt", check_reputation=False)
    assert r["score"] < 20
    assert r["verdict"]["level"] == "CLEAN"

def test_double_extension_spoof():
    r = scan_file(b"hello", "invoice.pdf.exe", check_reputation=False)
    labels = [x["label"] for x in r["reasons"]]
    assert "EXT:double-extension-spoof" in labels

def test_score_to_verdict_thresholds():
    assert score_to_verdict(0)["level"] == "CLEAN"
    assert score_to_verdict(25)["level"] == "LOW"
    assert score_to_verdict(50)["level"] == "MEDIUM"
    assert score_to_verdict(75)["level"] == "HIGH"
    assert score_to_verdict(95)["level"] == "MALICIOUS"

def test_extension_utils():
    e = utils.extension_analysis("invoice.pdf.exe")
    assert e["spoofed_double_ext"] is True
