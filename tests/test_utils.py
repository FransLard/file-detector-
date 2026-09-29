from engine import utils

def test_spoof_detection():
    e = utils.extension_analysis("invoice.pdf.exe")
    assert e["spoofed_double_ext"] is True

def test_clean_extension():
    e = utils.extension_analysis("catatan.txt")
    assert e["danger_score"] == 0

def test_hash_lengths():
    h = utils.hashes(b"hello")
    assert len(h["md5"]) == 32
    assert len(h["sha256"]) == 64
