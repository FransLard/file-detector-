from engine.detector import score_to_verdict

def test_thresholds():
    assert score_to_verdict(0)["level"] == "CLEAN"
    assert score_to_verdict(25)["level"] == "LOW"
    assert score_to_verdict(50)["level"] == "MEDIUM"
    assert score_to_verdict(75)["level"] == "HIGH"
    assert score_to_verdict(95)["level"] == "MALICIOUS"
