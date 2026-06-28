from triage.heuristics import Evidence
from triage.verdict import compute_overall_verdict


def test_clean_when_nothing_flagged():
    assert compute_overall_verdict([Evidence("x", "info", "fine")], []) == "likely legitimate"


def test_suspicious_evidence_short_of_malicious():
    evidence = [Evidence("x", "suspicious", "hmm")]
    assert compute_overall_verdict(evidence, []) == "suspicious"


def test_malicious_evidence_wins():
    evidence = [Evidence("x", "suspicious", "hmm"), Evidence("y", "malicious", "bad")]
    assert compute_overall_verdict(evidence, []) == "phishing"


def test_malicious_enrichment_result_triggers_phishing_even_with_clean_heuristics():
    evidence = [Evidence("x", "info", "fine")]
    enrichment = [{"indicator": "evil.com", "verdict": "malicious"}]
    assert compute_overall_verdict(evidence, enrichment) == "phishing"


def test_suspicious_enrichment_result_triggers_suspicious():
    evidence = [Evidence("x", "info", "fine")]
    enrichment = [{"indicator": "evil.com", "verdict": "suspicious"}]
    assert compute_overall_verdict(evidence, enrichment) == "suspicious"


def test_unknown_enrichment_verdict_does_not_count_as_a_signal():
    evidence = [Evidence("x", "info", "fine")]
    enrichment = [{"indicator": "evil.com", "verdict": "unknown"}]
    assert compute_overall_verdict(evidence, enrichment) == "likely legitimate"
