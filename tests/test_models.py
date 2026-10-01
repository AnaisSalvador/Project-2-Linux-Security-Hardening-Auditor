"""Tests for hardening_auditor.models."""

import pytest

from hardening_auditor.models import (
    Category,
    Finding,
    Report,
    Severity,
    Status,
)


# ---------------------------------------------------------------------------
# Helpers
# ---------------------------------------------------------------------------

def make_finding(**overrides) -> Finding:
    """Build a valid PASS finding; override any field to change it."""
    values = {
        "check_id": "SSH-01",
        "category": Category.SSH,
        "title": "SSH root login",
        "status": Status.PASS,
        "severity": Severity.HIGH,
        "evidence": ["permitrootlogin no"],
        "expected_state": "PermitRootLogin is 'no'",
        "why_it_matters": "Root login enables brute-force against a known account.",
        "remediation": "Set 'PermitRootLogin no' and reload sshd.",
        "reference": None,
        "reason": None,
    }
    values.update(overrides)
    return Finding(**values)


def make_report(findings) -> Report:
    return Report(
        tool_version="0.1.0",
        hostname="testhost",
        os_description="Ubuntu 22.04",
        timestamp="2025-01-01T00:00:00Z",
        is_root=False,
        findings=findings,
    )


# ---------------------------------------------------------------------------
# 1. Enums
# ---------------------------------------------------------------------------

def test_category_values():
    assert {c.value for c in Category} == {
        "SSH", "USER", "NETWORK", "SERVICE", "FILES",
    }


def test_status_values():
    assert {s.value for s in Status} == {
        "PASS", "FAIL", "WARNING", "NOT_ASSESSED", "ERROR",
    }


def test_severity_values():
    assert {s.value for s in Severity} == {
        "CRITICAL", "HIGH", "MEDIUM", "LOW", "INFO",
    }


# ---------------------------------------------------------------------------
# 2. Valid Finding
# ---------------------------------------------------------------------------

def test_valid_finding_can_be_created():
    finding = make_finding()
    assert finding.check_id == "SSH-01"
    assert finding.category == Category.SSH
    assert finding.status == Status.PASS
    assert finding.severity == Severity.HIGH
    assert finding.evidence == ["permitrootlogin no"]
    assert finding.reference is None
    assert finding.reason is None


# ---------------------------------------------------------------------------
# 3-7. Status validation rules
# ---------------------------------------------------------------------------

def test_fail_without_evidence_raises():
    with pytest.raises(ValueError):
        make_finding(status=Status.FAIL, evidence=[])


def test_warning_without_evidence_raises():
    with pytest.raises(ValueError):
        make_finding(status=Status.WARNING, evidence=[])


def test_not_assessed_without_reason_raises():
    with pytest.raises(ValueError):
        make_finding(status=Status.NOT_ASSESSED, evidence=[], reason=None)


def test_error_without_reason_raises():
    with pytest.raises(ValueError):
        make_finding(status=Status.ERROR, evidence=[], reason=None)


def test_pass_with_reason_raises():
    with pytest.raises(ValueError):
        make_finding(status=Status.PASS, reason="should not be here")


# ---------------------------------------------------------------------------
# 8. Invalid enum values
# ---------------------------------------------------------------------------

def test_invalid_category_raises():
    with pytest.raises(ValueError):
        make_finding(category="SSH")  # a plain string, not a Category


def test_invalid_status_raises():
    with pytest.raises(ValueError):
        make_finding(status="PASS")


def test_invalid_severity_raises():
    with pytest.raises(ValueError):
        make_finding(severity="HIGH")


# ---------------------------------------------------------------------------
# 9. Finding.to_dict()
# ---------------------------------------------------------------------------

def test_finding_to_dict_converts_enums_to_strings():
    data = make_finding(status=Status.FAIL, evidence=["permitrootlogin yes"]).to_dict()
    assert data["category"] == "SSH"
    assert data["status"] == "FAIL"
    assert data["severity"] == "HIGH"
    assert data["check_id"] == "SSH-01"
    assert data["reference"] is None
    assert data["reason"] is None


def test_finding_to_dict_copies_evidence():
    finding = make_finding()
    data = finding.to_dict()
    assert data["evidence"] == finding.evidence
    assert data["evidence"] is not finding.evidence

    data["evidence"].append("changed")
    assert finding.evidence == ["permitrootlogin no"]


# ---------------------------------------------------------------------------
# 10-11. Report creation and validation
# ---------------------------------------------------------------------------

def test_valid_report_can_be_created():
    findings = [make_finding(), make_finding(check_id="SSH-02")]
    report = make_report(findings)
    assert report.hostname == "testhost"
    assert report.is_root is False
    assert len(report.findings) == 2


def test_duplicate_check_ids_raise():
    findings = [make_finding(), make_finding()]
    with pytest.raises(ValueError):
        make_report(findings)


# ---------------------------------------------------------------------------
# 12-13. Counts
# ---------------------------------------------------------------------------

def test_counts_by_status_includes_all_statuses():
    report = make_report([
        make_finding(check_id="SSH-01", status=Status.PASS),
        make_finding(check_id="SSH-02", status=Status.PASS),
        make_finding(check_id="SSH-03", status=Status.FAIL, evidence=["bad"]),
    ])
    counts = report.counts_by_status()
    assert set(counts) == set(Status)
    assert counts[Status.PASS] == 2
    assert counts[Status.FAIL] == 1
    assert counts[Status.WARNING] == 0
    assert counts[Status.NOT_ASSESSED] == 0
    assert counts[Status.ERROR] == 0


def test_counts_by_severity_counts_only_fail_findings():
    report = make_report([
        make_finding(check_id="A-1", status=Status.FAIL, severity=Severity.HIGH, evidence=["x"]),
        make_finding(check_id="A-2", status=Status.FAIL, severity=Severity.HIGH, evidence=["x"]),
        make_finding(check_id="A-3", status=Status.FAIL, severity=Severity.LOW, evidence=["x"]),
        make_finding(check_id="A-4", status=Status.PASS, severity=Severity.CRITICAL),
        make_finding(check_id="A-5", status=Status.WARNING, severity=Severity.MEDIUM, evidence=["x"]),
    ])
    counts = report.counts_by_severity()
    assert set(counts) == set(Severity)
    assert counts[Severity.HIGH] == 2
    assert counts[Severity.LOW] == 1
    assert counts[Severity.CRITICAL] == 0  # the CRITICAL one is a PASS
    assert counts[Severity.MEDIUM] == 0    # the MEDIUM one is a WARNING
    assert counts[Severity.INFO] == 0


# ---------------------------------------------------------------------------
# 14. by_category()
# ---------------------------------------------------------------------------

def test_by_category_groups_findings():
    ssh_2 = make_finding(check_id="SSH-02")
    ssh_1 = make_finding(check_id="SSH-01")
    usr_1 = make_finding(check_id="USR-01", category=Category.USER)
    report = make_report([ssh_2, usr_1, ssh_1])

    groups = report.by_category()

    assert set(groups) == {Category.SSH, Category.USER}  # empty categories omitted
    assert groups[Category.SSH] == [ssh_1, ssh_2]       # sorted by check ID
    assert groups[Category.USER] == [usr_1]


# ---------------------------------------------------------------------------
# 15. sorted_findings()
# ---------------------------------------------------------------------------

def test_sorted_findings_orders_by_attention_then_severity_then_id():
    pass_high = make_finding(check_id="A-1", status=Status.PASS, severity=Severity.HIGH)
    fail_low = make_finding(check_id="A-2", status=Status.FAIL, severity=Severity.LOW, evidence=["x"])
    fail_critical = make_finding(check_id="A-3", status=Status.FAIL, severity=Severity.CRITICAL, evidence=["x"])
    warn_medium = make_finding(check_id="A-4", status=Status.WARNING, severity=Severity.MEDIUM, evidence=["x"])
    pass_critical = make_finding(check_id="A-5", status=Status.PASS, severity=Severity.CRITICAL)

    report = make_report([pass_high, fail_low, fail_critical, warn_medium, pass_critical])

    ids = [f.check_id for f in report.sorted_findings()]
    assert ids == ["A-3", "A-4", "A-2", "A-5", "A-1"]


def test_sorted_findings_uses_check_id_as_tiebreaker():
    second = make_finding(check_id="A-2", status=Status.FAIL, evidence=["x"])
    first = make_finding(check_id="A-1", status=Status.FAIL, evidence=["x"])
    report = make_report([second, first])

    assert [f.check_id for f in report.sorted_findings()] == ["A-1", "A-2"]


# ---------------------------------------------------------------------------
# 16. not_assessed()
# ---------------------------------------------------------------------------

def test_not_assessed_returns_not_assessed_and_error_findings():
    passed = make_finding(check_id="A-1")
    failed = make_finding(check_id="A-2", status=Status.FAIL, evidence=["x"])
    skipped = make_finding(
        check_id="A-3", status=Status.NOT_ASSESSED, evidence=[], reason="needs root"
    )
    crashed = make_finding(
        check_id="A-4", status=Status.ERROR, evidence=[], reason="unexpected exception"
    )
    report = make_report([passed, failed, skipped, crashed])

    assert report.not_assessed() == [skipped, crashed]


# ---------------------------------------------------------------------------
# 17. has_failures()
# ---------------------------------------------------------------------------

def test_has_failures_true_when_any_fail():
    report = make_report([
        make_finding(check_id="A-1"),
        make_finding(check_id="A-2", status=Status.FAIL, evidence=["x"]),
    ])
    assert report.has_failures() is True


def test_has_failures_false_without_fail():
    report = make_report([
        make_finding(check_id="A-1", status=Status.PASS),
        make_finding(check_id="A-2", status=Status.WARNING, evidence=["x"]),
        make_finding(check_id="A-3", status=Status.NOT_ASSESSED, evidence=[], reason="needs root"),
        make_finding(check_id="A-4", status=Status.ERROR, evidence=[], reason="crashed"),
    ])
    assert report.has_failures() is False


def test_has_failures_false_for_empty_report():
    assert make_report([]).has_failures() is False


# ---------------------------------------------------------------------------
# 18. Report.to_dict()
# ---------------------------------------------------------------------------

def test_report_to_dict_contains_metadata_and_findings():
    finding = make_finding()
    data = make_report([finding]).to_dict()

    assert data["tool_version"] == "0.1.0"
    assert data["hostname"] == "testhost"
    assert data["os_description"] == "Ubuntu 22.04"
    assert data["timestamp"] == "2025-01-01T00:00:00Z"
    assert data["is_root"] is False
    assert data["findings"] == [finding.to_dict()]
