from hardening_auditor.models import (
    Category,
    Finding,
    Report,
    Severity,
    Status,
)
from hardening_auditor.reporting.console import render_console
from hardening_auditor.reporting.json_report import render_json
from hardening_auditor.reporting.markdown import render_markdown


def make_report() -> Report:
    finding = Finding(
        check_id="TEST-01",
        category=Category.SSH,
        title="Test finding",
        status=Status.FAIL,
        severity=Severity.HIGH,
        evidence=["Example evidence"],
        expected_state="The test should pass.",
        why_it_matters="This is a test.",
        remediation="Fix the test.",
        reference="test-reference",
    )

    return Report(
        tool_version="0.1.0",
        hostname="test-host",
        os_description="Test Linux",
        timestamp="2026-10-01T00:00:00+00:00",
        is_root=True,
        findings=[finding],
    )


def test_json_report_contains_report_data():
    report = make_report()

    output = render_json(report)

    assert '"check_id": "TEST-01"' in output
    assert '"status": "FAIL"' in output
    assert '"severity": "HIGH"' in output
    assert '"Example evidence"' in output


def test_markdown_report_contains_finding():
    report = make_report()

    output = render_markdown(report)

    assert "# Linux Security Hardening Audit" in output
    assert "### TEST-01 — Test finding" in output
    assert "**Status:** FAIL" in output
    assert "**Severity:** HIGH" in output
    assert "Example evidence" in output


def test_console_report_contains_summary_and_finding():
    report = make_report()

    output = render_console(report)

    assert "Linux Security Hardening Auditor" in output
    assert "FAIL:         1" in output
    assert "[FAIL] TEST-01 Test finding" in output
    assert "Example evidence" in output
