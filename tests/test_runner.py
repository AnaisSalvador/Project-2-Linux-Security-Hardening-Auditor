from hardening_auditor.checks.base import SecurityCheck
from hardening_auditor.models import Category, Finding, Severity, Status
from hardening_auditor.runner import Runner
from hardening_auditor.system import FakeSystemInfo


def make_finding(
    check_id: str,
    status: Status = Status.PASS,
) -> Finding:
    return Finding(
        check_id=check_id,
        category=Category.SSH,
        title=f"Test {check_id}",
        status=status,
        severity=Severity.INFO,
        evidence=["test evidence"] if status == Status.FAIL else [],
        expected_state="Expected test state.",
        why_it_matters="Test only.",
        remediation="Test only.",
    )


class PassingCheck(SecurityCheck):
    check_id = "TEST-01"
    category = Category.SSH
    title = "Passing check"

    def run(self, system):
        return make_finding(self.check_id)


class FailingCheck(SecurityCheck):
    check_id = "TEST-02"
    category = Category.SSH
    title = "Failing check"

    def run(self, system):
        return make_finding(self.check_id, Status.FAIL)


class BrokenCheck(SecurityCheck):
    check_id = "TEST-03"
    category = Category.SSH
    title = "Broken check"

    def run(self, system):
        raise RuntimeError("simulated failure")


def test_runner_collects_successful_finding():
    system = FakeSystemInfo()
    runner = Runner(system, [PassingCheck()])

    report = runner.run()

    assert len(report.findings) == 1
    assert report.findings[0].check_id == "TEST-01"
    assert report.findings[0].status == Status.PASS


def test_runner_collects_failed_finding():
    system = FakeSystemInfo()
    runner = Runner(system, [FailingCheck()])

    report = runner.run()

    assert len(report.findings) == 1
    assert report.findings[0].check_id == "TEST-02"
    assert report.findings[0].status == Status.FAIL


def test_runner_converts_unexpected_exception_to_error():
    system = FakeSystemInfo()
    runner = Runner(system, [BrokenCheck()])

    report = runner.run()

    assert len(report.findings) == 1
    finding = report.findings[0]

    assert finding.check_id == "TEST-03"
    assert finding.status == Status.ERROR
    assert finding.reason is not None
    assert "RuntimeError" in finding.reason


def test_runner_continues_after_check_error():
    system = FakeSystemInfo()
    runner = Runner(
        system,
        [
            PassingCheck(),
            BrokenCheck(),
            FailingCheck(),
        ],
    )

    report = runner.run()

    assert len(report.findings) == 3
    assert [f.check_id for f in report.findings] == [
        "TEST-01",
        "TEST-03",
        "TEST-02",
    ]

    assert [f.status for f in report.findings] == [
        Status.PASS,
        Status.ERROR,
        Status.FAIL,
    ]


def test_runner_builds_report_metadata():
    system = FakeSystemInfo()

    runner = Runner(system, [PassingCheck()])
    report = runner.run()

    assert report.tool_version == "0.1.0"
    assert report.hostname == system.hostname()
    assert report.os_description == system.os_description()
    assert report.is_root == system.is_root()
    assert report.timestamp
