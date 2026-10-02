"""Execution engine for security checks."""

from datetime import datetime, timezone

from hardening_auditor.checks.base import SecurityCheck
from hardening_auditor.models import (
    Category,
    Finding,
    Report,
    Severity,
    Status,
)
from hardening_auditor.system import SystemInfo


TOOL_VERSION = "0.1.0"


class Runner:
    """Execute security checks and build a Report."""

    def __init__(
        self,
        system: SystemInfo,
        checks: list[SecurityCheck],
    ):
        self.system = system
        self.checks = checks

    def run(self) -> Report:
        """Run every registered check and return the resulting report."""
        findings: list[Finding] = []

        for check in self.checks:
            try:
                finding = check.run(self.system)
                findings.append(finding)
            except Exception as exc:
                findings.append(self._error_finding(check, exc))

        return Report(
            tool_version=TOOL_VERSION,
            hostname=self.system.hostname(),
            os_description=self.system.os_description(),
            timestamp=datetime.now(timezone.utc).isoformat(),
            is_root=self.system.is_root(),
            findings=findings,
        )

    @staticmethod
    def _error_finding(
        check: SecurityCheck,
        exc: Exception,
    ) -> Finding:
        """Create an ERROR finding when a check raises unexpectedly."""
        return Finding(
            check_id=check.check_id,
            category=check.category,
            title=check.title,
            status=Status.ERROR,
            severity=Severity.INFO,
            evidence=[],
            expected_state="The check should complete without unexpected errors.",
            why_it_matters=(
                "An unexpected check error means this security condition "
                "could not be evaluated normally."
            ),
            remediation="Review the error and fix the check before relying on its result.",
            reason=f"{type(exc).__name__}: {exc}",
        )
