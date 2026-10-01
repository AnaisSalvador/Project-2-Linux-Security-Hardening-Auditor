"""Data models for the Linux Security Hardening Auditor.

Every security check returns one Finding. A Report bundles all Findings
with metadata about the run. Reporters (console, JSON, Markdown) only
read these models; they never add data of their own.
"""

from dataclasses import dataclass
from enum import Enum


class Category(Enum):
    SSH = "SSH"
    USER = "USER"
    NETWORK = "NETWORK"
    SERVICE = "SERVICE"
    FILES = "FILES"


class Status(Enum):
    PASS = "PASS"
    FAIL = "FAIL"
    WARNING = "WARNING"
    NOT_ASSESSED = "NOT_ASSESSED"
    ERROR = "ERROR"


class Severity(Enum):
    CRITICAL = "CRITICAL"
    HIGH = "HIGH"
    MEDIUM = "MEDIUM"
    LOW = "LOW"
    INFO = "INFO"


# Lower number = more severe. Used only for sorting.
_SEVERITY_RANK = {
    Severity.CRITICAL: 0,
    Severity.HIGH: 1,
    Severity.MEDIUM: 2,
    Severity.LOW: 3,
    Severity.INFO: 4,
}


@dataclass(frozen=True)
class Finding:
    """The result of one security check."""

    check_id: str
    category: Category
    title: str
    status: Status
    severity: Severity
    evidence: list[str]
    expected_state: str
    why_it_matters: str
    remediation: str
    reference: str | None = None
    reason: str | None = None

    def __post_init__(self):
        # Required text fields must not be empty.
        required_text = {
            "check_id": self.check_id,
            "title": self.title,
            "expected_state": self.expected_state,
            "why_it_matters": self.why_it_matters,
            "remediation": self.remediation,
        }
        for name, value in required_text.items():
            if not isinstance(value, str) or not value.strip():
                raise ValueError(f"{name} must be a non-empty string")

        # Enum fields must be real enum members.
        if not isinstance(self.category, Category):
            raise ValueError("category must be a Category")
        if not isinstance(self.status, Status):
            raise ValueError("status must be a Status")
        if not isinstance(self.severity, Severity):
            raise ValueError("severity must be a Severity")

        if not isinstance(self.evidence, list):
            raise ValueError("evidence must be a list of strings")

        # Status-specific rules.
        if self.status in (Status.FAIL, Status.WARNING) and not self.evidence:
            raise ValueError(f"{self.status.value} findings require evidence")

        if self.status in (Status.NOT_ASSESSED, Status.ERROR):
            if not self.reason or not self.reason.strip():
                raise ValueError(f"{self.status.value} findings require a reason")

        if self.status == Status.PASS and self.reason is not None:
            raise ValueError("PASS findings must not have a reason")

    def to_dict(self) -> dict:
        """Return a JSON-friendly dict (enums become their string values)."""
        return {
            "check_id": self.check_id,
            "category": self.category.value,
            "title": self.title,
            "status": self.status.value,
            "severity": self.severity.value,
            "evidence": list(self.evidence),
            "expected_state": self.expected_state,
            "why_it_matters": self.why_it_matters,
            "remediation": self.remediation,
            "reference": self.reference,
            "reason": self.reason,
        }


@dataclass
class Report:
    """All findings from one run, plus metadata about the run."""

    tool_version: str
    hostname: str
    os_description: str
    timestamp: str  # ISO 8601, UTC
    is_root: bool
    findings: list[Finding]

    def __post_init__(self):
        ids = [f.check_id for f in self.findings]
        duplicates = sorted({i for i in ids if ids.count(i) > 1})
        if duplicates:
            raise ValueError(f"Duplicate check_id values: {', '.join(duplicates)}")

    def counts_by_status(self) -> dict[Status, int]:
        """Number of findings per status (every status is present, even if 0)."""
        counts = {status: 0 for status in Status}
        for finding in self.findings:
            counts[finding.status] += 1
        return counts

    def counts_by_severity(self) -> dict[Severity, int]:
        """Number of FAIL findings per severity (passes are not counted)."""
        counts = {severity: 0 for severity in Severity}
        for finding in self.findings:
            if finding.status == Status.FAIL:
                counts[finding.severity] += 1
        return counts

    def by_category(self) -> dict[Category, list[Finding]]:
        """Findings grouped by category, ordered by check ID within each group."""
        groups: dict[Category, list[Finding]] = {}
        for category in Category:
            members = [f for f in self.findings if f.category == category]
            if members:
                groups[category] = sorted(members, key=lambda f: f.check_id)
        return groups

    def sorted_findings(self) -> list[Finding]:
        """FAIL/WARNING first, then by severity (most severe first), then by ID."""
        def sort_key(f: Finding):
            needs_attention = f.status in (Status.FAIL, Status.WARNING)
            return (0 if needs_attention else 1, _SEVERITY_RANK[f.severity], f.check_id)

        return sorted(self.findings, key=sort_key)

    def not_assessed(self) -> list[Finding]:
        """Findings that could not be evaluated (NOT_ASSESSED or ERROR)."""
        return [
            f for f in self.findings
            if f.status in (Status.NOT_ASSESSED, Status.ERROR)
        ]

    def has_failures(self) -> bool:
        """True if any check has status FAIL (used for the CLI exit code)."""
        return any(f.status == Status.FAIL for f in self.findings)

    def to_dict(self) -> dict:
        """Return a JSON-friendly dict of the run metadata and all findings."""
        return {
            "tool_version": self.tool_version,
            "hostname": self.hostname,
            "os_description": self.os_description,
            "timestamp": self.timestamp,
            "is_root": self.is_root,
            "findings": [f.to_dict() for f in self.findings],
        }
