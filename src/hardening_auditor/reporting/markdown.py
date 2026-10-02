"""Markdown report renderer."""

from hardening_auditor.models import Report, Status


def render_markdown(report: Report) -> str:
    """Render a Report as Markdown."""
    lines = [
        "# Linux Security Hardening Audit",
        "",
        f"- **Tool version:** {report.tool_version}",
        f"- **Hostname:** {report.hostname}",
        f"- **Operating system:** {report.os_description}",
        f"- **Timestamp:** {report.timestamp}",
        f"- **Running as root:** {report.is_root}",
        "",
        "## Summary",
        "",
    ]

    status_counts = report.counts_by_status()

    lines.extend(
        [
            f"- PASS: {status_counts[Status.PASS]}",
            f"- FAIL: {status_counts[Status.FAIL]}",
            f"- WARNING: {status_counts[Status.WARNING]}",
            f"- NOT_ASSESSED: {status_counts[Status.NOT_ASSESSED]}",
            f"- ERROR: {status_counts[Status.ERROR]}",
            "",
            "## Findings",
            "",
        ]
    )

    for finding in report.sorted_findings():
        lines.extend(
            [
                f"### {finding.check_id} — {finding.title}",
                "",
                f"- **Category:** {finding.category.value}",
                f"- **Status:** {finding.status.value}",
                f"- **Severity:** {finding.severity.value}",
                "",
                "**Evidence:**",
                "",
            ]
        )

        if finding.evidence:
            lines.extend(f"- {item}" for item in finding.evidence)
        else:
            lines.append("- None")

        lines.extend(
            [
                "",
                f"**Expected state:** {finding.expected_state}",
                "",
                f"**Why it matters:** {finding.why_it_matters}",
                "",
                f"**Remediation:** {finding.remediation}",
                "",
            ]
        )

        if finding.reference:
            lines.extend(
                [
                    f"**Reference:** `{finding.reference}`",
                    "",
                ]
            )

        if finding.reason:
            lines.extend(
                [
                    f"**Reason:** {finding.reason}",
                    "",
                ]
            )

        lines.append("---")
        lines.append("")

    return "\n".join(lines)
