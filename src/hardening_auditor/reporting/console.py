"""Console report renderer."""

from hardening_auditor.models import Report, Status


def render_console(report: Report) -> str:
    """Render a concise human-readable report."""
    status_counts = report.counts_by_status()

    lines = [
        "Linux Security Hardening Auditor",
        "=" * 36,
        f"Hostname: {report.hostname}",
        f"OS: {report.os_description}",
        f"Root: {report.is_root}",
        "",
        "Summary",
        "-------",
        f"PASS:         {status_counts[Status.PASS]}",
        f"FAIL:         {status_counts[Status.FAIL]}",
        f"WARNING:      {status_counts[Status.WARNING]}",
        f"NOT_ASSESSED: {status_counts[Status.NOT_ASSESSED]}",
        f"ERROR:        {status_counts[Status.ERROR]}",
        "",
        "Findings",
        "--------",
    ]

    for finding in report.sorted_findings():
        lines.append(
            f"[{finding.status.value}] "
            f"{finding.check_id} "
            f"{finding.title} "
            f"(severity: {finding.severity.value})"
        )

        for evidence in finding.evidence:
            lines.append(f"  - {evidence}")

        if finding.reason:
            lines.append(f"  Reason: {finding.reason}")

    return "\n".join(lines)
