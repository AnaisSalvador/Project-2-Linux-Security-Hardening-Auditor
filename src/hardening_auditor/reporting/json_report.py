"""JSON report renderer."""

import json

from hardening_auditor.models import Report


def render_json(report: Report) -> str:
    """Render a Report as formatted JSON."""
    return json.dumps(
        report.to_dict(),
        indent=2,
        ensure_ascii=False,
    )
