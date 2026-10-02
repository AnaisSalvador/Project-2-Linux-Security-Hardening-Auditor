"""Service security checks."""

from hardening_auditor.checks.base import SecurityCheck
from hardening_auditor.models import Category, Finding, Severity, Status
from hardening_auditor.system import SystemInfo


class LegacyServicesCheck(SecurityCheck):
    """Check for insecure legacy services."""

    check_id = "SVC-01"
    category = Category.SERVICE
    title = "Insecure legacy services"

    SERVICES = {
        "telnet": "Telnet",
        "rsh": "rsh",
        "rlogin": "rlogin",
        "vsftpd": "FTP server",
        "ftpd": "FTP server",
        "tftpd": "TFTP server",
        "xinetd": "xinetd",
        "ypserv": "NIS server",
    }

    def run(self, system: SystemInfo) -> Finding:
        expected_state = (
            "Insecure legacy services should not be active."
        )

        active = []
        installed = []

        for service, description in self.SERVICES.items():
            result = system.run_command(
                ["systemctl", "is-active", service]
            )

            if result.returncode == 0 and result.stdout.strip() == "active":
                active.append(f"{description} ({service})")

        if active:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.HIGH,
                evidence=[
                    f"Active legacy service: {service}"
                    for service in active
                ],
                expected_state=expected_state,
                why_it_matters=(
                    "Legacy services may use insecure protocols or expose "
                    "unnecessary network attack surfaces."
                ),
                remediation=(
                    "Stop and disable unnecessary legacy services, then "
                    "remove them when they are no longer required."
                ),
                reference="man:systemctl(1)",
            )

        for service, description in self.SERVICES.items():
            result = system.run_command(
                ["systemctl", "is-enabled", service]
            )

            if result.returncode == 0:
                installed.append(f"{description} ({service})")

        if installed:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.WARNING,
                severity=Severity.LOW,
                evidence=[
                    f"Legacy service is installed or enabled: {service}"
                    for service in installed
                ],
                expected_state=expected_state,
                why_it_matters=(
                    "Installed legacy services may become active later "
                    "or increase maintenance and attack surface."
                ),
                remediation=(
                    "Remove unnecessary legacy services or ensure they "
                    "remain disabled."
                ),
                reference="man:systemctl(1)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=["No monitored legacy services are active."],
            expected_state=expected_state,
            why_it_matters=(
                "Avoiding insecure legacy services reduces unnecessary "
                "attack surface."
            ),
            remediation="No remediation required.",
            reference="man:systemctl(1)",
        )


class SecurityUpdatesCheck(SecurityCheck):
    """Check for pending package updates."""

    check_id = "SVC-02"
    category = Category.SERVICE
    title = "Pending security updates"

    def run(self, system: SystemInfo) -> Finding:
        result = system.run_command(
            ["apt", "list", "--upgradable"]
        )

        expected_state = (
            "Security updates should be applied in accordance with "
            "the system's patch management process."
        )

        if result.returncode != 0:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "Unpatched software may contain known vulnerabilities "
                    "that attackers can exploit."
                ),
                remediation=(
                    "Review the package manager configuration and apply "
                    "available security updates according to policy."
                ),
                reference="man:apt(8)",
                reason=(
                    "Could not query available package updates: "
                    f"{result.stderr.strip() or 'apt command failed'}"
                ),
            )

        lines = [
            line.strip()
            for line in result.stdout.splitlines()
            if line.strip()
        ]

        packages = [
            line for line in lines
            if not line.lower().startswith("listing...")
        ]

        if packages:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                evidence=packages,
                expected_state=expected_state,
                why_it_matters=(
                    "Pending updates may leave known vulnerabilities "
                    "unpatched."
                ),
                remediation=(
                    "Review and install pending updates using the system's "
                    "normal patch management process."
                ),
                reference="man:apt(8)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=["No pending package updates reported by apt."],
            expected_state=expected_state,
            why_it_matters=(
                "Keeping software updated reduces exposure to known "
                "vulnerabilities."
            ),
            remediation="No remediation required.",
            reference="man:apt(8)",
        )


class LoggingServiceCheck(SecurityCheck):
    """Check whether a logging service is active."""

    check_id = "SVC-03"
    category = Category.SERVICE
    title = "System logging service"

    def run(self, system: SystemInfo) -> Finding:
        expected_state = (
            "At least one system logging service should be active, "
            "and persistent journaling should be configured when applicable."
        )

        rsyslog = system.run_command(
            ["systemctl", "is-active", "rsyslog"]
        )

        journald = system.run_command(
            ["systemctl", "is-active", "systemd-journald"]
        )

        if (
            rsyslog.returncode == 0
            and rsyslog.stdout.strip() == "active"
        ):
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.PASS,
                severity=Severity.INFO,
                evidence=["rsyslog service is active."],
                expected_state=expected_state,
                why_it_matters=(
                    "Centralized system logging supports detection, "
                    "investigation, and incident response."
                ),
                remediation="No remediation required.",
                reference="man:rsyslogd(8)",
            )

        if (
            journald.returncode == 0
            and journald.stdout.strip() == "active"
        ):
            persistent = system.stat_path("/var/log/journal")

            if persistent.ok and persistent.is_dir:
                return Finding(
                    check_id=self.check_id,
                    category=self.category,
                    title=self.title,
                    status=Status.PASS,
                    severity=Severity.INFO,
                    evidence=[
                        "systemd-journald service is active.",
                        "Persistent journal directory exists.",
                    ],
                    expected_state=expected_state,
                    why_it_matters=(
                        "Persistent system logs support detection and "
                        "post-incident investigation."
                    ),
                    remediation="No remediation required.",
                    reference="man:systemd-journald.service(8)",
                )

            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.WARNING,
                severity=Severity.LOW,
                evidence=[
                    "systemd-journald service is active.",
                    "Persistent journal directory was not detected.",
                ],
                expected_state=expected_state,
                why_it_matters=(
                    "Non-persistent logs may be lost after a reboot, "
                    "reducing forensic visibility."
                ),
                remediation=(
                    "Configure persistent journaling when required by "
                    "the system's logging and retention requirements."
                ),
                reference="man:systemd-journald.service(8)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            evidence=["No monitored logging service is active."],
            expected_state=expected_state,
            why_it_matters=(
                "Without active system logging, security events may not "
                "be available for detection or investigation."
            ),
            remediation=(
                "Enable an appropriate system logging service and verify "
                "that logs are being retained according to policy."
            ),
            reference="man:systemd-journald.service(8)",
        )
