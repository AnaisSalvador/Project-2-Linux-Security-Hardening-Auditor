"""Network security checks."""

from hardening_auditor.checks.base import SecurityCheck
from hardening_auditor.models import Category, Finding, Severity, Status
from hardening_auditor.system import SystemInfo


class LegacyListenersCheck(SecurityCheck):
    """Check for insecure or legacy network listeners."""

    check_id = "NET-01"
    category = Category.NETWORK
    title = "Insecure legacy network listeners"

    LEGACY_PORTS = {
        "21": "FTP",
        "23": "Telnet",
        "69": "TFTP",
        "512": "rexec",
        "513": "rlogin",
        "514": "rsh",
    }

    def run(self, system: SystemInfo) -> Finding:
        result = system.run_command(["ss", "-tulnp"])

        expected_state = (
            "No insecure legacy services should be listening on "
            "ports 21, 23, 69, 512, 513, or 514."
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
                    "Legacy cleartext or insecure network services can "
                    "expose credentials and services to network attacks."
                ),
                remediation=(
                    "Disable unnecessary legacy services and replace them "
                    "with secure alternatives."
                ),
                reference="man:ss(8)",
                reason=(
                    "Could not inspect listening sockets: "
                    f"{result.stderr.strip() or 'ss command failed'}"
                ),
            )

        findings = self._find_legacy_listeners(result.stdout)

        if findings:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.HIGH,
                evidence=findings,
                expected_state=expected_state,
                why_it_matters=(
                    "Legacy network services may transmit data without "
                    "adequate encryption or authentication."
                ),
                remediation=(
                    "Disable the affected services or replace them with "
                    "secure alternatives such as SSH or SFTP."
                ),
                reference="man:ss(8)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=["No insecure legacy listeners detected."],
            expected_state=expected_state,
            why_it_matters=(
                "Avoiding legacy network services reduces exposure to "
                "cleartext and outdated protocols."
            ),
            remediation="No remediation required.",
            reference="man:ss(8)",
        )

    @classmethod
    def _find_legacy_listeners(cls, output: str) -> list[str]:
        """Return listening socket lines using legacy ports."""
        matches = []

        for line in output.splitlines():
            for port, service in cls.LEGACY_PORTS.items():
                if cls._line_uses_port(line, port):
                    matches.append(f"{service} (port {port}): {line.strip()}")
                    break

        return matches

    @staticmethod
    def _line_uses_port(line: str, port: str) -> bool:
        """Check whether an ss output line contains the given port."""
        return (
            f":{port} " in line
            or f":{port}\n" in line
            or f":{port}," in line
            or f":{port}]" in line
        )


class SensitiveExposureCheck(SecurityCheck):
    """Check whether sensitive services listen on all interfaces."""

    check_id = "NET-02"
    category = Category.NETWORK
    title = "Sensitive services exposed on all interfaces"

    SENSITIVE_PORTS = {
        "3306": "MySQL",
        "5432": "PostgreSQL",
        "6379": "Redis",
        "27017": "MongoDB",
        "11211": "Memcached",
        "5900": "VNC",
    }

    def run(self, system: SystemInfo) -> Finding:
        result = system.run_command(["ss", "-tulnp"])

        expected_state = (
            "Sensitive administrative or database services should not "
            "listen on all network interfaces unless explicitly required."
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
                    "Exposing sensitive services on every interface "
                    "increases the network attack surface."
                ),
                remediation=(
                    "Bind sensitive services to localhost or a specific "
                    "trusted interface when remote access is not required."
                ),
                reference="man:ss(8)",
                reason=(
                    "Could not inspect listening sockets: "
                    f"{result.stderr.strip() or 'ss command failed'}"
                ),
            )

        findings = self._find_exposed_services(result.stdout)

        if findings:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                evidence=findings,
                expected_state=expected_state,
                why_it_matters=(
                    "A service listening on all interfaces may be "
                    "reachable from networks that should not access it."
                ),
                remediation=(
                    "Restrict the service binding address to localhost "
                    "or the required trusted interface."
                ),
                reference="man:ss(8)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=["No sensitive services exposed on all interfaces."],
            expected_state=expected_state,
            why_it_matters=(
                "Restricting service exposure reduces unnecessary "
                "network attack surface."
            ),
            remediation="No remediation required.",
            reference="man:ss(8)",
        )

    @classmethod
    def _find_exposed_services(cls, output: str) -> list[str]:
        """Return sensitive services bound to all interfaces."""
        matches = []

        for line in output.splitlines():
            stripped = line.strip()

            for port, service in cls.SENSITIVE_PORTS.items():
                if cls._line_is_exposed(stripped, port):
                    matches.append(
                        f"{service} (port {port}) exposed: {stripped}"
                    )
                    break

        return matches

    @staticmethod
    def _line_is_exposed(line: str, port: str) -> bool:
        """Check whether a socket is bound to all IPv4/IPv6 interfaces."""
        addresses = (
            f"0.0.0.0:{port}",
            f"[::]:{port}",
            f":::{port}",
        )

        return any(address in line for address in addresses)


class HostFirewallCheck(SecurityCheck):
    """Check whether a host firewall appears to be active."""

    check_id = "NET-03"
    category = Category.NETWORK
    title = "Host firewall active"

    def run(self, system: SystemInfo) -> Finding:
        expected_state = (
            "At least one host firewall mechanism should be active "
            "and enforcing rules."
        )

        ufw = system.run_command(["ufw", "status"])

        if ufw.returncode == 0:
            if "status: active" in ufw.stdout.lower():
                return self._pass(
                    expected_state,
                    "UFW reports an active firewall.",
                )

        nft = system.run_command(["nft", "list", "ruleset"])

        if nft.returncode == 0 and nft.stdout.strip():
            return self._pass(
                expected_state,
                "nftables returned an active ruleset.",
            )

        iptables = system.run_command(["iptables", "-S"])

        if iptables.returncode == 0:
            rules = [
                line.strip()
                for line in iptables.stdout.splitlines()
                if line.strip()
            ]

            if rules:
                return self._pass(
                    expected_state,
                    "iptables returned firewall rules.",
                )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            evidence=["No active host firewall was detected."],
            expected_state=expected_state,
            why_it_matters=(
                "A host firewall can reduce exposure by controlling "
                "which network connections reach the system."
            ),
            remediation=(
                "Enable and configure an appropriate host firewall "
                "according to the system's role and network requirements."
            ),
            reference="man:ufw(8), man:nft(8), man:iptables(8)",
        )

    def _pass(self, expected_state: str, evidence: str) -> Finding:
        """Build a passing firewall finding."""
        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=[evidence],
            expected_state=expected_state,
            why_it_matters=(
                "A host firewall provides an additional network access "
                "control layer."
            ),
            remediation="No remediation required.",
            reference="man:ufw(8), man:nft(8), man:iptables(8)",
        )
