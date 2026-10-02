"""SSH security checks."""

from hardening_auditor.checks.base import SecurityCheck
from hardening_auditor.models import Category, Finding, Severity, Status
from hardening_auditor.system import SystemInfo


class SSHRootLoginCheck(SecurityCheck):
    """Check whether SSH permits direct root login."""

    check_id = "SSH-01"
    category = Category.SSH
    title = "SSH root login"

    def run(self, system: SystemInfo) -> Finding:
        result = system.run_command(["sshd", "-T"])

        expected_state = (
            "Effective PermitRootLogin should be 'no' "
            "or 'prohibit-password'."
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
                    "Direct root SSH access can increase the impact of "
                    "credential compromise and reduces accountability."
                ),
                remediation=(
                    "Review the SSH server configuration and set "
                    "PermitRootLogin to 'no' or 'prohibit-password'."
                ),
                reference="man:sshd_config(5)",
                reason=(
                    "Could not obtain effective SSH configuration: "
                    f"{result.stderr.strip() or 'sshd -T failed'}"
                ),
            )

        value = self._parse_setting(result.stdout, "permitrootlogin")

        if value is None:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "Direct root SSH access can increase the impact of "
                    "credential compromise and reduces accountability."
                ),
                remediation=(
                    "Review the effective SSH configuration and verify "
                    "PermitRootLogin explicitly."
                ),
                reference="man:sshd_config(5)",
                reason="PermitRootLogin was not found in sshd -T output.",
            )

        evidence = [f"Effective PermitRootLogin: {value}"]

        if value in {"no", "prohibit-password"}:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.PASS,
                severity=Severity.INFO,
                evidence=evidence,
                expected_state=expected_state,
                why_it_matters=(
                    "Restricting direct root SSH access reduces the risk "
                    "associated with compromised root credentials."
                ),
                remediation=(
                    "No remediation required. Continue reviewing other "
                    "SSH authentication controls."
                ),
                reference="man:sshd_config(5)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.FAIL,
            severity=Severity.HIGH,
            evidence=evidence,
            expected_state=expected_state,
            why_it_matters=(
                "Allowing direct root SSH login exposes the highest-"
                "privileged account to remote authentication attempts."
            ),
            remediation=(
                "Set PermitRootLogin to 'no' or 'prohibit-password' "
                "according to the system's operational requirements."
            ),
            reference="man:sshd_config(5)",
        )

    @staticmethod
    def _parse_setting(output: str, setting: str) -> str | None:
        """Extract a setting from sshd -T output."""
        for line in output.splitlines():
            parts = line.split(maxsplit=1)

            if len(parts) == 2 and parts[0].lower() == setting.lower():
                return parts[1].strip().lower()

        return None


class SSHPasswordAuthenticationCheck(SecurityCheck):
    """Check whether SSH password authentication is enabled."""

    check_id = "SSH-02"
    category = Category.SSH
    title = "SSH password authentication"

    def run(self, system: SystemInfo) -> Finding:
        result = system.run_command(["sshd", "-T"])

        expected_state = (
            "Effective PasswordAuthentication should be 'no'."
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
                    "Password-based SSH authentication can increase exposure "
                    "to password guessing and credential attacks."
                ),
                remediation=(
                    "Review SSH authentication requirements and set "
                    "PasswordAuthentication to 'no' when key-based "
                    "authentication is appropriate."
                ),
                reference="man:sshd_config(5)",
                reason=(
                    "Could not obtain effective SSH configuration: "
                    f"{result.stderr.strip() or 'sshd -T failed'}"
                ),
            )

        value = SSHRootLoginCheck._parse_setting(
            result.stdout,
            "passwordauthentication",
        )

        if value is None:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "Password-based SSH authentication can increase exposure "
                    "to password guessing and credential attacks."
                ),
                remediation=(
                    "Review the effective SSH configuration and verify "
                    "PasswordAuthentication explicitly."
                ),
                reference="man:sshd_config(5)",
                reason=(
                    "PasswordAuthentication was not found in sshd -T output."
                ),
            )

        evidence = [f"Effective PasswordAuthentication: {value}"]

        if value == "no":
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.PASS,
                severity=Severity.INFO,
                evidence=evidence,
                expected_state=expected_state,
                why_it_matters=(
                    "Disabling password authentication can reduce exposure "
                    "to password guessing and credential attacks."
                ),
                remediation="No remediation required.",
                reference="man:sshd_config(5)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.FAIL,
            severity=Severity.MEDIUM,
            evidence=evidence,
            expected_state=expected_state,
            why_it_matters=(
                "Password authentication increases exposure to password "
                "guessing and credential attacks."
            ),
            remediation=(
                "Set PasswordAuthentication to 'no' after confirming "
                "that the required key-based authentication works."
            ),
            reference="man:sshd_config(5)",
        )

class SSHKeyPermissionsCheck(SecurityCheck):
    """Check permissions of the current user's SSH directory and keys."""

    check_id = "SSH-03"
    category = Category.SSH
    title = "SSH key permissions"

    def run(self, system: SystemInfo) -> Finding:
        home = system.home_directory()

        if home is None:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=(
                    "The user's .ssh directory should be 700, "
                    "authorized_keys should be 600, and private keys "
                    "should not be readable by other users."
                ),
                why_it_matters=(
                    "Weak SSH file permissions can expose private keys "
                    "or authorized key configuration to other users."
                ),
                remediation=(
                    "Review the user's SSH directory and key permissions "
                    "and restrict access to the account owner."
                ),
                reference="man:ssh(1)",
                reason="Could not determine the current user's home directory.",
            )

        ssh_dir = f"{home}/.ssh"
        ssh_stat = system.stat_path(ssh_dir)

        if ssh_stat is None:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=(
                    "The user's .ssh directory should be 700, "
                    "authorized_keys should be 600, and private keys "
                    "should not be readable by other users."
                ),
                why_it_matters=(
                    "Weak SSH file permissions can expose private keys "
                    "or authorized key configuration to other users."
                ),
                remediation=(
                    "Create or review the user's .ssh directory if SSH "
                    "key authentication is required."
                ),
                reference="man:ssh(1)",
                reason=f"SSH directory was not found: {ssh_dir}",
            )

        mode = ssh_stat.mode & 0o777
        evidence = [f"{ssh_dir} permissions: {oct(mode)}"]

        if mode & 0o077:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                evidence=evidence,
                expected_state=(
                    "The user's .ssh directory should be accessible "
                    "only by the account owner (700 or stricter)."
                ),
                why_it_matters=(
                    "Other users with access to the SSH directory may "
                    "read or manipulate SSH configuration and keys."
                ),
                remediation=(
                    f"Restrict permissions on {ssh_dir} to 700 or stricter."
                ),
                reference="man:ssh(1)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=evidence,
            expected_state=(
                "The user's .ssh directory should be accessible "
                "only by the account owner (700 or stricter)."
            ),
            why_it_matters=(
                "Restricting the SSH directory prevents other users "
                "from accessing SSH configuration and key material."
            ),
            remediation="No remediation required.",
            reference="man:ssh(1)",
        )


class SSHKeyPermissionsCheck(SecurityCheck):
    """Check permissions of the current user's SSH directory."""

    check_id = "SSH-03"
    category = Category.SSH
    title = "SSH key permissions"

    def run(self, system: SystemInfo) -> Finding:
        home = system.home_directory()
        ssh_dir = f"{home}/.ssh"
        result = system.stat_path(ssh_dir)

        expected_state = (
            "The user's .ssh directory should be 700 or stricter."
        )

        if result.error is not None:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "Weak SSH directory permissions can expose SSH "
                    "configuration and key material to other users."
                ),
                remediation=(
                    "Restrict the user's .ssh directory to owner-only "
                    "access, normally mode 700."
                ),
                reference="man:ssh(1)",
                reason=f"Could not inspect {ssh_dir}: {result.error.value}",
            )

        mode = result.mode & 0o777
        evidence = [f"{ssh_dir} permissions: {oct(mode)}"]

        if mode & 0o077:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.MEDIUM,
                evidence=evidence,
                expected_state=expected_state,
                why_it_matters=(
                    "Other users may be able to access SSH configuration "
                    "or key material."
                ),
                remediation=(
                    f"Restrict permissions on {ssh_dir} to 700 or stricter."
                ),
                reference="man:ssh(1)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=evidence,
            expected_state=expected_state,
            why_it_matters=(
                "Owner-only SSH directory permissions reduce exposure "
                "of SSH configuration and key material."
            ),
            remediation="No remediation required.",
            reference="man:ssh(1)",
        )
