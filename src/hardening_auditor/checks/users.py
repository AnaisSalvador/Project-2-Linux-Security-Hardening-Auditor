"""User and privilege security checks."""

from hardening_auditor.checks.base import SecurityCheck
from hardening_auditor.models import Category, Finding, Severity, Status
from hardening_auditor.system import SystemInfo


class ExtraUID0AccountsCheck(SecurityCheck):
    """Check for accounts other than root with UID 0."""

    check_id = "USR-01"
    category = Category.USER
    title = "Extra UID 0 accounts"

    def run(self, system: SystemInfo) -> Finding:
        result = system.read_file("/etc/passwd")

        expected_state = "Only the root account should have UID 0."

        if not result.ok:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "Additional UID 0 accounts have root-level privileges "
                    "and can bypass normal privilege separation."
                ),
                remediation=(
                    "Review all UID 0 accounts and remove or disable "
                    "unexpected privileged accounts."
                ),
                reference="man:passwd(5)",
                reason=(
                    "Could not read /etc/passwd: "
                    f"{result.error.value}"
                ),
            )

        extra_accounts = []

        for line in result.text.splitlines():
            if not line or line.startswith("#"):
                continue

            fields = line.split(":")

            if len(fields) >= 3 and fields[2] == "0" and fields[0] != "root":
                extra_accounts.append(fields[0])

        if extra_accounts:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                evidence=[
                    f"Unexpected UID 0 account: {username}"
                    for username in extra_accounts
                ],
                expected_state=expected_state,
                why_it_matters=(
                    "An unexpected UID 0 account has full root-level "
                    "privileges."
                ),
                remediation=(
                    "Investigate each UID 0 account and remove or disable "
                    "any account that is not intentionally required."
                ),
                reference="man:passwd(5)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=["Only root has UID 0."],
            expected_state=expected_state,
            why_it_matters=(
                "Restricting UID 0 to the intended root account preserves "
                "privilege separation and accountability."
            ),
            remediation="No remediation required.",
            reference="man:passwd(5)",
        )


class EmptyPasswordAccountsCheck(SecurityCheck):
    """Check for accounts with empty password hashes."""

    check_id = "USR-02"
    category = Category.USER
    title = "Accounts with empty passwords"

    def run(self, system: SystemInfo) -> Finding:
        result = system.read_file("/etc/shadow")

        expected_state = (
            "No login-capable account should have an empty password hash."
        )

        if not result.ok:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "An empty password can allow authentication without "
                    "a password when the account is otherwise usable."
                ),
                remediation=(
                    "Restrict access to /etc/shadow and assign a secure "
                    "authentication method to affected accounts."
                ),
                reference="man:shadow(5)",
                reason=(
                    "Could not read /etc/shadow: "
                    f"{result.error.value}"
                ),
            )

        empty_accounts = []

        for line in result.text.splitlines():
            if not line or line.startswith("#"):
                continue

            fields = line.split(":")

            if len(fields) >= 2 and fields[1] == "":
                empty_accounts.append(fields[0])

        if empty_accounts:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                evidence=[
                    f"Empty password hash for account: {username}"
                    for username in empty_accounts
                ],
                expected_state=expected_state,
                why_it_matters=(
                    "Accounts with empty password fields may be "
                    "authenticatable without a password."
                ),
                remediation=(
                    "Set a secure authentication method or disable "
                    "affected accounts after verifying their purpose."
                ),
                reference="man:shadow(5)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=["No empty password hashes found."],
            expected_state=expected_state,
            why_it_matters=(
                "Avoiding empty password hashes reduces the risk of "
                "unauthenticated account access."
            ),
            remediation="No remediation required.",
            reference="man:shadow(5)",
        )


class SudoRulesCheck(SecurityCheck):
    """Check for overly permissive sudo rules."""

    check_id = "USR-03"
    category = Category.USER
    title = "Overly permissive sudo rules"

    def run(self, system: SystemInfo) -> Finding:
        result = system.read_file("/etc/sudoers")

        expected_state = (
            "Sudo rules should avoid unrestricted NOPASSWD: ALL grants "
            "and unnecessarily broad ALL privileges."
        )

        if not result.ok:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "Overly broad sudo permissions can allow privilege "
                    "escalation or bypass intended access controls."
                ),
                remediation=(
                    "Review sudoers configuration and restrict commands "
                    "and privileges to what each account requires."
                ),
                reference="man:sudoers(5)",
                reason=(
                    "Could not read /etc/sudoers: "
                    f"{result.error.value}"
                ),
            )

        files = [("/etc/sudoers", result.text)]

        directory_result = system.list_dir("/etc/sudoers.d")

        if directory_result.ok:
            for filename in directory_result.entries:
                if filename.startswith("."):
                    continue

                path = f"/etc/sudoers.d/{filename}"
                file_result = system.read_file(path)

                if file_result.ok:
                    files.append((path, file_result.text))

        nopasswd_rules = []
        broad_user_rules = []

        for path, text in files:
            for line in text.splitlines():
                stripped = line.strip()

                if not stripped or stripped.startswith("#"):
                    continue

                if "NOPASSWD:" in stripped and "ALL" in stripped:
                    nopasswd_rules.append(f"{path}: {stripped}")
                    continue

                parts = stripped.split()

                if not parts:
                    continue

                subject = parts[0]

                if subject == "root" or subject.startswith("%"):
                   continue

                if (
                    "ALL=(ALL)" in stripped
                    or "ALL=(ALL:ALL)" in stripped
                    or "ALL = (ALL)" in stripped
                    or "ALL = (ALL:ALL)" in stripped
                ):
                    broad_user_rules.append(f"{path}: {stripped}")

        if nopasswd_rules:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.HIGH,
                evidence=nopasswd_rules,
                expected_state=expected_state,
                why_it_matters=(
                    "NOPASSWD: ALL can grant unrestricted administrative "
                    "access without requiring password authentication."
                ),
                remediation=(
                    "Replace unrestricted NOPASSWD: ALL rules with the "
                    "smallest set of required commands and privileges."
                ),
                reference="man:sudoers(5)",
            )

        if broad_user_rules:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                evidence=broad_user_rules,
                expected_state=expected_state,
                why_it_matters=(
                    "Broad sudo privileges increase the impact of a "
                    "compromised account."
                ),
                remediation=(
                    "Review broad sudo grants and apply least privilege "
                    "where operationally possible."
                ),
                reference="man:sudoers(5)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=["No obviously broad sudo rules detected."],
            expected_state=expected_state,
            why_it_matters=(
                "Restricting sudo privileges reduces the impact of "
                "compromised user accounts."
            ),
            remediation="No remediation required.",
            reference="man:sudoers(5)",
        )
