"""Sensitive file permission checks."""

from hardening_auditor.checks.base import SecurityCheck
from hardening_auditor.models import Category, Finding, Severity, Status
from hardening_auditor.system import FindPredicate, SystemInfo


class SensitiveFilePermissionsCheck(SecurityCheck):
    """Check permissions of /etc/shadow and /etc/passwd."""

    check_id = "FIL-01"
    category = Category.FILES
    title = "Sensitive account file permissions"

    def run(self, system: SystemInfo) -> Finding:
        expected_state = (
            "/etc/shadow should not be writable or readable by other users, "
            "and /etc/passwd should not be writable by other users."
        )

        shadow = system.stat_path("/etc/shadow")
        passwd = system.stat_path("/etc/passwd")

        if not shadow.ok or not passwd.ok:
            missing = []

            if not shadow.ok:
                missing.append("/etc/shadow")
            if not passwd.ok:
                missing.append("/etc/passwd")

            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.NOT_ASSESSED,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "These files contain account and authentication "
                    "information and require restrictive permissions."
                ),
                remediation=(
                    "Verify that the account files exist and are owned "
                    "by the expected privileged users."
                ),
                reference="man:passwd(5), man:shadow(5)",
                reason=(
                    "Could not inspect: "
                    + ", ".join(missing)
                ),
            )

        evidence = [
            f"/etc/shadow permissions: {oct(shadow.mode & 0o777)}",
            f"/etc/passwd permissions: {oct(passwd.mode & 0o777)}",
        ]

        shadow_mode = shadow.mode & 0o777
        passwd_mode = passwd.mode & 0o777

        shadow_world_accessible = shadow_mode & 0o007
        shadow_group_writable = shadow_mode & 0o020
        passwd_writable = passwd_mode & 0o022

        if shadow_world_accessible or shadow_group_writable:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                evidence=evidence,
                expected_state=expected_state,
                why_it_matters=(
                    "Weak /etc/shadow permissions can expose password "
                    "hashes or allow unauthorized modification."
                ),
                remediation=(
                    "Restrict /etc/shadow permissions so that only "
                    "authorized privileged users can access it."
                ),
                reference="man:shadow(5)",
            )

        if passwd_writable:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.CRITICAL,
                evidence=evidence,
                expected_state=expected_state,
                why_it_matters=(
                    "Unauthorized modification of /etc/passwd can alter "
                    "account information and enable privilege abuse."
                ),
                remediation=(
                    "Remove unauthorized write permissions from "
                    "/etc/passwd and keep it owned by root."
                ),
                reference="man:passwd(5)",
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
                "Restrictive permissions protect account and "
                "authentication information."
            ),
            remediation="No remediation required.",
            reference="man:passwd(5), man:shadow(5)",
        )


class SuspiciousSUIDCheck(SecurityCheck):
    """Check SUID and SGID binaries against a small baseline."""

    check_id = "FIL-02"
    category = Category.FILES
    title = "Unexpected SUID or SGID binaries"

    BASELINE = {
        "/usr/bin/passwd",
        "/usr/bin/su",
        "/usr/bin/sudo",
        "/usr/bin/chsh",
        "/usr/bin/chfn",
        "/usr/bin/mount",
        "/usr/bin/umount",
        "/usr/bin/newgrp",
        "/usr/bin/gpasswd",
    }

    DANGEROUS_NAMES = {
        "bash",
        "sh",
        "dash",
        "zsh",
        "python",
        "python3",
        "perl",
        "ruby",
        "vim",
        "nvim",
        "nano",
    }

    SEARCH_PATHS = (
        "/usr/bin",
        "/usr/sbin",
        "/bin",
        "/sbin",
    )

    def run(self, system: SystemInfo) -> Finding:
        expected_state = (
            "SUID/SGID binaries should be limited to expected system "
            "binaries and documented exceptions."
        )

        try:
            result = system.find_files(
                self.SEARCH_PATHS,
                predicate=FindPredicate.SUID_SGID,
            )
            paths = result.paths
        except Exception as exc:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.ERROR,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "SUID and SGID binaries can execute with elevated "
                    "privileges and therefore require careful monitoring."
                ),
                remediation=(
                    "Review the scanner error and verify SUID/SGID files "
                    "manually before relying on the result."
                ),
                reference="man:find(1)",
                reason=f"{type(exc).__name__}: {exc}",
            )

        unexpected = []
        dangerous = []

        for path in sorted(paths):
            if path in self.BASELINE:
                continue

            unexpected.append(path)

            if path.rsplit("/", 1)[-1] in self.DANGEROUS_NAMES:
                dangerous.append(path)

        if dangerous:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.HIGH,
                evidence=dangerous,
                expected_state=expected_state,
                why_it_matters=(
                    "SUID or SGID on shells, interpreters, or editors "
                    "can provide a path to unintended privileged execution."
                ),
                remediation=(
                    "Investigate the affected binary, remove unnecessary "
                    "SUID/SGID bits, and verify package integrity."
                ),
                reference="man:find(1)",
            )

        if unexpected:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.WARNING,
                severity=Severity.MEDIUM,
                evidence=unexpected,
                expected_state=expected_state,
                why_it_matters=(
                    "Unexpected SUID/SGID binaries increase the number "
                    "of privileged execution paths."
                ),
                remediation=(
                    "Review each unexpected SUID/SGID binary and determine "
                    "whether the privilege bit is required."
                ),
                reference="man:find(1)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=["No unexpected SUID/SGID binaries detected."],
            expected_state=expected_state,
            why_it_matters=(
                "Limiting privileged file permissions reduces "
                "unnecessary privilege escalation paths."
            ),
            remediation="No remediation required.",
            reference="man:find(1)",
        )


class WorldWritableSystemFilesCheck(SecurityCheck):
    """Check system paths for world-writable regular files."""

    check_id = "FIL-03"
    category = Category.FILES
    title = "World-writable system files"

    SEARCH_PATHS = (
        "/etc",
        "/bin",
        "/sbin",
        "/usr/bin",
        "/usr/sbin",
    )

    def run(self, system: SystemInfo) -> Finding:
        expected_state = (
            "System files in protected paths should not be writable "
            "by all users."
        )

        try:
            result = system.find_files(
                self.SEARCH_PATHS,
                predicate=FindPredicate.WORLD_WRITABLE,
            )
            paths = result.paths
        except Exception as exc:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.ERROR,
                severity=Severity.INFO,
                evidence=[],
                expected_state=expected_state,
                why_it_matters=(
                    "World-writable system files may allow unauthorized "
                    "modification of executable or configuration content."
                ),
                remediation=(
                    "Review the scanner error and manually verify "
                    "permissions before relying on the result."
                ),
                reference="man:find(1)",
                reason=f"{type(exc).__name__}: {exc}",
            )

        if paths:
            return Finding(
                check_id=self.check_id,
                category=self.category,
                title=self.title,
                status=Status.FAIL,
                severity=Severity.HIGH,
                evidence=sorted(paths),
                expected_state=expected_state,
                why_it_matters=(
                    "World-writable system files can be modified by "
                    "unprivileged users and may enable tampering."
                ),
                remediation=(
                    "Investigate each file and remove unnecessary "
                    "world-write permissions."
                ),
                reference="man:find(1)",
            )

        return Finding(
            check_id=self.check_id,
            category=self.category,
            title=self.title,
            status=Status.PASS,
            severity=Severity.INFO,
            evidence=["No world-writable files detected in system paths."],
            expected_state=expected_state,
            why_it_matters=(
                "Restrictive permissions reduce the risk of unauthorized "
                "modification of system files."
            ),
            remediation="No remediation required.",
            reference="man:find(1)",
        )
