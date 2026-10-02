from hardening_auditor.checks.files import (    
    SensitiveFilePermissionsCheck,
    SuspiciousSUIDCheck,
    WorldWritableSystemFilesCheck,
)
from hardening_auditor.models import Status
from hardening_auditor.system import FakeSystemInfo


def test_sensitive_file_permissions_pass():
    system = FakeSystemInfo()

    system.add_stat(
        "/etc/shadow",
        mode=0o640,
        uid=0,
        gid=42,
    )

    system.add_stat(
        "/etc/passwd",
        mode=0o644,
        uid=0,
        gid=0,
    )

    finding = SensitiveFilePermissionsCheck().run(system)

    assert finding.check_id == "FIL-01"
    assert finding.status == Status.PASS


def test_shadow_world_readable_fails():
    system = FakeSystemInfo()

    system.add_stat(
        "/etc/shadow",
        mode=0o644,
        uid=0,
        gid=42,
    )

    system.add_stat(
        "/etc/passwd",
        mode=0o644,
        uid=0,
        gid=0,
    )

    finding = SensitiveFilePermissionsCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "CRITICAL"


def test_passwd_world_writable_fails():
    system = FakeSystemInfo()

    system.add_stat(
        "/etc/shadow",
        mode=0o640,
        uid=0,
        gid=42,
    )

    system.add_stat(
        "/etc/passwd",
        mode=0o666,
        uid=0,
        gid=0,
    )

    finding = SensitiveFilePermissionsCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "CRITICAL"


def test_sensitive_files_not_assessed_when_missing():
    system = FakeSystemInfo()

    finding = SensitiveFilePermissionsCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason is not None


def test_suid_baseline_pass():
    system = FakeSystemInfo()

    system.add_find_files_result(
        [
            "/usr/bin/passwd",
            "/usr/bin/sudo",
        ]
    )

    finding = SuspiciousSUIDCheck().run(system)

    assert finding.check_id == "FIL-02"
    assert finding.status == Status.PASS


def test_unexpected_suid_binary_warning():
    system = FakeSystemInfo()

    system.add_find_files_result(
        [
            "/usr/bin/passwd",
            "/usr/bin/custom-tool",
        ]
    )

    finding = SuspiciousSUIDCheck().run(system)

    assert finding.status == Status.WARNING
    assert finding.severity.value == "MEDIUM"
    assert "/usr/bin/custom-tool" in finding.evidence


def test_suid_shell_fails():
    system = FakeSystemInfo()

    system.add_find_files_result(
        [
            "/usr/bin/bash",
        ]
    )

    finding = SuspiciousSUIDCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "HIGH"


def test_world_writable_system_files_pass():
    system = FakeSystemInfo()

    system.add_find_files_result([])

    finding = WorldWritableSystemFilesCheck().run(system)

    assert finding.check_id == "FIL-03"
    assert finding.status == Status.PASS


def test_world_writable_system_file_fails():
    system = FakeSystemInfo()

    system.add_find_files_result(
        [
            "/etc/example.conf",
        ]
    )

    finding = WorldWritableSystemFilesCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "HIGH"
    assert "/etc/example.conf" in finding.evidence
