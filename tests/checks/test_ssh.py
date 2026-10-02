from types import SimpleNamespace

from hardening_auditor.checks.ssh import (
    SSHKeyPermissionsCheck,
    SSHPasswordAuthenticationCheck,
    SSHRootLoginCheck,
)
from hardening_auditor.models import Status
from hardening_auditor.system import FakeSystemInfo


def make_system(stdout="", returncode=0, stderr=""):
    system = FakeSystemInfo()

    def fake_run_command(args):
        if args == ["sshd", "-T"]:
            return SimpleNamespace(
                stdout=stdout,
                stderr=stderr,
                returncode=returncode,
            )

        raise AssertionError(f"Unexpected command: {args}")

    system.run_command = fake_run_command
    return system


def test_root_login_disabled():
    system = make_system(
        stdout="permitrootlogin no\npasswordauthentication no\n"
    )

    finding = SSHRootLoginCheck().run(system)

    assert finding.check_id == "SSH-01"
    assert finding.status == Status.PASS
    assert finding.severity.value == "INFO"
    assert finding.evidence == ["Effective PermitRootLogin: no"]


def test_root_login_prohibit_password_is_allowed():
    system = make_system(
        stdout="permitrootlogin prohibit-password\n"
    )

    finding = SSHRootLoginCheck().run(system)

    assert finding.status == Status.PASS


def test_root_login_enabled():
    system = make_system(
        stdout="permitrootlogin yes\n"
    )

    finding = SSHRootLoginCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "HIGH"
    assert finding.evidence == ["Effective PermitRootLogin: yes"]


def test_root_login_cannot_be_assessed_when_command_fails():
    system = make_system(
        returncode=1,
        stderr="sshd: command failed",
    )

    finding = SSHRootLoginCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason is not None


def test_root_login_cannot_be_assessed_when_setting_is_missing():
    system = make_system(
        stdout="passwordauthentication no\n"
    )

    finding = SSHRootLoginCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason == "PermitRootLogin was not found in sshd -T output."

def test_password_authentication_disabled():
    system = make_system(
        stdout="passwordauthentication no\n"
    )

    finding = SSHPasswordAuthenticationCheck().run(system)

    assert finding.check_id == "SSH-02"
    assert finding.status == Status.PASS
    assert finding.severity.value == "INFO"
    assert finding.evidence == [
        "Effective PasswordAuthentication: no"
    ]


def test_password_authentication_enabled():
    system = make_system(
        stdout="passwordauthentication yes\n"
    )

    finding = SSHPasswordAuthenticationCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "MEDIUM"
    assert finding.evidence == [
        "Effective PasswordAuthentication: yes"
    ]


def test_password_authentication_cannot_be_assessed_when_command_fails():
    system = make_system(
        returncode=1,
        stderr="sshd: command failed",
    )

    finding = SSHPasswordAuthenticationCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason is not None


def test_password_authentication_setting_missing():
    system = make_system(
        stdout="permitrootlogin no\n"
    )

    finding = SSHPasswordAuthenticationCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason == (
        "PasswordAuthentication was not found in sshd -T output."
    )

def test_ssh_directory_permissions_are_secure():
    system = FakeSystemInfo()
    system.add_stat(
        "/home/testuser/.ssh",
        mode=0o700,
        uid=1000,
        gid=1000,
    )

    finding = SSHKeyPermissionsCheck().run(system)

    assert finding.check_id == "SSH-03"
    assert finding.status == Status.PASS
    assert finding.evidence == [
        "/home/testuser/.ssh permissions: 0o700"
    ]


def test_ssh_directory_permissions_are_too_open():
    system = FakeSystemInfo()
    system.add_stat(
        "/home/testuser/.ssh",
        mode=0o755,
        uid=1000,
        gid=1000,
    )

    finding = SSHKeyPermissionsCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "MEDIUM"


def test_ssh_directory_missing():
    system = FakeSystemInfo()

    finding = SSHKeyPermissionsCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason is not None
