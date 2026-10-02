from hardening_auditor.checks.users import (
    EmptyPasswordAccountsCheck,
    ExtraUID0AccountsCheck,
    SudoRulesCheck,
)
from hardening_auditor.models import Status
from hardening_auditor.system import ErrorKind, FakeSystemInfo

def test_extra_uid0_accounts_pass():
    system = FakeSystemInfo()

    system.add_file(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "alice:x:1000:1000:Alice:/home/alice:/bin/bash\n",
    )

    finding = ExtraUID0AccountsCheck().run(system)

    assert finding.check_id == "USR-01"
    assert finding.status == Status.PASS


def test_extra_uid0_account_fails():
    system = FakeSystemInfo()

    system.add_file(
        "/etc/passwd",
        "root:x:0:0:root:/root:/bin/bash\n"
        "admin:x:0:0:Admin:/home/admin:/bin/bash\n",
    )

    finding = ExtraUID0AccountsCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "CRITICAL"
    assert "admin" in finding.evidence[0]

def test_extra_uid0_accounts_not_assessed_when_passwd_unavailable():
    system = FakeSystemInfo()

    system.add_file_error(
        "/etc/passwd",
        error=ErrorKind.PERMISSION_DENIED,
        detail="permission denied",
    )

    finding = ExtraUID0AccountsCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason is not None



def test_empty_password_accounts_pass():
    system = FakeSystemInfo()

    system.add_file(
        "/etc/shadow",
        "root:$6$hash:20000:0:99999:7:::\n"
        "alice:$6$hash:20000:0:99999:7:::\n",
    )

    finding = EmptyPasswordAccountsCheck().run(system)

    assert finding.check_id == "USR-02"
    assert finding.status == Status.PASS


def test_empty_password_account_fails():
    system = FakeSystemInfo()

    system.add_file(
        "/etc/shadow",
        "root:$6$hash:20000:0:99999:7:::\n"
        "alice::20000:0:99999:7:::\n",
    )

    finding = EmptyPasswordAccountsCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "CRITICAL"
    assert "alice" in finding.evidence[0]


def test_empty_password_accounts_not_assessed_when_shadow_unavailable():
    system = FakeSystemInfo()

    system.add_file_error(
        "/etc/shadow",
        error=ErrorKind.PERMISSION_DENIED,
        detail="permission denied",
    )

    finding = EmptyPasswordAccountsCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason is not None


def test_sudo_rules_pass():
    system = FakeSystemInfo()

    system.add_file(
        "/etc/sudoers",
        "root ALL=(ALL:ALL) ALL\n"
        "%sudo ALL=(ALL:ALL) ALL\n",
    )

    system.add_dir("/etc/sudoers.d", [])

    finding = SudoRulesCheck().run(system)

    assert finding.check_id == "USR-03"
    assert finding.status == Status.PASS


def test_sudo_nopasswd_all_fails():
    system = FakeSystemInfo()

    system.add_file(
        "/etc/sudoers",
        "root ALL=(ALL:ALL) ALL\n"
        "alice ALL=(ALL) NOPASSWD: ALL\n",
    )

    system.add_dir("/etc/sudoers.d", [])

    finding = SudoRulesCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "HIGH"


def test_sudo_broad_rule_warning():
    system = FakeSystemInfo()

    system.add_file(
        "/etc/sudoers",
        "alice ALL=(ALL) ALL\n",
    )

    system.add_dir("/etc/sudoers.d", [])

    finding = SudoRulesCheck().run(system)

    assert finding.status == Status.WARNING
    assert finding.severity.value == "MEDIUM"
