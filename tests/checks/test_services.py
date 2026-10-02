from hardening_auditor.checks.services import (
    LegacyServicesCheck,
    LoggingServiceCheck,
    SecurityUpdatesCheck,
)
from hardening_auditor.models import Status
from hardening_auditor.system import FakeSystemInfo


def test_legacy_services_pass():
    system = FakeSystemInfo()

    for service in LegacyServicesCheck.SERVICES:
        system.add_command(
            ["systemctl", "is-active", service],
            returncode=3,
            stdout="inactive\n",
            stderr="",
        )

        system.add_command(
            ["systemctl", "is-enabled", service],
            returncode=1,
            stdout="disabled\n",
            stderr="",
        )

    finding = LegacyServicesCheck().run(system)

    assert finding.check_id == "SVC-01"
    assert finding.status == Status.PASS


def test_active_legacy_service_fails():
    system = FakeSystemInfo()

    for service in LegacyServicesCheck.SERVICES:
        output = "active\n" if service == "telnet" else "inactive\n"

        system.add_command(
            ["systemctl", "is-active", service],
            returncode=0 if service == "telnet" else 3,
            stdout=output,
            stderr="",
        )

    finding = LegacyServicesCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "HIGH"
    assert "Telnet" in finding.evidence[0]


def test_installed_legacy_service_warning():
    system = FakeSystemInfo()

    for service in LegacyServicesCheck.SERVICES:
        system.add_command(
            ["systemctl", "is-active", service],
            returncode=3,
            stdout="inactive\n",
            stderr="",
        )

        enabled = service == "telnet"

        system.add_command(
            ["systemctl", "is-enabled", service],
            returncode=0 if enabled else 1,
            stdout="enabled\n" if enabled else "disabled\n",
            stderr="",
        )

    finding = LegacyServicesCheck().run(system)

    assert finding.status == Status.WARNING
    assert finding.severity.value == "LOW"


def test_security_updates_pass():
    system = FakeSystemInfo()

    system.add_command(
        ["apt", "list", "--upgradable"],
        returncode=0,
        stdout="Listing...\n",
        stderr="",
    )

    finding = SecurityUpdatesCheck().run(system)

    assert finding.check_id == "SVC-02"
    assert finding.status == Status.PASS


def test_security_updates_warning():
    system = FakeSystemInfo()

    system.add_command(
        ["apt", "list", "--upgradable"],
        returncode=0,
        stdout=(
            "Listing...\n"
            "openssl/stable-security 3.0.1 amd64 [upgradable from: 3.0.0]\n"
        ),
        stderr="",
    )

    finding = SecurityUpdatesCheck().run(system)

    assert finding.status == Status.WARNING
    assert finding.severity.value == "MEDIUM"


def test_security_updates_not_assessed_when_apt_fails():
    system = FakeSystemInfo()

    system.add_command(
        ["apt", "list", "--upgradable"],
        returncode=1,
        stdout="",
        stderr="apt failed",
    )

    finding = SecurityUpdatesCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason is not None


def test_logging_rsyslog_active():
    system = FakeSystemInfo()

    system.add_command(
        ["systemctl", "is-active", "rsyslog"],
        returncode=0,
        stdout="active\n",
        stderr="",
    )

    system.add_command(
        ["systemctl", "is-active", "systemd-journald"],
        returncode=0,
        stdout="active\n",
        stderr="",
    )

    finding = LoggingServiceCheck().run(system)

    assert finding.check_id == "SVC-03"
    assert finding.status == Status.PASS


def test_logging_journald_persistent():
    system = FakeSystemInfo()

    system.add_command(
        ["systemctl", "is-active", "rsyslog"],
        returncode=3,
        stdout="inactive\n",
        stderr="",
    )

    system.add_command(
        ["systemctl", "is-active", "systemd-journald"],
        returncode=0,
        stdout="active\n",
        stderr="",
    )

    system.add_stat(
        "/var/log/journal",
        mode=0o2755,
        uid=0,
        gid=0,
        is_dir=True,
    )

    finding = LoggingServiceCheck().run(system)

    assert finding.status == Status.PASS


def test_logging_journald_not_persistent():
    system = FakeSystemInfo()

    system.add_command(
        ["systemctl", "is-active", "rsyslog"],
        returncode=3,
        stdout="inactive\n",
        stderr="",
    )

    system.add_command(
        ["systemctl", "is-active", "systemd-journald"],
        returncode=0,
        stdout="active\n",
        stderr="",
    )

    finding = LoggingServiceCheck().run(system)

    assert finding.status == Status.WARNING
    assert finding.severity.value == "LOW"


def test_logging_service_missing_fails():
    system = FakeSystemInfo()

    system.add_command(
        ["systemctl", "is-active", "rsyslog"],
        returncode=3,
        stdout="inactive\n",
        stderr="",
    )

    system.add_command(
        ["systemctl", "is-active", "systemd-journald"],
        returncode=3,
        stdout="inactive\n",
        stderr="",
    )

    finding = LoggingServiceCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "MEDIUM"
