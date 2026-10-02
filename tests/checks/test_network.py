from hardening_auditor.checks.network import (
    HostFirewallCheck,
    LegacyListenersCheck,
    SensitiveExposureCheck,
)
from hardening_auditor.models import Status
from hardening_auditor.system import FakeSystemInfo


SS_CLEAN = """\
Netid State  Local Address:Port  Peer Address:Port
tcp   LISTEN 127.0.0.1:22      0.0.0.0:*
tcp   LISTEN 127.0.0.1:5432    0.0.0.0:*
"""


SS_LEGACY = """\
Netid State  Local Address:Port  Peer Address:Port
tcp   LISTEN 0.0.0.0:23        0.0.0.0:*
tcp   LISTEN 0.0.0.0:22        0.0.0.0:*
"""


SS_EXPOSED = """\
Netid State  Local Address:Port  Peer Address:Port
tcp   LISTEN 0.0.0.0:3306      0.0.0.0:*
tcp   LISTEN 127.0.0.1:5432    0.0.0.0:*
"""


def fake_ss(system: FakeSystemInfo, output: str):
    """Make FakeSystemInfo return controlled ss output."""
    system.add_command(
        ["ss", "-tulnp"],
        returncode=0,
        stdout=output,
        stderr="",
    )


def test_legacy_listeners_pass():
    system = FakeSystemInfo()
    fake_ss(system, SS_CLEAN)

    finding = LegacyListenersCheck().run(system)

    assert finding.check_id == "NET-01"
    assert finding.status == Status.PASS


def test_legacy_listener_fails():
    system = FakeSystemInfo()
    fake_ss(system, SS_LEGACY)

    finding = LegacyListenersCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "HIGH"
    assert "Telnet" in finding.evidence[0]


def test_legacy_listener_not_assessed_when_ss_fails():
    system = FakeSystemInfo()

    system.add_command(
        ["ss", "-tulnp"],
        returncode=1,
        stdout="",
        stderr="permission denied",
    )

    finding = LegacyListenersCheck().run(system)

    assert finding.status == Status.NOT_ASSESSED
    assert finding.reason is not None


def test_sensitive_exposure_pass():
    system = FakeSystemInfo()
    fake_ss(system, SS_CLEAN)

    finding = SensitiveExposureCheck().run(system)

    assert finding.check_id == "NET-02"
    assert finding.status == Status.PASS


def test_sensitive_service_exposed_fails():
    system = FakeSystemInfo()
    fake_ss(system, SS_EXPOSED)

    finding = SensitiveExposureCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "MEDIUM"
    assert "MySQL" in finding.evidence[0]


def test_firewall_ufw_active():
    system = FakeSystemInfo()

    system.add_command(
        ["ufw", "status"],
        returncode=0,
        stdout="Status: active\n",
        stderr="",
    )

    finding = HostFirewallCheck().run(system)

    assert finding.check_id == "NET-03"
    assert finding.status == Status.PASS


def test_firewall_nftables_active():
    system = FakeSystemInfo()

    system.add_command(
        ["ufw", "status"],
        returncode=1,
        stdout="",
        stderr="command not found",
    )

    system.add_command(
        ["nft", "list", "ruleset"],
        returncode=0,
        stdout="table inet filter {\n chain input {}\n}\n",
        stderr="",
    )

    finding = HostFirewallCheck().run(system)

    assert finding.status == Status.PASS


def test_firewall_missing_fails():
    system = FakeSystemInfo()

    for command in (
        ["ufw", "status"],
        ["nft", "list", "ruleset"],
        ["iptables", "-S"],
    ):
        system.add_command(
            command,
            returncode=1,
            stdout="",
            stderr="command not found",
        )

    finding = HostFirewallCheck().run(system)

    assert finding.status == Status.FAIL
    assert finding.severity.value == "MEDIUM"
