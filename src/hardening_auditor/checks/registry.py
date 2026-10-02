"""Registry of all security checks."""

from hardening_auditor.checks.base import SecurityCheck
from hardening_auditor.checks.files import (
    SensitiveFilePermissionsCheck,
    SuspiciousSUIDCheck,
    WorldWritableSystemFilesCheck,
)
from hardening_auditor.checks.network import (
    HostFirewallCheck,
    LegacyListenersCheck,
    SensitiveExposureCheck,
)
from hardening_auditor.checks.services import (
    LegacyServicesCheck,
    LoggingServiceCheck,
    SecurityUpdatesCheck,
)
from hardening_auditor.checks.ssh import (
    SSHKeyPermissionsCheck,
    SSHPasswordAuthenticationCheck,
    SSHRootLoginCheck,
)
from hardening_auditor.checks.users import (
    EmptyPasswordAccountsCheck,
    ExtraUID0AccountsCheck,
    SudoRulesCheck,
)


def get_all_checks() -> list[SecurityCheck]:
    """Return all registered security checks in a stable order."""
    return [
        SSHRootLoginCheck(),
        SSHPasswordAuthenticationCheck(),
        SSHKeyPermissionsCheck(),
        ExtraUID0AccountsCheck(),
        EmptyPasswordAccountsCheck(),
        SudoRulesCheck(),
        LegacyListenersCheck(),
        SensitiveExposureCheck(),
        HostFirewallCheck(),
        LegacyServicesCheck(),
        SecurityUpdatesCheck(),
        LoggingServiceCheck(),
        SensitiveFilePermissionsCheck(),
        SuspiciousSUIDCheck(),
        WorldWritableSystemFilesCheck(),
    ]
