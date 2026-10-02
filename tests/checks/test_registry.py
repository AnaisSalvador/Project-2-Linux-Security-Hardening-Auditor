from hardening_auditor.checks.registry import get_all_checks


EXPECTED_CHECK_IDS = [
    "SSH-01",
    "SSH-02",
    "SSH-03",
    "USR-01",
    "USR-02",
    "USR-03",
    "NET-01",
    "NET-02",
    "NET-03",
    "SVC-01",
    "SVC-02",
    "SVC-03",
    "FIL-01",
    "FIL-02",
    "FIL-03",
]


def test_registry_contains_all_checks():
    checks = get_all_checks()

    assert len(checks) == 15
    assert [check.check_id for check in checks] == EXPECTED_CHECK_IDS


def test_registry_has_unique_check_ids():
    checks = get_all_checks()

    check_ids = [check.check_id for check in checks]

    assert len(check_ids) == len(set(check_ids))


def test_registry_contains_security_check_instances():
    checks = get_all_checks()

    assert all(check.check_id for check in checks)
    assert all(check.category for check in checks)
    assert all(check.title for check in checks)
