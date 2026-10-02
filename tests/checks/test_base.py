import pytest

from hardening_auditor.checks.base import SecurityCheck
from hardening_auditor.models import Category


class ValidCheck(SecurityCheck):
    check_id = "TEST-01"
    category = Category.SSH
    title = "Test check"

    def run(self, system):
        return None


def test_valid_check_can_be_instantiated():
    check = ValidCheck()

    assert check.check_id == "TEST-01"
    assert check.category == Category.SSH
    assert check.title == "Test check"


def test_base_check_cannot_be_instantiated():
    with pytest.raises(TypeError):
        SecurityCheck()
