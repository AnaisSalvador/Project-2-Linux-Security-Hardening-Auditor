"""Base interface for security checks."""

from abc import ABC, abstractmethod

from hardening_auditor.models import Category, Finding
from hardening_auditor.system import SystemInfo


class SecurityCheck(ABC):
    """Base class for every security check."""

    check_id: str
    category: Category
    title: str

    @abstractmethod
    def run(self, system: SystemInfo) -> Finding:
        """Run the check and return exactly one Finding."""
        raise NotImplementedError
