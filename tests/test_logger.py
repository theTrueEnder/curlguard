import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from curlguard.logger import AuditLogger, AuditEvent


def test_logger_import():
    assert AuditLogger is not None
    assert AuditEvent is not None


def test_auditevent_defaults():
    event = AuditEvent(
        timestamp="2024-01-01T00:00:00",
        url="https://example.com",
        destination=None,
        scan_result="clean",
    )
    assert event.scan_result == "clean"
    assert event.user_decision is None