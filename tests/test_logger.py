import os
import stat
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.logger import AuditEvent, AuditLogger


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


def test_logger_redacts_url_secrets(tmp_path):
    logger = AuditLogger(tmp_path / "audit.log")
    logger.log(
        AuditEvent(
            timestamp="2024-01-01T00:00:00",
            url="https://user:secret@example.com/file?token=secret#fragment",
            destination=None,
            scan_result="clean",
        )
    )
    logger.close()

    contents = (tmp_path / "audit.log").read_text(encoding="utf-8")
    assert "user:secret" not in contents
    assert "token=secret" not in contents
    assert "https://example.com/file" in contents
    if os.name == "posix":
        assert stat.S_IMODE((tmp_path / "audit.log").stat().st_mode) == 0o600
