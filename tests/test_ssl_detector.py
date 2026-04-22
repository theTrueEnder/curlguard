import pytest
from curlguard.ssl_detector import SslBypassDetector, SslBypassResult


def test_detector_import():
    assert SslBypassDetector is not None
    assert SslBypassResult is not None


def test_clean_request():
    detector = SslBypassDetector()
    result = detector.detect(["https://example.com/file.sh"], "https://example.com/file.sh")
    assert result.is_bypass is False


def test_insecure_flag():
    detector = SslBypassDetector()
    result = detector.detect(["--insecure", "https://example.com"], "https://example.com")
    assert result.is_bypass is True
    assert result.bypass_type == "flag"