import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.ssl_detector import SslBypassDetector, SslBypassResult


def test_detector_import():
    assert SslBypassDetector is not None
    assert SslBypassResult is not None


def test_clean_request():
    detector = SslBypassDetector()
    result = detector.detect(
        ["https://example.com/file.sh"], "https://example.com/file.sh"
    )
    assert result.is_bypass is False


def test_insecure_flag():
    detector = SslBypassDetector()
    result = detector.detect(
        ["--insecure", "https://example.com"], "https://example.com"
    )
    assert result.is_bypass is True
    assert result.bypass_type == "flag"


def test_combined_insecure_flag_and_attached_tls_max():
    detector = SslBypassDetector()

    assert detector.detect(
        ["-skL", "https://example.com"], "https://example.com"
    ).is_bypass
    result = detector.detect(
        ["--tls-max=1.0", "https://example.com"], "https://example.com"
    )
    assert result.severity == "block"
