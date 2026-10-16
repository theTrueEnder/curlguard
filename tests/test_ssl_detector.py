import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.ssl_detector import SslBypassDetector, SslBypassResult


def test_option_values_do_not_become_tls_flags():
    result = SslBypassDetector().detect(["-H", "--tlsv1.0"], "https://example.com")
    assert not result.is_bypass


def test_tls_block_has_priority_over_insecure_warning():
    result = SslBypassDetector().detect(
        ["-ksS", "--tls-max=1.1"], "https://example.com"
    )
    assert result.severity == "block"


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
