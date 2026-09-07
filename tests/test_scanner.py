import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.scanner import ScanResult, YaraScanner


def test_scanner_import():
    assert YaraScanner is not None
    assert ScanResult is not None


def test_scanner_clean_content():
    scanner = YaraScanner([])
    result = scanner.scan(b"#!/bin/bash\necho hello world")
    assert result.clean is True


def test_scanner_always_discovers_bundled_rules():
    scanner = YaraScanner([])
    if scanner._yara_available:
        assert scanner.get_rules_count() >= 1


def test_scanresult_dataclass():
    result = ScanResult(
        clean=True,
        matches=[],
        rules_triggered=[],
        scan_time_ms=0.5,
    )
    assert result.clean is True
    assert result.scan_time_ms == 0.5
