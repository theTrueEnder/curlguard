import pytest
from curlguard.scanner import YaraScanner, ScanResult


def test_scanner_import():
    assert YaraScanner is not None
    assert ScanResult is not None


def test_scanner_clean_content():
    scanner = YaraScanner([])
    result = scanner.scan(b"#!/bin/bash\necho hello world")
    assert result.clean is True


def test_scanresult_dataclass():
    result = ScanResult(
        clean=True,
        matches=[],
        rules_triggered=[],
        scan_time_ms=0.5,
    )
    assert result.clean is True
    assert result.scan_time_ms == 0.5