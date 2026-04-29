import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from unittest.mock import MagicMock, patch

import pytest
from curlguard.config import CurlGuardConfig
from curlguard.scanner import ScanResult
from curlguard.ssl_detector import SslBypassResult
from curlguard.wrapper import CurlWrapper


def test_wrapper_import():
    assert CurlWrapper is not None


@pytest.fixture
def wrapper(tmp_path):
    config = CurlGuardConfig(
        mode="per-user",
        log_path=tmp_path / "audit.log",
        rules_dirs=[],
        quarantine_dir=tmp_path / "quarantine",
        real_curl_path=tmp_path / "curl.real",
    )
    config.real_curl_path.write_text("#!/bin/sh\n")
    scanner = MagicMock()
    scanner.scan_file.return_value = ScanResult(
        clean=True,
        matches=[],
        rules_triggered=[],
        scan_time_ms=1.0,
    )
    logger = MagicMock()
    ssl_detector = MagicMock()
    ssl_detector.detect.return_value = SslBypassResult(
        is_bypass=False,
        bypass_type=None,
        severity="warning",
        message="",
    )
    return CurlWrapper(config, scanner, logger, ssl_detector)


def test_sanitize_args_removes_all_output_spellings(wrapper):
    args = [
        "-H",
        "Authorization: Bearer token",
        "-o",
        "out-a",
        "https://example.com",
        "--output",
        "out-b",
        "-oout-c",
        "--output=out-d",
        "-fsSLO",
        "--remote-name",
    ]

    assert wrapper._sanitize_args(args) == [
        "-H",
        "Authorization: Bearer token",
        "https://example.com",
        "-fsSL",
    ]


def test_extract_output_handles_stdout_and_remote_name(wrapper):
    assert wrapper._extract_output(["-o", "-", "https://example.com"]) is None
    assert wrapper._extract_output(
        ["-fsSLO", "https://deno.land/install.sh"],
        "https://deno.land/install.sh",
    ) == "install.sh"
    assert wrapper._extract_output(
        ["--remote-name", "https://example.com/path/tool"],
        "https://example.com/path/tool",
    ) == "tool"


def test_extract_urls_handles_curl_url_option(wrapper):
    assert wrapper._extract_urls(["--url", "https://example.com"]) == ["https://example.com"]
    assert wrapper._extract_urls(["--url=https://example.com"]) == ["https://example.com"]


def test_dispatch_rejects_multiple_urls(wrapper, capsys):
    exit_code = wrapper.dispatch([
        "https://example.com",
        "https://deno.land/install.sh",
    ])

    captured = capsys.readouterr()
    assert exit_code == 2
    assert "multiple URLs" in captured.err
    wrapper._scanner.scan_file.assert_not_called()


def test_download_to_temp_does_not_inject_fail_or_forward_user_output(wrapper, tmp_path):
    temp_path = tmp_path / "body.download"

    class FakeTemp:
        name = str(temp_path)

        def __enter__(self):
            temp_path.write_bytes(b"ok")
            return self

        def __exit__(self, *args):
            return None

    with patch("curlguard.wrapper.tempfile.NamedTemporaryFile", return_value=FakeTemp()), \
         patch("curlguard.wrapper.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0)

        path = wrapper._download_to_temp(
            [
                "http://127.0.0.1:4000/v1/models",
                "-H",
                "Authorization: Bearer sk-local-proxy-key",
                "-o",
                "models.json",
            ]
        )

    cmd = run.call_args.args[0]
    assert "-f" not in cmd
    assert "--fail" not in cmd
    assert "models.json" not in cmd
    assert cmd.count("--output") == 1
    assert path == temp_path


def test_dispatch_honors_remote_name_output(wrapper, tmp_path, monkeypatch, capsys):
    monkeypatch.chdir(tmp_path)
    temp_path = tmp_path / "body.download"

    class FakeTemp:
        name = str(temp_path)

        def __enter__(self):
            temp_path.write_bytes(b"installer")
            return self

        def __exit__(self, *args):
            return None

    with patch("curlguard.wrapper.tempfile.NamedTemporaryFile", return_value=FakeTemp()), \
         patch("curlguard.wrapper.subprocess.run") as run:
        run.return_value = MagicMock(returncode=0)

        exit_code = wrapper.dispatch(["-fsSLO", "https://deno.land/install.sh"])

    captured = capsys.readouterr()
    cmd = run.call_args.args[0]
    assert exit_code == 0
    assert "-fsSL" in cmd
    assert "-fsSLO" not in cmd
    assert captured.out == ""
    assert (tmp_path / "install.sh").read_bytes() == b"installer"


def test_dispatch_returns_real_curl_exit_code_on_download_failure(wrapper, tmp_path, capsys):
    temp_path = tmp_path / "body.download"

    class FakeTemp:
        name = str(temp_path)

        def __enter__(self):
            temp_path.write_bytes(b"")
            return self

        def __exit__(self, *args):
            return None

    with patch("curlguard.wrapper.tempfile.NamedTemporaryFile", return_value=FakeTemp()), \
         patch("curlguard.wrapper.subprocess.run") as run:
        run.return_value = MagicMock(
            returncode=7,
            stderr=b"curl: (7) Failed to connect to 127.0.0.1 port 4000\n",
        )

        exit_code = wrapper.dispatch(["http://127.0.0.1:4000/v1/models"])

    captured = capsys.readouterr()
    assert exit_code == 7
    assert "curl: (7) Failed to connect" in captured.err
    wrapper._scanner.scan_file.assert_not_called()
    assert not temp_path.exists()
