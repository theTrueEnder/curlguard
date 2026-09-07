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


@pytest.mark.parametrize(
    ("args", "expected"),
    [
        (["-o", "out", "https://example.com"], ["https://example.com"]),
        (["-oout", "https://example.com"], ["https://example.com"]),
        (["--output=out", "https://example.com"], ["https://example.com"]),
        (["-fsSLO", "https://example.com/a"], ["-fsSL", "https://example.com/a"]),
    ],
)
def test_sanitize_args_removes_output_for_supported_requests(wrapper, args, expected):
    assert wrapper._sanitize_args(args) == expected


def test_extract_output_handles_stdout_and_remote_name(wrapper):
    assert wrapper._extract_output(["-o", "-", "https://example.com"]) is None
    assert (
        wrapper._extract_output(
            ["-fsSLO", "https://deno.land/install.sh"],
            "https://deno.land/install.sh",
        )
        == "install.sh"
    )
    assert (
        wrapper._extract_output(
            ["--remote-name", "https://example.com/path/tool"],
            "https://example.com/path/tool",
        )
        == "tool"
    )


def test_extract_urls_handles_curl_url_option(wrapper):
    assert wrapper._extract_urls(["--url", "https://example.com"]) == [
        "https://example.com"
    ]
    assert wrapper._extract_urls(["--url=https://example.com"]) == [
        "https://example.com"
    ]


def test_dispatch_passes_multiple_urls_through_unchanged(wrapper):
    args = ["https://example.com", "https://deno.land/install.sh"]
    with patch.object(wrapper, "_call_real_curl", return_value=0) as call_real_curl:
        exit_code = wrapper.dispatch(args)

    assert exit_code == 0
    call_real_curl.assert_called_once_with(args)
    wrapper._scanner.scan_file.assert_not_called()


def test_noninteractive_context_does_not_bypass_scanning(wrapper):
    with (
        patch.object(wrapper, "_is_interactive_session", return_value=False),
        patch.object(wrapper, "_has_passthrough_ancestor", return_value=False),
    ):
        assert wrapper._should_passthrough_for_context() is False


def test_dispatch_passthroughs_package_manager_ancestor(wrapper, monkeypatch):
    monkeypatch.setenv("CURLGUARD_SHIM_ACTIVE", "1")
    with (
        patch.object(wrapper, "_is_interactive_session", return_value=True),
        patch.object(wrapper, "_has_passthrough_ancestor", return_value=True),
        patch.object(wrapper, "_call_real_curl", return_value=23) as call_real_curl,
    ):
        exit_code = wrapper.dispatch(["https://example.com/install.sh"])

    assert exit_code == 23
    call_real_curl.assert_called_once_with(["https://example.com/install.sh"])
    wrapper._scanner.scan_file.assert_not_called()


def test_explicit_curlguard_ignores_package_manager_bypass(wrapper):
    with patch.object(wrapper, "_has_passthrough_ancestor", return_value=True):
        assert wrapper._should_passthrough_for_context() is False


def test_force_intercept_overrides_context_bypass(wrapper, tmp_path):
    wrapper._config.force_intercept = True
    temp_path = tmp_path / "body.download"

    class FakeTemp:
        name = str(temp_path)

        def __enter__(self):
            temp_path.write_bytes(b"installer")
            return self

        def __exit__(self, *args):
            return None

    with (
        patch.object(wrapper, "_is_interactive_session", return_value=False),
        patch.object(wrapper, "_has_passthrough_ancestor", return_value=True),
        patch("curlguard.wrapper.tempfile.NamedTemporaryFile", return_value=FakeTemp()),
        patch("curlguard.wrapper.subprocess.run") as run,
    ):
        run.return_value = MagicMock(returncode=0)

        exit_code = wrapper.dispatch(["https://example.com/install.sh"])

    assert exit_code == 0
    wrapper._scanner.scan_file.assert_called_once()


def test_download_to_temp_does_not_inject_fail_or_forward_user_output(
    wrapper, tmp_path
):
    temp_path = tmp_path / "body.download"

    class FakeTemp:
        name = str(temp_path)

        def __enter__(self):
            temp_path.write_bytes(b"ok")
            return self

        def __exit__(self, *args):
            return None

    with (
        patch("curlguard.wrapper.tempfile.NamedTemporaryFile", return_value=FakeTemp()),
        patch("curlguard.wrapper.subprocess.run") as run,
    ):
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
    wrapper._config.force_intercept = True
    monkeypatch.chdir(tmp_path)
    temp_path = tmp_path / "body.download"

    class FakeTemp:
        name = str(temp_path)

        def __enter__(self):
            temp_path.write_bytes(b"installer")
            return self

        def __exit__(self, *args):
            return None

    with (
        patch("curlguard.wrapper.tempfile.NamedTemporaryFile", return_value=FakeTemp()),
        patch("curlguard.wrapper.subprocess.run") as run,
    ):
        run.return_value = MagicMock(returncode=0)

        exit_code = wrapper.dispatch(["-fsSLO", "https://deno.land/install.sh"])

    captured = capsys.readouterr()
    cmd = run.call_args.args[0]
    assert exit_code == 0
    assert "-fsSL" in cmd
    assert "-fsSLO" not in cmd
    assert captured.out == ""
    assert (tmp_path / "install.sh").read_bytes() == b"installer"


def test_dispatch_returns_real_curl_exit_code_on_download_failure(
    wrapper, tmp_path, capsys
):
    wrapper._config.force_intercept = True
    temp_path = tmp_path / "body.download"

    class FakeTemp:
        name = str(temp_path)

        def __enter__(self):
            temp_path.write_bytes(b"")
            return self

        def __exit__(self, *args):
            return None

    with (
        patch("curlguard.wrapper.tempfile.NamedTemporaryFile", return_value=FakeTemp()),
        patch("curlguard.wrapper.subprocess.run") as run,
    ):
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


def test_dispatch_uses_configured_review_interface(wrapper, tmp_path):
    wrapper._config.force_intercept = True
    wrapper._config.review_interface = "console"
    wrapper._scanner.scan_file.return_value = ScanResult(
        clean=False,
        matches=["suspicious_pipe_bash"],
        rules_triggered=["suspicious_pipe_bash"],
        scan_time_ms=1.0,
        status="flagged",
    )
    temp_path = tmp_path / "body.download"

    class FakeTemp:
        name = str(temp_path)

        def __enter__(self):
            temp_path.write_bytes(b"installer")
            return self

        def __exit__(self, *args):
            return None

    with (
        patch("curlguard.wrapper.tempfile.NamedTemporaryFile", return_value=FakeTemp()),
        patch("curlguard.wrapper.subprocess.run") as run,
        patch("curlguard.review.prompt_user", return_value="allow") as prompt_user,
    ):
        run.return_value = MagicMock(returncode=0)

        exit_code = wrapper.dispatch(["https://example.com/install.sh"])

    assert exit_code == 0
    prompt_user.assert_called_once_with(
        wrapper._scanner.scan_file.return_value,
        "https://example.com/install.sh",
        ssl_warn=False,
        interface="console",
    )
