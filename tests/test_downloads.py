import json
import signal
import subprocess
import sys
import time
from pathlib import Path

import pytest

from tests.conftest import MALWARE, PAYLOAD


@pytest.mark.parametrize(
    "path,flags",
    [
        ("/artifact", []),
        ("/empty", []),
        ("/gzip", ["--compressed"]),
        ("/redirect", ["-L"]),
        ("/retry", ["--retry", "1", "--retry-delay", "0"]),
    ],
)
def test_body_parity(http_server, cli, path, flags):
    url, _, _ = http_server
    baseline = cli(["-qfsS", *flags, url + path], guarded=False)
    guarded = cli(["-qfsS", *flags, url + path])
    assert (guarded.returncode, guarded.stdout) == (
        baseline.returncode,
        baseline.stdout,
    )
    assert guarded.returncode == 0


@pytest.mark.parametrize(
    "path,flags",
    [("/missing", ["-f"]), ("/truncated", []), ("/loop", ["-L", "--max-redirs", "2"])],
)
def test_transfer_failure_preserves_destination(
    http_server, cli, tmp_path, path, flags
):
    url, _, _ = http_server
    dest = tmp_path / "out"
    dest.write_bytes(b"original")
    base = cli(["-q", "-sS", *flags, url + path], guarded=False)
    guarded = cli(["-q", "-sS", *flags, "-o", dest, url + path])
    assert guarded.returncode == base.returncode != 0
    assert dest.read_bytes() == b"original"
    assert guarded.stdout == b""
    assert b"Traceback" not in guarded.stderr
    assert not list(tmp_path.glob(".curlguard-*"))


@pytest.mark.parametrize("offset", ["-", "100"])
def test_resume_scans_complete_file(http_server, cli, tmp_path, offset):
    url, _, _ = http_server
    for guarded in (False, True):
        dest = tmp_path / str(guarded)
        dest.write_bytes(PAYLOAD[:100])
        p = cli(["-qfsS", "-C", offset, "-o", dest, url + "/artifact"], guarded=guarded)
        assert p.returncode == 0, p.stderr
        assert dest.read_bytes() == PAYLOAD


@pytest.mark.parametrize("path", ["/bad-range", "/range-ignore"])
def test_invalid_resume_preserves_original(http_server, cli, tmp_path, path):
    url, _, _ = http_server
    dest = tmp_path / "resume"
    dest.write_bytes(PAYLOAD[:100])
    p = cli(["-qfsS", "-C", "-", "-o", dest, url + path])
    assert p.returncode != 0
    assert dest.read_bytes() == PAYLOAD[:100]


def test_flagged_existing_prefix_is_scanned(http_server, cli, tmp_path):
    url, _, _ = http_server
    dest = tmp_path / "resume"
    dest.write_bytes(MALWARE)
    # The resumed suffix is clean, but the retained prefix still needs scanning.
    p = cli(["-qfsS", "-C", "-", "-o", dest, url + "/artifact"])
    assert p.returncode == 11
    assert dest.read_bytes() == MALWARE


def test_completed_resume_preserves_native_failure_codes(http_server, cli, tmp_path):
    url, _, _ = http_server
    dest = tmp_path / "resume"
    dest.write_bytes(PAYLOAD)
    base = cli(["-qfsS", "-C", "-", "-o", dest, url + "/artifact"], guarded=False)
    p = cli(["-qfsS", "-C", "-", "-o", dest, url + "/artifact"])
    assert p.returncode == base.returncode
    assert dest.read_bytes() == PAYLOAD


def test_conditional_and_empty_are_distinct(http_server, cli, tmp_path):
    url, _, _ = http_server
    dest = tmp_path / "out"
    dest.write_bytes(PAYLOAD)
    p = cli(["-qfsS", "-z", dest, "-o", dest, url + "/conditional"])
    assert p.returncode == 0
    assert dest.read_bytes() == PAYLOAD
    p = cli(["-qfsS", "-o", dest, url + "/empty"])
    assert p.returncode == 0
    assert dest.read_bytes() == b""


def test_etag_conditional(http_server, cli, tmp_path):
    url, _, _ = http_server
    tag, dest = tmp_path / "tag", tmp_path / "out"
    p = cli(["-qfsS", "--etag-save", tag, "-o", dest, url + "/conditional"])
    assert p.returncode == 0, p.stderr
    assert tag.read_text().strip() == '"v1"'
    p = cli(
        [
            "-qfsS",
            "--etag-compare",
            tag,
            "--etag-save",
            tag,
            "-o",
            dest,
            url + "/conditional",
        ]
    )
    assert p.returncode == 0, p.stderr
    assert dest.read_bytes() == PAYLOAD


def test_missing_etag_clears_stale_saved_tag(http_server, cli, tmp_path):
    url, _, _ = http_server
    tag = tmp_path / "tag"
    tag.write_text('"stale"')
    p = cli(["-qfsS", "--etag-save", tag, "-o", tmp_path / "out", url + "/artifact"])
    assert p.returncode == 0
    assert tag.read_bytes() == b""


@pytest.mark.parametrize("output_file", [False, True])
def test_native_writeout_and_order(http_server, cli, tmp_path, output_file):
    url, _, _ = http_server
    args = ["-qfsS", "-w", "code=%{http_code} bytes=%{size_download}\n"]
    if output_file:
        args += ["-o", tmp_path / "out"]
    baseline = cli([*args, url + "/artifact"], guarded=False)
    guarded = cli([*args, url + "/artifact"])
    assert guarded.returncode == baseline.returncode == 0
    assert guarded.stdout == baseline.stdout
    assert b"CURLGUARD-" not in guarded.stdout


def test_repeated_output_uses_first_transfer_slot(http_server, cli, tmp_path):
    url, _, _ = http_server
    for guarded in (False, True):
        first, second = tmp_path / f"{guarded}-first", tmp_path / f"{guarded}-second"
        p = cli(
            ["-qfsS", "-o", first, "-o", second, url + "/artifact"], guarded=guarded
        )
        assert p.returncode == 0
        assert first.read_bytes() == PAYLOAD
        assert not second.exists()


def test_no_bytes_before_quarantine(http_server, cli, tmp_path):
    url, _, _ = http_server
    p = cli(["-qfsS", url + "/malware"])
    assert p.returncode == 11
    assert p.stdout == b""
    payload = next((tmp_path / "quarantine").glob("*.download"))
    assert payload.read_bytes() == MALWARE
    assert payload.stat().st_mode & 0o777 == 0o600
    assert payload.with_suffix(".download.json").stat().st_mode & 0o777 == 0o600


def test_unsupported_block_makes_no_request(http_server, cli):
    url, requests, _ = http_server
    p = cli(["-I", url], overrides={"CURLGUARD_UNSUPPORTED_POLICY": "block"})
    assert p.returncode == 14
    assert requests == []


def test_unsupported_passes_original(cli, tmp_path):
    baseline = cli(["--definitely-unknown"], guarded=False)
    guarded = cli(["--definitely-unknown"])
    assert guarded.returncode == baseline.returncode
    event = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert event["scan_result"] == "skipped"
    assert event["interception_reason"]


def test_active_curl_config_is_not_silently_ignored(http_server, cli, tmp_path):
    url, requests, _ = http_server
    config = Path(cli.env["HOME"]) / ".curlrc"
    config.write_text('header = "X-Config: active"\n')
    p = cli(["-fsS", url + "/empty"])
    assert p.returncode == 0
    assert requests[-1][1]["X-Config"] == "active"
    event = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert event["scan_result"] == "skipped"
    before = len(requests)
    p = cli(
        ["-fsS", url + "/empty"], overrides={"CURLGUARD_UNSUPPORTED_POLICY": "block"}
    )
    assert p.returncode == 14
    assert len(requests) == before
    p = cli(["-qfsS", url + "/empty"])
    assert p.returncode == 0
    assert "X-Config" not in requests[-1][1]
    assert (
        json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])["scan_result"]
        == "clean"
    )


def test_timeout_preserves_existing_destination(http_server, cli, tmp_path):
    url, _, _ = http_server
    dest = tmp_path / "out"
    dest.write_bytes(b"original")
    p = cli(["-qfsS", "--max-time", "0.1", "-o", dest, url + "/slow"])
    assert p.returncode == 28
    assert dest.read_bytes() == b"original"
    assert b"Traceback" not in p.stderr


def test_tls_verification_and_explicit_ca(https_server, cli):
    url, cert = https_server
    for guarded in (False, True):
        p = cli(["-qfsS", url + "/artifact"], guarded=guarded)
        assert p.returncode == 60
        p = cli(["-qfsS", "--cacert", cert, url + "/artifact"], guarded=guarded)
        assert p.returncode == 0, p.stderr
        assert p.stdout == PAYLOAD


def test_scan_limit_warn_and_block(http_server, cli):
    url, _, _ = http_server
    for mode, code in [("warn", 0), ("block", 13)]:
        p = cli(
            ["-qfsS", url + "/artifact"],
            overrides={
                "CURLGUARD_MAX_SCAN_BYTES": "10",
                "CURLGUARD_SCAN_FAILURE_MODE": mode,
            },
        )
        assert p.returncode == code
        assert p.stdout == (PAYLOAD if mode == "warn" else b"")
        assert b"verified" not in p.stderr


def test_native_help_and_management(cli):
    p = cli(["--version"], overrides={"CURLGUARD_UNSUPPORTED_POLICY": "block"})
    assert p.returncode == 0
    assert p.stdout.startswith(b"curl ")
    p = subprocess.run(
        [sys.executable, "-m", "curlguard.cli", "--version"],
        env=cli.env,
        capture_output=True,
    )
    assert p.stdout.startswith(b"curlguard ")


def test_sigterm_cleans_staging_and_reaps_child(http_server, cli, tmp_path):
    url, requests, _ = http_server
    dest = tmp_path / "out"
    dest.write_bytes(b"original")
    p = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "curlguard.cli",
            "--as-curl",
            "-qfsS",
            "-o",
            str(dest),
            url + "/slow",
        ],
        env=cli.env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    try:
        deadline = time.monotonic() + 5
        while not requests and time.monotonic() < deadline:
            time.sleep(0.02)
        assert requests
        p.send_signal(signal.SIGTERM)
        out, err = p.communicate(timeout=5)
        assert p.returncode == 143
        assert out == b""
        assert b"Traceback" not in err
        assert dest.read_bytes() == b"original"
        assert not list(tmp_path.glob(".curlguard-*"))
    finally:
        if p.poll() is None:
            p.kill()
            p.wait()


def test_broken_pipe_has_no_traceback(http_server, cli):
    url, _, _ = http_server
    p = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "curlguard.cli",
            "--as-curl",
            "-qfsS",
            url + "/artifact",
        ],
        env=cli.env,
        stdout=subprocess.PIPE,
        stderr=subprocess.PIPE,
    )
    p.stdout.close()
    err = p.stderr.read()
    p.wait(timeout=5)
    assert p.returncode == 23
    assert b"Traceback" not in err
    assert b"Exception ignored" not in err
