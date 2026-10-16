import pytest

from curlguard.arguments import parse


@pytest.mark.parametrize(
    "args,output",
    [
        (["-fsSLoout", "https://example.com/a"], "out"),
        (["--url=https://example.com/a", "--output=out"], "out"),
        (["-oone", "-otwo", "--", "https://example.com/a"], "one"),
        (["-O", "https://example.com/a"], "a"),
        (["-O", "-o", "-", "https://example.com/a"], "a"),
    ],
)
def test_option_forms(args, output):
    request = parse(args, check_config=False)
    assert request.reason is None
    assert request.destination == output
    assert request.urls == ["https://example.com/a"]


def test_url_like_values_are_not_urls():
    request = parse(
        ["-H", "https://not-a-url", "-ehttps://referer", "https://actual/a"],
        check_config=False,
    )
    assert request.reason is None
    assert request.urls == ["https://actual/a"]


@pytest.mark.parametrize(
    "args",
    [
        ["--new-future-option"],
        ["-dvalue", "https://example.com"],
        ["-Kconfig", "https://example.com"],
        ["-N", "https://example.com"],
        ["https://example.com/{a,b}"],
        ["https://a", "https://b"],
        ["-w%{json}", "https://example.com"],
        ["-w%output{file}", "https://example.com"],
        ["-w@file", "https://example.com"],
        ["-C100", "https://example.com"],
        ["-o"],
        ["--output"],
        ["--parallel", "https://example.com"],
        ["-o", "", "https://example.com"],
        ["-H", "Range: bytes=1-", "https://example.com"],
        ["https://[invalid"],
    ],
)
def test_unsupported(args):
    assert parse(args, check_config=False).reason


def test_implicit_config(tmp_path, monkeypatch):
    monkeypatch.setenv("CURL_HOME", str(tmp_path))
    (tmp_path / ".curlrc").write_text("url=https://hidden.example")
    assert parse(["https://example.com"]).reason == "active implicit curl config"
    assert parse(["-qfsSL", "https://example.com"]).reason is None


def test_nonregular_destination(tmp_path):
    dest = tmp_path / "link"
    dest.symlink_to(tmp_path / "missing")
    assert parse(["-o", str(dest), "https://example.com"], check_config=False).reason


def test_readonly_output_uses_unsupported_policy(tmp_path, monkeypatch):
    path = tmp_path / "out"
    path.write_text("original")
    monkeypatch.setattr("curlguard.arguments.os.access", lambda *args: False)
    assert parse(["-o", str(path), "https://example.com"], check_config=False).reason


def test_hardlinked_output_uses_unsupported_policy(tmp_path):
    import os

    path = tmp_path / "out"
    path.write_text("original")
    os.link(path, tmp_path / "other")
    assert parse(["-o", str(path), "https://example.com"], check_config=False).reason
