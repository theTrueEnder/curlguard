import fcntl
from unittest.mock import patch

import pytest

from curlguard.auto_updater import AutoUpdater
from curlguard.config import CurlGuardConfig
from curlguard.scanner import YaraScanner

VALID = (
    b'rule remote_indicator { strings: $a = "remote synthetic marker" condition: $a }'
)


class Response:
    def __init__(self, body=VALID, *, status=200, location=None):
        self.body, self.status_code = body, status
        self.is_redirect = location is not None
        self.headers = {"Location": location} if location else {}

    def raise_for_status(self):
        if self.status_code >= 400:
            raise OSError("HTTP error")

    def iter_content(self, size):
        for i in range(0, len(self.body), size):
            yield self.body[i : i + size]

    def __enter__(self):
        return self

    def __exit__(self, *args):
        pass


@pytest.fixture
def updater(tmp_path):
    rules = tmp_path / "rules"
    rules.mkdir()
    config = CurlGuardConfig(
        "per-user",
        tmp_path / "audit.log",
        rules_dirs=[rules],
        quarantine_dir=tmp_path / "quarantine",
        update_url="https://rules.example/rules.yar",
    )
    return AutoUpdater(config, YaraScanner(config.rules_dirs))


def session_response(response):
    context = patch("requests.Session")
    session = context.start().return_value.__enter__.return_value
    if isinstance(response, Exception):
        session.get.side_effect = response
    else:
        session.get.return_value = response
    return context, session


def test_valid_update_activates_and_timestamps(updater):
    context, session = session_response(Response())
    try:
        updater.check_and_update()
    finally:
        context.stop()
    assert updater._last_update_file.exists()
    assert not updater.should_update()
    assert updater._scanner.scan(b"remote synthetic marker").status == "flagged"
    assert session.get.call_args.kwargs == {
        "timeout": 30,
        "stream": True,
        "allow_redirects": False,
    }
    assert not list(updater._base.glob("rules/.update-*"))


@pytest.mark.parametrize(
    "response",
    [
        OSError("offline"),
        Response(status=500),
        Response(b"invalid yara"),
        Response(b'include "/etc/passwd"'),
        Response(b"x" * (5 * 1024 * 1024 + 1)),
        Response(status=302, location="http://insecure.example/rules"),
    ],
)
def test_failed_update_keeps_last_good_and_backoff(updater, response):
    target = updater._base / "rules/auto_update.yar"
    target.write_bytes(VALID)
    updater._scanner.reload_rules()
    previous = updater._scanner.ruleset_id
    context, session = session_response(response)
    try:
        updater.check_and_update()
        updater.check_and_update()
    finally:
        context.stop()
    assert session.get.call_count == 1
    assert target.read_bytes() == VALID
    assert updater._scanner.ruleset_id == previous
    assert not updater._last_update_file.exists()
    assert updater._failure_file.exists()
    assert not list(target.parent.glob(".update-*"))


def test_http_source_is_rejected_before_request(updater):
    updater._config.update_url = "http://rules.example/rules.yar"
    context, session = session_response(Response())
    try:
        updater.check_and_update()
    finally:
        context.stop()
    session.get.assert_not_called()
    assert not updater._last_update_file.exists()


def test_update_lock_prevents_concurrent_fetch(updater):
    with (updater._base / ".update.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        context, session = session_response(Response())
        try:
            updater.check_and_update()
        finally:
            context.stop()
    session.get.assert_not_called()


def test_interrupted_update_keeps_active_rules(updater):
    identity = updater._scanner.ruleset_id
    context, session = session_response(Response())
    session.get.side_effect = KeyboardInterrupt
    try:
        with pytest.raises(KeyboardInterrupt):
            updater.check_and_update()
    finally:
        context.stop()
    assert updater._scanner.ruleset_id == identity
    assert not updater._last_update_file.exists()
    assert not list(updater._base.glob("rules/.update-*"))
