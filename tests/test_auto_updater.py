import io
from unittest.mock import MagicMock

import pytest

from curlguard.auto_updater import AutoUpdater
from curlguard.config import CurlGuardConfig


def _config(tmp_path):
    return CurlGuardConfig(
        mode="per-user",
        log_path=tmp_path / "audit.log",
        rules_dirs=[tmp_path / "rules"],
        quarantine_dir=tmp_path / "quarantine",
        update_url="https://rules.example/foundation.yar",
    )


def test_rule_update_requires_https(tmp_path):
    updater = AutoUpdater(_config(tmp_path), MagicMock())

    with pytest.raises(ValueError, match="https"):
        updater.fetch_rules("http://rules.example/foundation.yar")


def test_failed_update_does_not_write_success_timestamp(tmp_path, monkeypatch):
    updater = AutoUpdater(_config(tmp_path), MagicMock())
    monkeypatch.setattr(updater, "_last_update_file", tmp_path / ".last_update")
    monkeypatch.setattr(updater, "_lock_file", tmp_path / ".update.lock")
    monkeypatch.setattr(
        updater, "fetch_rules", MagicMock(side_effect=OSError("offline"))
    )

    updater.check_and_update()

    assert not updater._last_update_file.exists()
    assert not updater._lock_file.exists()


def test_rule_update_honors_sha256_pin(tmp_path, monkeypatch):
    config = _config(tmp_path)
    config.update_sha256 = "0" * 64
    updater = AutoUpdater(config, MagicMock())

    class Response(io.BytesIO):
        def geturl(self):
            return config.update_url

        def __enter__(self):
            return self

        def __exit__(self, *args):
            self.close()

    monkeypatch.setattr(
        "curlguard.auto_updater.urlopen", lambda *args, **kwargs: Response(b"rule x {}")
    )

    with pytest.raises(ValueError, match="SHA-256"):
        updater.fetch_rules(config.update_url)
