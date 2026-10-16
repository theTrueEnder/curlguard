"""Signed feed lifecycle; all keys are ephemeral and all traffic mocked."""

import fcntl
import hashlib
import json
import subprocess
from datetime import datetime, timedelta, timezone
from unittest.mock import patch

import pytest
from cryptography.exceptions import InvalidSignature
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PrivateKey

from curlguard.auto_updater import AutoUpdater, encode
from curlguard.config import CurlGuardConfig
from curlguard.scanner import YaraScanner

VALID = (
    b'rule remote_indicator { strings: $a = "remote synthetic marker" condition: $a }'
)


class Response:
    def __init__(self, body, status=200, location=None):
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
    keys = tmp_path / "keys.json"
    key = Ed25519PrivateKey.generate()
    keys.write_text(
        json.dumps(
            {
                "keys": {
                    "test": encode(
                        key.public_key().public_bytes(
                            serialization.Encoding.Raw, serialization.PublicFormat.Raw
                        )
                    )
                }
            }
        )
    )
    config = CurlGuardConfig(
        "per-user",
        tmp_path / "audit.log",
        quarantine_dir=tmp_path / "quarantine",
        update_url="https://rules.example/bundle.json",
        update_keys_file=keys,
        update_feed_id="test-feed",
    )
    updater = AutoUpdater(config, YaraScanner())
    updater.test_key = key
    updater._base.mkdir(mode=0o700)
    return updater


def bundle(updater, sequence=1, source=VALID, **updates):
    now = datetime.now(timezone.utc)
    manifest = {
        "schema_version": 1,
        "feed_id": "test-feed",
        "sequence": sequence,
        "published_at": (now - timedelta(days=1)).isoformat(),
        "expires_at": (now + timedelta(days=1)).isoformat(),
        "rules_sha256": hashlib.sha256(source).hexdigest(),
        "rules": encode(source),
    }
    manifest.update(updates)
    raw = json.dumps(manifest, sort_keys=True).encode()
    return json.dumps(
        {
            "schema_version": 1,
            "key_id": "test",
            "manifest": encode(raw),
            "signature": encode(updater.test_key.sign(raw)),
        }
    ).encode()


def fetch(updater, body):
    with patch("requests.Session") as session:
        session.return_value.__enter__.return_value.get.return_value = Response(body)
        return updater.fetch_rules(updater._config.update_url)


def test_activation_persistence_and_status(updater):
    body = bundle(updater)
    fetch(updater, body)
    assert updater._scanner.scan(b"remote synthetic marker").status == "flagged"
    assert updater.status()["sequence"] == 1
    assert updater.status()["usable"]
    scanner = YaraScanner()
    reloaded = AutoUpdater(updater._config, scanner)
    assert reloaded.load_active()["usable"]
    assert scanner.scan(b"remote synthetic marker").status == "flagged"
    assert scanner.ruleset_id == updater._scanner.ruleset_id
    fetch(updater, body)  # Identical sequence and bytes are idempotent.
    assert not list(updater._base.glob("generations/.stage-*"))


@pytest.mark.parametrize(
    "kind",
    [
        "unsigned",
        "signature",
        "unknown_key",
        "expired",
        "future",
        "feed",
        "sequence",
        "digest",
        "encoding",
        "invalid_yara",
        "includes",
    ],
)
def test_rejection_preserves_active_generation(updater, kind):
    fetch(updater, bundle(updater))
    previous = updater.current()[0]
    body = bundle(updater, sequence=2)
    if kind == "unsigned":
        body = VALID
    elif kind in {"signature", "unknown_key", "encoding"}:
        data = json.loads(body)
        data[
            {"signature": "signature", "unknown_key": "key_id", "encoding": "manifest"}[
                kind
            ]
        ] = "unknown"
        body = json.dumps(data).encode()
    elif kind == "expired":
        body = bundle(
            updater,
            sequence=2,
            expires_at=(datetime.now(timezone.utc) - timedelta(hours=1)).isoformat(),
        )
    elif kind == "future":
        body = bundle(
            updater,
            sequence=2,
            published_at=(datetime.now(timezone.utc) + timedelta(hours=1)).isoformat(),
        )
    elif kind == "feed":
        body = bundle(updater, sequence=2, feed_id="other")
    elif kind == "sequence":
        body = bundle(updater, sequence=True)
    elif kind == "digest":
        body = bundle(updater, sequence=2, rules_sha256="0" * 64)
    elif kind == "invalid_yara":
        body = bundle(updater, sequence=2, source=b"not valid yara")
    elif kind == "includes":
        body = bundle(updater, sequence=2, source=b'include "/etc/passwd"')
    with pytest.raises((ValueError, InvalidSignature)):
        fetch(updater, body)
    assert updater.current()[0] == previous
    assert updater._scanner.scan(b"remote synthetic marker").status == "flagged"


def test_rollback_and_conflicting_equal_sequence(updater):
    fetch(updater, bundle(updater, sequence=2))
    for body in (
        bundle(updater, sequence=1),
        bundle(updater, sequence=2, source=VALID + b"\n"),
    ):
        with pytest.raises(ValueError, match="rollback"):
            fetch(updater, body)


def test_configured_trust_and_source_are_bound(updater):
    fetch(updater, bundle(updater))
    updater._config.update_url = "https://different.example/bundle"
    assert not updater.status()["usable"]
    updater._config.update_url = "https://rules.example/bundle.json"
    data = json.loads(updater._config.update_keys_file.read_text())
    data["keys"]["extra"] = data["keys"]["test"]
    updater._config.update_keys_file.write_text(json.dumps(data))
    assert not updater.status()["usable"]


def test_tampered_persisted_generation_never_loads(updater):
    fetch(updater, bundle(updater))
    name = updater.current()[0]
    (updater._base / "generations" / name / "bundle.json").write_bytes(b"tampered")
    assert not updater.load_active()["usable"]


def test_backoff_and_lock(updater):
    with patch("requests.Session") as session:
        session.return_value.__enter__.return_value.get.side_effect = OSError("offline")
        assert not updater.check_and_update()
        assert not updater.check_and_update()
        assert session.return_value.__enter__.return_value.get.call_count == 1
    assert updater.status()["last_failure"]["error"] == "OSError"
    updater._failure_file.unlink()
    with (updater._base / ".update.lock").open("w") as lock:
        fcntl.flock(lock, fcntl.LOCK_EX)
        with patch("requests.Session") as session:
            assert not updater.check_and_update()
            session.assert_not_called()


def test_https_redirects_size_and_non_200(updater):
    for response in (
        Response(b"", location="http://unsafe.example/rules"),
        Response(b"x" * (updater.MAX_BYTES + 1)),
        Response(b"", status=204),
    ):
        with patch("requests.Session") as session:
            session.return_value.__enter__.return_value.get.return_value = response
            with pytest.raises(ValueError):
                updater.fetch_rules(updater._config.update_url)
    updater._config.update_url = "http://unsafe.example/rules"
    with patch("requests.Session") as session:
        with pytest.raises(ValueError):
            updater.fetch_rules(updater._config.update_url)
        session.return_value.__enter__.return_value.get.assert_not_called()


def test_worker_timeout_preserves_rules_and_cleans_stage(updater):
    previous = updater._scanner.ruleset_id
    with patch(
        "curlguard.scanner.subprocess.run",
        side_effect=subprocess.TimeoutExpired("worker", 30),
    ):
        with pytest.raises(subprocess.TimeoutExpired):
            fetch(updater, bundle(updater))
    assert updater._scanner.ruleset_id == previous
    assert not updater._last_update_file.exists()
    assert not list(updater._base.glob("generations/.stage-*"))


def test_interrupted_activation_preserves_generation(updater):
    with patch.object(
        updater._scanner, "compile_candidate", side_effect=KeyboardInterrupt
    ):
        with pytest.raises(KeyboardInterrupt):
            fetch(updater, bundle(updater))
    assert not updater._last_update_file.exists()
    assert not list(updater._base.glob("generations/.stage-*"))


def test_decoded_rule_limit(updater):
    updater.MAX_BYTES = 16 * 1024 * 1024
    with pytest.raises(ValueError, match="size limit"):
        fetch(updater, bundle(updater, source=b"x" * (updater.MAX_RULE_BYTES + 1)))


def test_publisher_utility_roundtrip(updater, tmp_path):
    import os
    import sys
    from pathlib import Path

    key = tmp_path / "private.pem"
    key.write_bytes(
        updater.test_key.private_bytes(
            serialization.Encoding.PEM,
            serialization.PrivateFormat.PKCS8,
            serialization.NoEncryption(),
        )
    )
    os.chmod(key, 0o600)
    source, output = tmp_path / "source.yar", tmp_path / "bundle.json"
    source.write_bytes(VALID)
    now = datetime.now(timezone.utc)
    env = {**os.environ, "PYTHONPATH": str(Path(__file__).resolve().parents[1] / "src")}
    result = subprocess.run(
        [
            sys.executable,
            "-m",
            "curlguard.sign_rules",
            str(source),
            str(output),
            "--private-key",
            str(key),
            "--key-id",
            "test",
            "--feed-id",
            "test-feed",
            "--sequence",
            "1",
            "--published-at",
            (now - timedelta(hours=1)).isoformat(),
            "--expires-at",
            (now + timedelta(days=1)).isoformat(),
        ],
        cwd=tmp_path,
        env=env,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
    assert updater.verify(output.read_bytes())[1] == VALID
