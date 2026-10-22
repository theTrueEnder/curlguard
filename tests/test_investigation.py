"""Local files and quarantine are inspected as inert data, without network access."""

import hashlib
import json
import os
from unittest.mock import Mock

import pytest

from curlguard.config import CurlGuardConfig
from curlguard.inspection import inspect_file
from curlguard.quarantine import investigate
from curlguard.scanner import ScanResult, YaraScanner
from tests.test_workflows import validate_document


@pytest.fixture
def config(tmp_path):
    return CurlGuardConfig(
        "per-user", tmp_path / "log", quarantine_dir=tmp_path, match_policy="block"
    )


@pytest.mark.parametrize(
    "data,code,status",
    [
        (b"inert", 0, "clean"),
        (b"echo ZWNobyB1bnNhZmU= | base64 -d | bash", 10, "flagged"),
    ],
)
def test_scan_read_only(cli, tmp_path, data, code, status):
    path = tmp_path / "input"
    path.write_bytes(data)
    path.chmod(0o640)
    before = path.stat()
    result = cli(["scan", path, "--json"], management=True)
    report = json.loads(result.stdout)
    validate_document(report, "scan-report")
    assert result.returncode == code
    assert report["outcome"] == status
    assert report["ruleset_id"] and report["schema_version"] == 1
    assert report["sha256"] == hashlib.sha256(data).hexdigest()
    after = path.stat()
    assert (before.st_uid, before.st_gid, before.st_mode, before.st_mtime_ns) == (
        after.st_uid,
        after.st_gid,
        after.st_mode,
        after.st_mtime_ns,
    )
    assert path.read_bytes() == data
    assert report["evidence"]["transport"] == {}


@pytest.mark.parametrize(
    "kind,outcome",
    [
        ("missing", "unreadable"),
        ("directory", "not_regular"),
        ("fifo", "not_regular"),
        ("large", "oversized"),
        ("symlink", "unreadable"),
    ],
)
def test_scan_invalid_inputs(config, tmp_path, kind, outcome):
    path = tmp_path / "input"
    config.max_scan_bytes = 2
    if kind == "directory":
        path.mkdir()
    elif kind == "fifo":
        os.mkfifo(path)
    elif kind == "large":
        path.write_bytes(b"big")
    elif kind == "symlink":
        path.symlink_to(tmp_path / "missing")
    report, code = inspect_file(path, config, Mock(ruleset_id="test"))
    assert code == 13 and report["outcome"] == outcome
    assert report["sha256"] is None


def test_unavailable_and_changed(config, tmp_path):
    path = tmp_path / "input"
    path.write_bytes(b"inert")
    scanner = Mock(ruleset_id="test")
    scanner.scan_file.return_value = ScanResult(False, [], [], 0, "unavailable")
    report, code = inspect_file(path, config, scanner)
    assert code == 13 and report["evidence"]["detection"] == "unavailable"

    def mutate(_):
        path.write_bytes(b"changed")
        return ScanResult(True, [], [], 0)

    scanner.scan_file.side_effect = mutate
    report, code = inspect_file(path, config, scanner)
    assert code == 17 and report["sha256"] is None


def record(tmp_path, data=b"inert", name="capture"):
    payload = tmp_path / name
    payload.write_bytes(data)
    metadata = {
        "sha256": hashlib.sha256(data).hexdigest(),
        "rules_triggered": ["historic"],
        "timestamp": "2020-01-01T00:00:00Z",
    }
    sidecar = tmp_path / (name + ".json")
    sidecar.write_text(json.dumps(metadata))
    return payload, sidecar, metadata


def test_legacy_inspect_and_append_rescan(config, tmp_path):
    payload, sidecar, original = record(tmp_path)
    report, code = investigate(config, payload.name, "inspect")
    validate_document(report, "quarantine-report")
    assert code == 0 and report["integrity"] == "matched"
    report, code = investigate(config, payload.name, "rescan")
    validate_document(report, "quarantine-report")
    assert code == 0
    updated = json.loads(sidecar.read_text())
    assert {k: updated[k] for k in original} == original
    assert updated["rescans"][0]["ruleset_id"] == YaraScanner().ruleset_id
    assert updated["rescans"][0]["outcome"] == "clean"
    assert payload.read_bytes() == b"inert"


def test_quarantine_integrity_and_export(config, tmp_path):
    payload, _, _ = record(tmp_path)
    dest = tmp_path / "export"
    report, code = investigate(config, payload.name, "export", dest)
    assert code == 0 and dest.read_bytes() == b"inert"
    assert dest.stat().st_mode & 0o777 == 0o600
    assert investigate(config, payload.name, "export", dest)[1] != 0
    payload.write_bytes(b"tampered")
    assert investigate(config, payload.name, "inspect")[1] == 17
    assert investigate(config, payload.name, "rescan")[1] == 17
    assert investigate(config, payload.name, "export", tmp_path / "new")[1] == 17
    assert not (tmp_path / "new").exists()
    payload.unlink()
    assert investigate(config, payload.name, "export", tmp_path / "new")[1] == 13


def test_ambiguous_and_policy_block(config, tmp_path):
    record(tmp_path, name="capture-a")
    record(tmp_path, name="capture-b")
    assert investigate(config, "capture", "inspect")[1] == 1
    payload, _, _ = record(
        tmp_path, b"echo ZWNobyB1bnNhZmU= | base64 -d | bash", "flagged"
    )
    dest = tmp_path / "export"
    assert investigate(config, payload.name, "export", dest)[1] == 10
    assert not dest.exists()


def test_export_destination_race(config, tmp_path, monkeypatch):
    payload, _, _ = record(tmp_path)
    destination = tmp_path / "new"
    link = os.link

    def race(source, target, **kwargs):
        destination.write_bytes(b"racer")
        link(source, target, **kwargs)

    monkeypatch.setattr(os, "link", race)
    assert investigate(config, payload.name, "export", destination)[1] != 0
    assert destination.read_bytes() == b"racer"


def test_legacy_missing_digest_and_payload(config, tmp_path):
    payload, sidecar, original = record(tmp_path)
    original.pop("sha256")
    sidecar.write_text(json.dumps(original))
    report, code = investigate(config, payload.name, "inspect")
    assert code == 0 and report["integrity"] == "unspecified"
    assert investigate(config, payload.name, "export", tmp_path / "export")[1] == 17
    payload.unlink()
    assert investigate(config, payload.name, "rescan")[1] == 13
    updated = json.loads(sidecar.read_text())
    assert updated["rescans"][-1]["outcome"] == "unreadable"
    assert updated["timestamp"] == original["timestamp"]


def test_local_rules_are_cache_only_and_transport_is_irrelevant(
    config, tmp_path, monkeypatch
):
    path = tmp_path / "input"
    path.write_bytes(b"inert")
    config.update_url = "https://rules.example/feed"
    config.require_https = config.require_sha256 = True
    config.expected_sha256 = "0" * 64
    scanner = YaraScanner()

    def no_network(*args, **kwargs):
        pytest.fail("local scan must not access network or refresh rules")

    monkeypatch.setattr("requests.sessions.Session.request", no_network)
    monkeypatch.setattr(
        "curlguard.auto_updater.AutoUpdater.check_and_update", no_network
    )
    monkeypatch.setattr(
        "curlguard.auto_updater.AutoUpdater.load_active", lambda _: {"usable": False}
    )
    config.require_fresh_rules = True
    report, code = inspect_file(path, config, scanner)
    assert code == 13 and report["outcome"] == "unavailable"
    config.require_fresh_rules = False
    report, code = inspect_file(path, config, scanner)
    assert code == 0 and report["evidence"]["transport"] == {}


def test_unreadable_file(config, tmp_path, monkeypatch):
    path = tmp_path / "input"
    path.write_bytes(b"inert")
    original = os.open

    def denied(target, flags, *args, **kwargs):
        if target == path:
            raise PermissionError("inert permission failure")
        return original(target, flags, *args, **kwargs)

    monkeypatch.setattr(os, "open", denied)
    report, code = inspect_file(path, config, YaraScanner())
    assert code == 13 and report["sha256"] is None
