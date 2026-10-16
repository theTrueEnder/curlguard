import errno
import hashlib
import json
import multiprocessing
import os
import subprocess
import sys
from pathlib import Path
from unittest.mock import patch

import pytest

from curlguard.config import CurlGuardConfig, load_config
from curlguard.curl_manager import CurlManager
from curlguard.logger import AuditEvent, AuditLogger
from curlguard.scanner import YaraScanner
from curlguard.ssl_detector import SslBypassDetector
from curlguard.wrapper import CurlWrapper


@pytest.mark.parametrize("terminal", [False, True])
def test_subprocess_terminal_and_process_group(monkeypatch, terminal):
    from curlguard.process import run

    monkeypatch.setattr(os, "isatty", lambda fd: terminal)
    p = run(
        [sys.executable, "-c", "import os; print(os.getpgrp())"], stdout=subprocess.PIPE
    )
    assert p.returncode == 0
    assert (int(p.stdout.strip()) == os.getpgrp()) == terminal


@pytest.fixture
def wrapper(tmp_path):
    config = CurlGuardConfig(
        "per-user",
        tmp_path / "audit.log",
        quarantine_dir=tmp_path / "quarantine",
        real_curl_path=Path(os.environ.get("CURLGUARD_TEST_CURL", "/usr/bin/curl")),
    )
    return CurlWrapper(
        config, YaraScanner(), AuditLogger(config.log_path), SslBypassDetector()
    )


def test_installer_snapshots_are_clean():
    directory = Path(__file__).parent / "fixtures/installers"
    manifest = json.loads((directory / "manifest.json").read_text())
    scanner = YaraScanner()
    for name, metadata in manifest["files"].items():
        path = directory / name
        assert hashlib.sha256(path.read_bytes()).hexdigest() == metadata["sha256"]
        result = scanner.scan_file(path)
        assert result.status == "clean", (name, result)


@pytest.mark.parametrize(
    "body",
    [
        b"echo abc | base64 -d | bash",
        b'eval "$(echo abc | base64 --decode)"',
        b"openssl base64 -d | sh",
    ],
)
def test_encoded_execution_stays_flagged(body):
    assert "base64_encoded_shell" in YaraScanner().scan(body).rules_triggered


def test_empty_user_rules_keep_builtin_protection(tmp_path):
    tmp_path.joinpath("rules").mkdir()
    scanner = YaraScanner([tmp_path / "rules"])
    assert scanner.scan(b"echo abc | base64 -d | bash").status == "flagged"


def test_missing_yara_is_explicit():
    with patch.dict("sys.modules", {"yara": None}):
        result = YaraScanner().scan(b"hello")
    assert result.status == "unavailable"
    assert not result.clean


def test_invalid_reload_preserves_rules(tmp_path):
    scanner = YaraScanner([tmp_path])
    identity = scanner.ruleset_id
    (tmp_path / "bad.yar").write_text("not valid yara")
    scanner.reload_rules()
    assert scanner.ruleset_id == identity
    assert scanner.scan(b"base64 -d | sh").status == "flagged"


def test_scan_timeout_has_failure_status():
    import yara

    scanner = YaraScanner()
    with patch.object(scanner, "_rules") as rules:
        rules.match.side_effect = yara.TimeoutError("timed out")
        assert scanner.scan(b"hello").status == "error"
        assert rules.match.call_args.kwargs["timeout"] == 10


@pytest.mark.parametrize(
    "name,value",
    [
        ("CURLGUARD_MATCH_POLICY", "typo"),
        ("CURLGUARD_UNSUPPORTED_POLICY", "typo"),
        ("CURLGUARD_SCAN_FAILURE_MODE", "typo"),
        ("CURLGUARD_SCAN_TIMEOUT_SECONDS", "0"),
        ("CURLGUARD_MAX_SCAN_BYTES", "-1"),
        ("CURLGUARD_UPDATE_INTERVAL_HOURS", "nan"),
        ("CURLGUARD_SSL_WARN_ONLY", "yes"),
        ("CURLGUARD_MODE", "typo"),
        ("CURLGUARD_TRUSTED_SHA256", "abc"),
    ],
)
def test_bad_configuration(name, value, monkeypatch, tmp_path):
    monkeypatch.setenv("CURLGUARD_TRUST_FILE", str(tmp_path / "missing"))
    monkeypatch.setenv(name, value)
    with pytest.raises(ValueError):
        load_config()


@pytest.mark.parametrize(
    "value", ["{", "[]", '{"hosts":"oops"}', '{"sha256":["oops"]}']
)
def test_malformed_trust_file(value, monkeypatch, tmp_path):
    path = tmp_path / "trust.json"
    path.write_text(value)
    monkeypatch.setenv("CURLGUARD_TRUST_FILE", str(path))
    with pytest.raises(ValueError):
        load_config()


def test_destination_changed_during_scan(wrapper, http_server, tmp_path):
    url, _, _ = http_server
    dest = tmp_path / "out"
    dest.write_bytes(b"original")
    original_scan = wrapper._scanner.scan_file

    def scan(path):
        dest.write_bytes(b"changed concurrently")
        return original_scan(path)

    wrapper._scanner.scan_file = scan
    assert wrapper.dispatch(["-q", "-o", str(dest), url + "/artifact"]) == 16
    assert dest.read_bytes() == b"changed concurrently"
    assert not list(tmp_path.glob(".curlguard-*"))


def test_disk_exhaustion_before_fetch(wrapper, http_server, monkeypatch):
    url, requests, _ = http_server

    def fail(*args):
        raise OSError(errno.ENOSPC, "disk full")

    monkeypatch.setattr(wrapper, "_temp", fail)
    assert wrapper.dispatch(["-q", url + "/artifact"]) == 16
    assert requests == []


def test_atomic_replace_failure_preserves_file_and_etag(
    wrapper, http_server, tmp_path, monkeypatch
):
    url, _, _ = http_server
    dest, etag = tmp_path / "out", tmp_path / "tag"
    dest.write_bytes(b"old payload")
    etag.write_bytes(b"old tag")
    replace = os.replace

    def fail_payload(src, dst):
        if Path(dst) == dest:
            raise PermissionError("cannot replace destination")
        return replace(src, dst)

    monkeypatch.setattr(os, "replace", fail_payload)
    assert (
        wrapper.dispatch(
            ["-q", "-o", str(dest), "--etag-save", str(etag), url + "/conditional"]
        )
        == 16
    )
    assert dest.read_bytes() == b"old payload"
    assert etag.read_bytes() == b"old tag"


def test_quarantine_failure_does_not_deliver(wrapper, http_server, tmp_path, capfd):
    url, _, _ = http_server
    wrapper._config.quarantine_dir.write_text("not a directory")
    dest = tmp_path / "out"
    dest.write_bytes(b"original")
    assert wrapper.dispatch(["-q", "-o", str(dest), url + "/malware"]) == 16
    assert capfd.readouterr().out == ""
    assert dest.read_bytes() == b"original"


def test_unwritable_log_does_not_change_result(wrapper, http_server, tmp_path, capfd):
    url, _, _ = http_server
    parent = tmp_path / "file"
    parent.write_text("not a directory")
    wrapper._logger = AuditLogger(parent / "audit.log")
    dest = tmp_path / "out"
    assert wrapper.dispatch(["-q", "-o", str(dest), url + "/empty"]) == 0
    assert "logging unavailable" in capfd.readouterr().err


def test_redirect_host_trust_requires_both_hosts(wrapper):
    wrapper._config.trusted_hosts = {"trusted.example"}
    wrapper._effective_url = "https://untrusted.example/payload"
    assert wrapper._get_trust_reason("https://trusted.example/a", "a" * 64) is None
    wrapper._effective_url = "https://cdn.trusted.example/payload"
    assert (
        wrapper._get_trust_reason("https://trusted.example/a", "a" * 64)
        == "trusted host"
    )


def test_audit_redacts_credentials_and_query(tmp_path):
    path = tmp_path / "audit.log"
    AuditLogger(path).log(
        AuditEvent(
            "now",
            "https://user:secret@example.com/a?token=secret",
            None,
            "skipped",
            effective_url="https://user:secret@cdn.example/a?q=secret",
        )
    )
    text = path.read_text()
    assert "secret" not in text
    assert "user:" not in text
    assert "redacted" in text


def _log_worker(path, number):
    log = AuditLogger(Path(path))
    log.MAX_SIZE_BYTES = 1000
    log.MAX_BACKUPS = 50
    for i in range(12):
        log.log(AuditEvent(f"{number}:{i}", "https://example.com", None, "clean"))


def test_concurrent_log_rotation(tmp_path):
    path = tmp_path / "audit.log"
    processes = [
        multiprocessing.Process(target=_log_worker, args=(str(path), n))
        for n in range(3)
    ]
    for p in processes:
        p.start()
    for p in processes:
        p.join(10)
        assert p.exitcode == 0
    events = []
    for p in tmp_path.glob("audit.*"):
        if p.suffix != ".lock":
            events.extend(json.loads(line) for line in p.read_text().splitlines())
    assert len(events) == 36
    assert len({e["timestamp"] for e in events}) == 36


def test_old_curl_metadata_fallback(wrapper, http_server, tmp_path, monkeypatch):
    url, requests, _ = http_server
    monkeypatch.setattr(wrapper, "_metadata_supported", lambda: False)
    wrapper._config.unsupported_policy = "block"
    assert wrapper.dispatch(["-q", url + "/empty"]) == 14
    assert not requests
    wrapper._config.unsupported_policy = "passthrough"
    assert wrapper.dispatch(["-q", "-o", str(tmp_path / "out"), url + "/empty"]) == 0


def test_missing_binary_and_recursion(wrapper, tmp_path):
    wrapper._config.real_curl_path = tmp_path / "missing"
    assert wrapper.dispatch(["https://example.com"]) == 16
    wrapper._config.real_curl_path.write_text('#!/bin/sh\nexec curlguard "$@"\n')
    assert wrapper.dispatch(["https://example.com"]) == 15


def test_system_wrapper_uses_writable_user_state(monkeypatch, tmp_path):
    monkeypatch.setenv("CURLGUARD_MODE", "system-wide")
    monkeypatch.setattr("pathlib.Path.home", lambda: tmp_path)
    monkeypatch.setattr(os, "geteuid", lambda: 1000)
    for key in (
        "CURLGUARD_LOG_PATH",
        "CURLGUARD_QUARANTINE",
        "CURLGUARD_TRUST_FILE",
        "CURLGUARD_RULES_DIR",
    ):
        monkeypatch.delenv(key, raising=False)
    config = load_config()
    assert config.log_path == tmp_path / ".curlguard/audit.log"
    assert config.quarantine_dir == tmp_path / ".curlguard/quarantine"
    assert Path("/var/lib/curlguard/rules") in config.rules_dirs


def test_blocked_unsupported_does_not_fetch_rule_updates(wrapper):
    wrapper._config.update_url = "https://rules.example/update"
    wrapper._config.unsupported_policy = "block"
    with patch("curlguard.auto_updater.AutoUpdater.check_and_update") as updater:
        assert wrapper.dispatch(["--unknown", "https://example.com"]) == 14
    updater.assert_not_called()


def test_custom_update_cache_is_included_on_next_start(monkeypatch, tmp_path):
    monkeypatch.setenv("CURLGUARD_QUARANTINE", str(tmp_path / "custom/quarantine"))
    monkeypatch.setenv("CURLGUARD_UPDATE_URL", "https://rules.example/update")
    monkeypatch.setenv("CURLGUARD_RULES_DIR", str(tmp_path / "other-rules"))
    monkeypatch.setenv("CURLGUARD_TRUST_FILE", str(tmp_path / "missing"))
    assert tmp_path / "custom/rules" in load_config().rules_dirs


def test_install_remove_and_package_replacement(tmp_path):
    real = tmp_path / "usr/bin/curl"
    real.parent.mkdir(parents=True)
    real.write_bytes(b"\x7fELF old curl")
    manager = CurlManager("system-wide", root=tmp_path)
    manager.install()
    manager.install()
    assert manager.is_installed()
    wrapper_content = manager._curl_path.read_bytes()
    real.write_bytes(b"\x7fELF upgraded curl")
    assert manager._curl_path.read_bytes() == wrapper_content
    manager.uninstall()
    manager.uninstall()
    assert real.read_bytes() == b"\x7fELF upgraded curl"


def test_install_remove_refuse_unrelated_files(tmp_path):
    real = tmp_path / "usr/bin/curl"
    real.parent.mkdir(parents=True)
    real.write_bytes(b"\x7fELF curl")
    manager = CurlManager("system-wide", root=tmp_path)
    manager._curl_path.parent.mkdir(parents=True)
    manager._curl_path.write_text("unrelated tool")
    for operation in (manager.install, manager.uninstall):
        with pytest.raises(ValueError, match="unrelated"):
            operation()
    assert manager._curl_path.read_text() == "unrelated tool"


def test_legacy_never_restores_stale_binary(tmp_path):
    real = tmp_path / "usr/bin/curl"
    real.parent.mkdir(parents=True)
    real.write_bytes(b"\x7fELF new curl")
    real.with_name("curl.real").write_bytes(b"\x7fELF stale curl")
    manager = CurlManager("system-wide", root=tmp_path)
    with pytest.raises(ValueError, match="migrate-legacy"):
        manager.install()
    with pytest.raises(ValueError, match="stale"):
        manager.uninstall()
    with pytest.raises(ValueError, match="real distro root"):
        manager.install(migrate_legacy=True)
    assert real.read_bytes() == b"\x7fELF new curl"
    assert (
        next(
            (tmp_path / "var/lib/curlguard").glob("legacy-backup-*/curl.real")
        ).read_bytes()
        == b"\x7fELF stale curl"
    )


@pytest.mark.parametrize("interrupted", [False, True])
def test_legacy_migration_package_repair(tmp_path, monkeypatch, interrupted):
    import curlguard.curl_manager as module

    system = tmp_path / "usr/bin/curl"
    system.parent.mkdir(parents=True)
    system.write_bytes(
        b'#!/bin/sh\nexport CURLGUARD_REAL_CURL_PATH=/usr/bin/curl.real\nexec curlguard "$@"\n'
    )
    saved = system.with_name("curl.real")
    saved.write_bytes(b"\x7fELF stale curl")
    manager = CurlManager("system-wide", root=tmp_path)
    metadata = tmp_path / "var/lib/dpkg/info/curl.md5sums"
    metadata.parent.mkdir(parents=True)
    # Map only the production root guard and distro metadata path. No real APT
    # command is run, even if this test is accidentally executed as root.
    real_path = Path

    def mapped_path(value):
        if str(value) == "/":
            return tmp_path
        if str(value) == "/var/lib/dpkg/info/curl.md5sums":
            return metadata
        return real_path(value)

    monkeypatch.setattr(module, "Path", mapped_path)

    def package_command(command, **kwargs):
        if command[0].endswith("dpkg-query"):
            return subprocess.CompletedProcess(
                command, 0, stdout="curl: /usr/bin/curl\n"
            )
        assert command == ["/usr/bin/apt-get", "install", "--reinstall", "-y", "curl"]
        system.write_bytes(b"\x7fELF current verified package")
        metadata.write_text(
            hashlib.md5(system.read_bytes(), usedforsecurity=False).hexdigest()
            + "  usr/bin/curl\n"
        )
        if interrupted:
            raise KeyboardInterrupt
        return subprocess.CompletedProcess(command, 0)

    monkeypatch.setattr(module.subprocess, "run", package_command)
    if interrupted:
        with pytest.raises(KeyboardInterrupt):
            manager.install(migrate_legacy=True)
        assert saved.exists()
        assert not manager._curl_path.exists()
    else:
        manager.install(migrate_legacy=True)
        assert not saved.exists()
        assert manager.is_installed()
    assert system.read_bytes() == b"\x7fELF current verified package"
    assert (
        next(
            (tmp_path / "var/lib/curlguard").glob("legacy-backup-*/curl.real")
        ).read_bytes()
        == b"\x7fELF stale curl"
    )
