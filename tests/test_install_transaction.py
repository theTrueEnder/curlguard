"""Fault injection uses inert wrappers and isolated filesystem paths only."""

import multiprocessing
import os
from pathlib import Path
from unittest.mock import patch

import pytest

from curlguard.install_transaction import WrapperTransaction, recover_install


@pytest.fixture
def transaction(tmp_path):
    parent = tmp_path / "bin"
    parent.mkdir()
    for name in ("curl", "curlguard"):
        (parent / name).write_bytes(b"old " + name.encode())
        (parent / name).chmod(0o751)
    return WrapperTransaction(parent, "system-wide", tmp_path)


NEW = {"curl": b"new curl", "curlguard": b"new cli"}


@pytest.mark.parametrize("fresh", [False, True])
@pytest.mark.parametrize("fail_at", ["curl", "curlguard"])
def test_publication_rollback_needs_no_allocation(transaction, fresh, fail_at):
    if fresh:
        for name in NEW:
            (transaction.parent / name).unlink()
    replace = os.replace

    def failure(source, destination):
        if Path(source).suffix == ".new" and Path(destination).name == fail_at:
            raise OSError("ENOSPC")
        # Allocation fails after preparation; rollback must use existing backups.
        if Path(source).name.startswith(".curlguard-prepare-"):
            patcher.start()
        return replace(source, destination)

    patcher = patch("tempfile.mkstemp", side_effect=OSError("ENOSPC"))
    try:
        with patch("os.replace", side_effect=failure), pytest.raises(OSError):
            transaction.publish(NEW)
    finally:
        patcher.stop()
    assert not transaction.directory.exists()
    for name in NEW:
        target = transaction.parent / name
        if fresh:
            assert not target.exists()
        else:
            assert target.read_bytes() == b"old " + name.encode()
            assert target.stat().st_mode & 0o777 == 0o751


def leave_unresolved(transaction):
    replace = os.replace

    def failure(source, destination):
        if Path(source).name in {"curlguard.new", "curl.old"}:
            raise OSError("publication and rollback unavailable")
        return replace(source, destination)

    with patch("os.replace", side_effect=failure), pytest.raises(OSError):
        transaction.publish(NEW)


def test_failed_restore_retains_backup_and_is_recoverable(transaction, capsys):
    leave_unresolved(transaction)
    assert "recover-install" in capsys.readouterr().err
    assert (transaction.directory / "curl.old").read_bytes() == b"old curl"
    assert (transaction.parent / "curl").read_bytes() == NEW["curl"]
    with pytest.raises(ValueError, match="recovery required"):
        transaction.require_resolved()
    transaction.recover()
    transaction.recover()
    assert (transaction.parent / "curl").read_bytes() == b"old curl"


def test_preparation_failure_preserves_originals(transaction):
    with (
        patch(
            "curlguard.install_transaction.write_file", side_effect=OSError("ENOSPC")
        ),
        pytest.raises(OSError),
    ):
        transaction.publish(NEW)
    assert (transaction.parent / "curl").read_bytes() == b"old curl"
    assert not transaction.directory.exists()
    assert not list(transaction.parent.glob(".curlguard-prepare-*"))


def test_committed_publication_cleanup_can_be_repeated(transaction):
    with (
        patch.object(
            transaction, "_cleanup", side_effect=OSError("read-only filesystem")
        ),
        pytest.raises(OSError),
    ):
        transaction.publish(NEW)
    assert (transaction.directory / "committed").exists()
    transaction.recover()
    transaction.recover()
    assert (transaction.parent / "curl").read_bytes() == NEW["curl"]


def test_manager_blocks_install_and_uninstall_with_unresolved_transaction(
    transaction, monkeypatch
):
    from curlguard.curl_manager import CurlManager

    manager = CurlManager("system-wide", root=transaction.root)
    monkeypatch.setattr(manager, "_curl_path", transaction.parent / "curl")
    leave_unresolved(transaction)
    for operation in (manager.install, manager.uninstall):
        with pytest.raises(ValueError, match="recovery required"):
            operation()


@pytest.mark.parametrize("unsafe", ["edit", "symlink", "permissions", "backup"])
def test_unsafe_recovery_refused_without_changing_other_wrapper(transaction, unsafe):
    leave_unresolved(transaction)
    if unsafe == "edit":
        (transaction.parent / "curlguard").write_bytes(b"concurrent edit")
    elif unsafe == "symlink":
        target = transaction.parent / "curlguard"
        target.unlink()
        target.symlink_to(transaction.parent / "curl")
    elif unsafe == "permissions":
        transaction.directory.chmod(0o777)
    else:
        (transaction.directory / "curl.old").write_bytes(b"changed")
    with pytest.raises(ValueError):
        transaction.recover()
    assert (transaction.parent / "curl").read_bytes() == NEW["curl"]
    assert transaction.directory.exists()


def interrupted_publication(parent, root):
    transaction = WrapperTransaction(parent, "system-wide", root)
    replace = os.replace

    def interrupt(source, destination):
        replace(source, destination)
        if Path(source).name == "curl.new":
            os._exit(42)

    with transaction.locked(), patch("os.replace", side_effect=interrupt):
        transaction.publish(NEW)


def test_process_death_releases_lock_and_retains_durable_recovery(transaction):
    process = multiprocessing.get_context("fork").Process(
        target=interrupted_publication,
        args=(transaction.parent, transaction.root),
    )
    process.start()
    process.join(5)
    try:
        assert process.exitcode == 42
        with transaction.locked():
            transaction.recover()
        assert (transaction.parent / "curl").read_bytes() == b"old curl"
    finally:
        if process.is_alive():
            process.kill()
            process.join()


def test_recovery_cli_rejects_arbitrary_target(transaction):
    with pytest.raises(ValueError, match="outside"):
        recover_install(transaction.directory)


def test_cli_recovery_ignores_invalid_download_policy(tmp_path, monkeypatch):
    from curlguard.cli import main

    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CURLGUARD_REQUIRE_SHA256", "invalid")
    parent = tmp_path / ".local/bin"
    parent.mkdir(parents=True)
    for name in NEW:
        (parent / name).write_bytes(b"old " + name.encode())
    transaction = WrapperTransaction(parent, "per-user", tmp_path / "isolated-distro")
    leave_unresolved(transaction)
    monkeypatch.setattr(
        "sys.argv",
        [
            "curlguard",
            "recover-install",
            str(tmp_path / ".local/bin/.curlguard-transaction"),
        ],
    )
    assert main() == 0
    assert (parent / "curl").read_bytes() == b"old curl"
    assert main() == 0


def wait_for_lock(parent, root, acquired):
    transaction = WrapperTransaction(parent, "system-wide", root)
    with transaction.locked():
        acquired.set()


def test_concurrent_operation_waits_for_lock(transaction):
    context = multiprocessing.get_context("spawn")
    acquired = context.Event()
    with transaction.locked():
        process = context.Process(
            target=wait_for_lock,
            args=(transaction.parent, transaction.root, acquired),
        )
        process.start()
        assert not acquired.wait(0.2)
    try:
        assert acquired.wait(5)
        process.join(5)
        assert process.exitcode == 0
    finally:
        if process.is_alive():
            process.kill()
            process.join()
