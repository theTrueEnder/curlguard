"""Durable wrapper publication and recovery, independent of download policy."""

import fcntl
import hashlib
import json
import os
import shlex
import shutil
import stat
import sys
import tempfile
import uuid
from contextlib import contextmanager
from pathlib import Path


def fingerprint(path):
    if path.is_symlink():
        raise ValueError(f"refusing symlink: {path}")
    return hashlib.sha256(path.read_bytes()).hexdigest() if path.exists() else None


def flush_directory(path):
    fd = os.open(path, os.O_RDONLY | os.O_DIRECTORY)
    try:
        os.fsync(fd)
    finally:
        os.close(fd)


def write_file(path, content, mode):
    with path.open("xb") as handle:
        handle.write(content)
        os.fchmod(handle.fileno(), mode)
        handle.flush()
        os.fsync(handle.fileno())


class WrapperTransaction:
    def __init__(self, parent, mode, root):
        self.parent, self.mode, self.root = Path(parent), mode, Path(root)
        self.directory = self.parent / ".curlguard-transaction"

    @contextmanager
    def locked(self):
        self.parent.mkdir(parents=True, exist_ok=True)
        for parent in (self.parent, *self.parent.parents):
            info = parent.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or info.st_uid not in {0, os.geteuid()}
                or (info.st_mode & 0o022 and not info.st_mode & stat.S_ISVTX)
            ):
                raise ValueError("unsafe wrapper directory ownership/permissions")
        lock = self.parent / ".curlguard-install.lock"
        fd = os.open(lock, os.O_RDWR | os.O_CREAT | os.O_NOFOLLOW, 0o600)
        try:
            info = os.fstat(fd)
            if (
                info.st_uid != os.geteuid()
                or not stat.S_ISREG(info.st_mode)
                or info.st_mode & 0o077
            ):
                raise ValueError("unsafe installation lock ownership or type")
            fcntl.flock(fd, fcntl.LOCK_EX)
            yield
        finally:
            os.close(fd)

    def require_resolved(self):
        if self.directory.exists() or self.directory.is_symlink():
            raise ValueError(f"installation recovery required: {self.directory}")

    def publish(self, scripts):
        self.require_resolved()
        # Unpublished preparation can be discarded. The durable directory is only
        # exposed once every original backup and replacement is ready.
        stage = Path(tempfile.mkdtemp(prefix=".curlguard-prepare-", dir=self.parent))
        prepared = False
        try:
            records = {}
            for name, content in scripts.items():
                target = self.parent / name
                old = fingerprint(target)
                record = {"old": old, "new": hashlib.sha256(content).hexdigest()}
                if old is not None:
                    write_file(
                        stage / (name + ".old"),
                        target.read_bytes(),
                        stat.S_IMODE(target.stat().st_mode),
                    )
                write_file(stage / (name + ".new"), content, 0o755)
                records[name] = record
            journal = {
                "schema_version": 1,
                "mode": self.mode,
                "root": str(self.root),
                "runtime_python": os.path.abspath(sys.executable),
                "wrappers": records,
            }
            write_file(stage / "journal.json", json.dumps(journal).encode(), 0o600)
            flush_directory(stage)
            os.replace(stage, self.directory)
            prepared = True
            flush_directory(self.parent)
            try:
                for name, record in records.items():
                    target = self.parent / name
                    if fingerprint(target) != record["old"]:
                        raise ValueError(
                            f"wrapper changed during installation: {target}"
                        )
                    os.replace(self.directory / (name + ".new"), target)
                    flush_directory(self.parent)
                # A durable commit marker distinguishes successful publication
                # from an interrupted pair update. Recovery can finalize cleanup.
                write_file(self.directory / "committed", b"committed\n", 0o600)
                flush_directory(self.directory)
            except BaseException:
                try:
                    self.recover()
                except BaseException as recovery_error:
                    command = (
                        f"{shlex.quote(journal['runtime_python'])} -I -m curlguard.cli "
                        f"recover-install {shlex.quote(str(self.directory))}"
                    )
                    print(
                        f"curlguard: recovery incomplete ({recovery_error}); "
                        f"runtime retained. Recover with: {command}",
                        file=sys.stderr,
                    )
                raise
            self._cleanup()
        finally:
            if not prepared:
                shutil.rmtree(stage, ignore_errors=True)

    def _load(self):
        for path in (self.directory, self.directory / "journal.json"):
            info = path.lstat()
            if (
                stat.S_ISLNK(info.st_mode)
                or info.st_uid != os.geteuid()
                or info.st_mode & 0o077
            ):
                raise ValueError(
                    "unsafe installation transaction ownership/permissions"
                )
        journal = json.loads((self.directory / "journal.json").read_text())
        if (
            not isinstance(journal, dict)
            or journal.get("schema_version") != 1
            or journal.get("mode") != self.mode
            or journal.get("root") != str(self.root)
            or not isinstance(journal.get("wrappers"), dict)
            or set(journal["wrappers"]) != {"curl", "curlguard"}
        ):
            raise ValueError("invalid installation transaction")
        for record in journal["wrappers"].values():
            if not isinstance(record, dict) or set(record) != {"old", "new"}:
                raise ValueError("invalid wrapper record")
            for key in ("old", "new"):
                value = record.get(key)
                if value is None and key == "old":
                    continue
                if not isinstance(value, str) or len(value) != 64:
                    raise ValueError("invalid wrapper fingerprint")
                try:
                    bytes.fromhex(value)
                except ValueError as exc:
                    raise ValueError("invalid wrapper fingerprint") from exc
        return journal

    def recover(self):
        if not self.directory.exists() and not self.directory.is_symlink():
            return
        journal = self._load()
        committed = self.directory / "committed"
        if committed.is_symlink():
            raise ValueError("unsafe transaction commit marker")
        final = committed.exists()
        # Validate the entire pair before mutating either path.
        for name, record in journal["wrappers"].items():
            current = fingerprint(self.parent / name)
            if current not in (record["new"], record["old"]):
                raise ValueError(f"wrapper changed; recovery refused: {name}")
            if final and current != record["new"]:
                raise ValueError("committed wrapper changed; recovery refused")
            if not final and current != record["old"] and record["old"] is not None:
                if fingerprint(self.directory / (name + ".old")) != record["old"]:
                    raise ValueError("missing or changed rollback backup")
        if not final:
            for name, record in journal["wrappers"].items():
                target = self.parent / name
                if fingerprint(target) == record["old"]:
                    continue
                if record["old"] is None:
                    target.unlink()
                else:
                    os.replace(self.directory / (name + ".old"), target)
                flush_directory(self.parent)
        self._cleanup()

    def _cleanup(self):
        # Rename first: interruption during removal cannot leave a partially
        # deleted journal blocking later installs or needing lost backups.
        garbage = self.parent / (".curlguard-completed-" + uuid.uuid4().hex)
        os.replace(self.directory, garbage)
        flush_directory(self.parent)
        shutil.rmtree(garbage)


def recover_install(path):
    """Recover only the fixed production wrapper directory for the journal mode."""
    from curlguard.curl_manager import CurlManager

    path = Path(path).absolute()
    # Determine mode from the fixed path, not from untrusted journal paths.
    for mode in ("per-user", "system-wide"):
        manager = CurlManager(mode)
        transaction = manager.transaction
        if path == transaction.directory:
            with transaction.locked():
                transaction.recover()
            return
    raise ValueError("transaction is outside the permitted wrapper directories")
