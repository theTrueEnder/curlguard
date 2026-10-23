"""Quarantine inspection helpers for curlguard."""

import json
import os
import tempfile
from dataclasses import dataclass
from datetime import datetime, timezone
from pathlib import Path


@dataclass
class QuarantineEntry:
    payload_path: Path
    metadata_path: Path
    timestamp: str | None
    url: str
    rules_triggered: list[str]
    sha256: str | None
    size_bytes: int | None

    @property
    def identifier(self) -> str:
        return self.payload_path.name

    @property
    def host(self) -> str:
        from urllib.parse import urlparse

        return urlparse(self.url).hostname or ""


def list_entries(quarantine_dir: Path) -> list[QuarantineEntry]:
    entries: list[QuarantineEntry] = []
    if not quarantine_dir.exists():
        return entries

    for metadata_path in sorted(
        quarantine_dir.glob("*.json"),
        key=lambda path: path.stat().st_mtime,
        reverse=True,
    ):
        entry = _load_entry(metadata_path)
        if entry is not None:
            entries.append(entry)
    return entries


def resolve_entry(quarantine_dir: Path, identifier: str) -> QuarantineEntry | None:
    candidate = Path(identifier).expanduser()
    if candidate.exists():
        metadata_path = (
            candidate if candidate.suffix == ".json" else _metadata_path_for(candidate)
        )
        return _load_entry(metadata_path)

    matches = [
        entry
        for entry in list_entries(quarantine_dir)
        if entry.identifier == identifier
        or entry.metadata_path.name == identifier
        or entry.identifier.startswith(identifier)
    ]
    if len(matches) == 1:
        return matches[0]
    return None


def format_size(size_bytes: int | None) -> str:
    if size_bytes is None:
        return "unknown"
    return f"{size_bytes} bytes"


def format_timestamp(timestamp: str | None) -> str:
    if not timestamp:
        return "unknown"
    try:
        return (
            datetime.fromisoformat(timestamp)
            .astimezone()
            .strftime("%Y-%m-%d %H:%M:%S %Z")
        )
    except ValueError:
        return timestamp


def _load_entry(metadata_path: Path) -> QuarantineEntry | None:
    if not metadata_path.exists():
        return None

    try:
        payload = json.loads(metadata_path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError):
        return None

    if not isinstance(payload, dict):
        return None

    payload_path = _payload_path_for(metadata_path)
    return QuarantineEntry(
        payload_path=payload_path,
        metadata_path=metadata_path,
        timestamp=_string_or_none(payload.get("timestamp")),
        url=_string_or_none(payload.get("url")) or "",
        rules_triggered=_string_list(payload.get("rules_triggered")),
        sha256=_string_or_none(payload.get("sha256")),
        size_bytes=_int_or_none(payload.get("size_bytes")),
    )


def _payload_path_for(metadata_path: Path) -> Path:
    if metadata_path.name.endswith(".json"):
        return metadata_path.with_name(metadata_path.name[:-5])
    return metadata_path


def _metadata_path_for(payload_path: Path) -> Path:
    return payload_path.with_name(f"{payload_path.name}.json")


def _string_or_none(value) -> str | None:
    if value is None:
        return None
    text = str(value).strip()
    return text or None


def _string_list(value) -> list[str]:
    if not isinstance(value, list):
        return []
    return [str(item) for item in value if str(item).strip()]


def _int_or_none(value) -> int | None:
    if value is None:
        return None
    try:
        return int(value)
    except (TypeError, ValueError):
        return None


def investigate(config, identifier, command, destination=None):
    report, code = _investigate(config, identifier, command, destination)
    report["exit_code"] = code
    return report, code


def _investigate(config, identifier, command, destination=None):
    """Retain capture fields; append independently identified current inspections."""
    import fcntl

    from curlguard.inspection import InspectionError, inspect_file, snapshot
    from curlguard.scanner import YaraScanner

    entry = resolve_entry(config.quarantine_dir, identifier)
    report = {"schema_version": 1, "kind": "quarantine", "command": command}
    if entry is None:
        return {**report, "outcome": "missing_or_ambiguous"}, 1
    try:
        fd = os.open(
            str(entry.metadata_path) + ".lock",
            os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
            0o600,
        )
        with os.fdopen(fd, "r+") as lock:
            fcntl.flock(lock, fcntl.LOCK_EX)
            raw = json.loads(entry.metadata_path.read_text(encoding="utf-8"))
            expected = raw.get("sha256")
            report.update(identifier=entry.identifier, capture=raw)
            if command == "inspect":
                with snapshot(entry.payload_path, config.max_scan_bytes) as (
                    _,
                    facts,
                    unchanged,
                ):
                    if not unchanged():
                        raise InspectionError("changed")
                    integrity = (
                        "unspecified"
                        if not expected
                        else "matched"
                        if expected == facts["sha256"]
                        else "mismatched"
                    )
                    report.update(**facts, integrity=integrity, outcome="inspected")
                    return report, 17 if integrity == "mismatched" else 0
            if command == "export" and not expected:
                return {**report, "outcome": "missing_stored_digest"}, 17
            scanner = YaraScanner(
                config.rules_dirs,
                timeout=config.scan_timeout_seconds,
                max_bytes=config.max_scan_bytes,
            )
            result, code = inspect_file(
                entry.payload_path,
                config,
                scanner,
                destination=destination,
                expected=expected,
            )
            report["inspection"] = result
            if command == "rescan":
                history = raw.setdefault("rescans", [])
                if not isinstance(history, list):
                    raise ValueError("invalid quarantine rescan history")
                history.append(
                    {"timestamp": datetime.now(timezone.utc).isoformat(), **result}
                )
                fd, name = tempfile.mkstemp(
                    prefix=".rescan-", dir=entry.metadata_path.parent
                )
                try:
                    with os.fdopen(fd, "w") as out:
                        json.dump(raw, out, sort_keys=True)
                        out.flush()
                        os.fsync(out.fileno())
                    os.replace(name, entry.metadata_path)
                finally:
                    Path(name).unlink(missing_ok=True)
            return report, code
    except InspectionError as exc:
        return {
            **report,
            "outcome": exc.outcome,
        }, 17 if exc.outcome == "changed" else 13
    except (OSError, ValueError):
        return {**report, "outcome": "unreadable"}, 13
