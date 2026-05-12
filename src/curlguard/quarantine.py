"""Quarantine inspection helpers for curlguard."""
import json
from dataclasses import dataclass
from datetime import datetime
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
        metadata_path = candidate if candidate.suffix == ".json" else _metadata_path_for(candidate)
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
        return datetime.fromisoformat(timestamp).astimezone().strftime("%Y-%m-%d %H:%M:%S %Z")
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
