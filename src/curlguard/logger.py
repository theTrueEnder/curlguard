"""Audit logger module for curlguard."""
import json
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path


@dataclass
class AuditEvent:
    timestamp: str
    url: str
    destination: str | None
    scan_result: str  # "clean" | "flagged" | "unavailable" | "error" | "skipped"
    rules_triggered: list = field(default_factory=list)
    user_decision: str | None = None  # "block" | "quarantine" | "allow" | None
    decision_reason: str | None = None
    ssl_bypass_detected: bool = False
    content_sha256: str | None = None
    content_size_bytes: int | None = None
    quarantine_path: str | None = None
    duration_ms: float = 0.0
    exit_code: int = 0


class AuditLogger:
    MAX_SIZE_BYTES = 10 * 1024 * 1024  # 10MB
    MAX_BACKUPS = 5

    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._lock = threading.Lock()
        log_path.parent.mkdir(parents=True, exist_ok=True)
        self._file = open(log_path, "a", buffering=1)

    def log(self, event: AuditEvent) -> None:
        with self._lock:
            if self._should_rotate():
                self._rotate()
            line = json.dumps(asdict(event))
            self._file.write(line + "\n")
            self._file.flush()

    def _should_rotate(self) -> bool:
        try:
            return self._path.stat().st_size >= self.MAX_SIZE_BYTES
        except OSError:
            return False

    def _rotate(self) -> None:
        self._file.close()
        # Shift existing backups
        for i in range(self.MAX_BACKUPS - 1, 0, -1):
            src = self._path.with_suffix(f".{i}")
            dst = self._path.with_suffix(f".{i + 1}")
            if src.exists():
                src.rename(dst)
        # Rename current to .1
        self._path.rename(self._path.with_suffix(".1"))
        self._file = open(self._path, "w")

    def close(self) -> None:
        with self._lock:
            self._file.flush()
            self._file.close()

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *args) -> None:
        self.close()
