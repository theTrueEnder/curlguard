"""Append-only, privacy-aware audit logging for curlguard."""

import json
import os
import sys
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import urlsplit, urlunsplit


@dataclass
class AuditEvent:
    timestamp: str
    url: str
    destination: str | None
    scan_result: str
    rules_triggered: list = field(default_factory=list)
    user_decision: str | None = None
    ssl_bypass_detected: bool = False
    duration_ms: float = 0.0
    exit_code: int = 0


def _redact_url(url: str) -> str:
    """Remove credentials, query parameters, and fragments from logged URLs."""

    try:
        parsed = urlsplit(url)
        if not parsed.scheme or not parsed.hostname:
            return url
        hostname = parsed.hostname
        if ":" in hostname and not hostname.startswith("["):
            hostname = f"[{hostname}]"
        netloc = hostname
        if parsed.port is not None:
            netloc = f"{netloc}:{parsed.port}"
        return urlunsplit((parsed.scheme, netloc, parsed.path, "", ""))
    except (TypeError, ValueError):
        return "<redacted-invalid-url>"


class AuditLogger:
    """Write one O_APPEND record per event; leave rotation to the host OS."""

    def __init__(self, log_path: Path) -> None:
        self._path = log_path
        self._lock = threading.Lock()
        self._fd: int | None = None
        try:
            log_path.parent.mkdir(parents=True, exist_ok=True)
            self._fd = os.open(
                log_path,
                os.O_APPEND | os.O_CREAT | os.O_WRONLY,
                0o600,
            )
            try:
                os.chmod(log_path, 0o600)
            except OSError:
                pass
        except OSError as exc:
            print(
                f"curlguard: audit logging unavailable at {log_path}: {exc}",
                file=sys.stderr,
            )

    def log(self, event: AuditEvent) -> None:
        if self._fd is None:
            return
        payload = asdict(event)
        payload["url"] = _redact_url(event.url)
        line = (json.dumps(payload, separators=(",", ":")) + "\n").encode("utf-8")
        with self._lock:
            try:
                os.write(self._fd, line)
            except OSError as exc:
                print(f"curlguard: audit log write failed: {exc}", file=sys.stderr)

    def close(self) -> None:
        with self._lock:
            if self._fd is not None:
                os.close(self._fd)
                self._fd = None

    def __enter__(self) -> "AuditLogger":
        return self

    def __exit__(self, *args) -> None:
        self.close()
