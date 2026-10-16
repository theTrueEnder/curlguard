"""Best-effort JSONL logging, serialized across processes during append/rotation."""

import json
import os
import sys
import threading
from dataclasses import asdict, dataclass, field
from pathlib import Path
from urllib.parse import parse_qsl, urlencode, urlsplit, urlunsplit


def redact_url(url):
    try:
        p = urlsplit(url)
        host = p.netloc.rsplit("@", 1)[-1]
        return urlunsplit(
            (
                p.scheme,
                host,
                p.path,
                urlencode(
                    [
                        (k, "[redacted]")
                        for k, _ in parse_qsl(p.query, keep_blank_values=True)
                    ]
                ),
                "",
            )
        )
    except ValueError:
        return "[invalid URL]"


@dataclass
class AuditEvent:
    timestamp: str
    url: str
    destination: str | None
    scan_result: str
    rules_triggered: list = field(default_factory=list)
    user_decision: str | None = None
    decision_reason: str | None = None
    ssl_bypass_detected: bool = False
    content_sha256: str | None = None
    content_size_bytes: int | None = None
    quarantine_path: str | None = None
    duration_ms: float = 0.0
    exit_code: int = 0
    stage: str | None = None
    error_category: str | None = None
    interception_reason: str | None = None
    effective_url: str | None = None
    ruleset_id: str | None = None


class AuditLogger:
    MAX_SIZE_BYTES = 10 * 1024 * 1024
    MAX_BACKUPS = 5

    def __init__(self, log_path: Path):
        self._path = Path(log_path)
        self._lock = threading.Lock()
        self._warned = False

    def log(self, event):
        try:
            import fcntl

            data = asdict(event)
            data["url"] = redact_url(data["url"])
            if data["effective_url"]:
                data["effective_url"] = redact_url(data["effective_url"])
            with self._lock:
                self._path.parent.mkdir(parents=True, exist_ok=True)
                if self._path.is_symlink():
                    raise OSError("audit path must not be a symlink")
                fd = os.open(
                    str(self._path) + ".lock",
                    os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW,
                    0o600,
                )
                with os.fdopen(fd, "a") as lock:
                    fcntl.flock(lock, fcntl.LOCK_EX)
                    if (
                        self._path.exists()
                        and self._path.stat().st_size >= self.MAX_SIZE_BYTES
                    ):
                        for i in range(self.MAX_BACKUPS - 1, 0, -1):
                            src = self._path.with_suffix(f".{i}")
                            if src.exists():
                                src.replace(self._path.with_suffix(f".{i + 1}"))
                        self._path.replace(self._path.with_suffix(".1"))
                    out = os.open(
                        self._path,
                        os.O_CREAT | os.O_APPEND | os.O_WRONLY | os.O_NOFOLLOW,
                        0o600,
                    )
                    with os.fdopen(out, "a") as handle:
                        handle.write(json.dumps(data) + "\n")
        except (OSError, ImportError, TypeError, ValueError) as exc:
            if not self._warned:
                print(
                    f"curlguard: audit logging unavailable ({type(exc).__name__})",
                    file=sys.stderr,
                )
                self._warned = True

    def close(self):
        pass

    def __enter__(self):
        return self

    def __exit__(self, *args):
        self.close()
