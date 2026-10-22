"""Invocation-local state, separate from immutable runtime configuration."""

from dataclasses import dataclass, field
from pathlib import Path

from curlguard.arguments import Request
from curlguard.evidence import Evidence


@dataclass
class TransferState:
    request: Request | None = None
    stage: str = "prepare"
    temporary: list[Path] = field(default_factory=list)
    effective_url: str = ""
    facts: dict = field(default_factory=dict)
    status: str = "skipped"
    decision: str | None = None
    rules: list[str] = field(default_factory=list)
    quarantined: str | None = None
    bypass: bool = False
    error: str | None = None
    reason: str | None = None
    writeout: bytes = b""
    snapshot: tuple | None = None
    etag_snapshot: tuple | None = None
    etag: Path | None = None
    metadata: dict = field(default_factory=dict)
    expected: str | None = None
    transport_options: list[str] = field(default_factory=list)
    publisher: dict | None = None
    evidence: Evidence = field(default_factory=Evidence)
