"""Independent evidence and stable decisions for staged downloads."""

import re
from dataclasses import asdict, dataclass, field


def safe_text(value):
    """Escape terminal controls; renderers must additionally disable markup."""
    return re.sub(r"[\x00-\x1f\x7f-\x9f]", lambda m: f"\\x{ord(m[0]):02x}", str(value))


@dataclass
class Finding:
    rule: str
    namespace: str = ""
    description: str = "Unclassified rule match"
    severity: str = "high"
    confidence: str = "unknown"
    category: str = "indicator"
    ruleset_id: str | None = None
    locations: list = field(default_factory=list)
    evidence: list = field(default_factory=list)

    def public(self):
        data = asdict(self)
        data.pop("evidence")
        return data


@dataclass
class Evidence:
    schema_version: int = 1
    detection: str = "skipped"
    integrity: str = "unspecified"
    authenticity: str = "unverified"
    transport: dict = field(default_factory=dict)
    findings: list = field(default_factory=list)
    decision: str | None = None
    reason: str | None = None

    def public(self):
        data = asdict(self)
        data["findings"] = [f.public() for f in self.findings]
        return data


@dataclass
class Decision:
    action: str
    reason: str


SEVERITIES = {"low": 0, "medium": 1, "high": 2, "critical": 3}
