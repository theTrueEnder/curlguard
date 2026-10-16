"""Exact artifact pins and expiring, content-bound detection exceptions."""

import hashlib
import json
import re
from dataclasses import dataclass, field
from datetime import datetime, timezone
from urllib.parse import urlsplit, urlunsplit

from curlguard.evidence import SEVERITIES, Decision


def sha256(value):
    if not isinstance(value, str) or not re.fullmatch(r"[0-9a-fA-F]{64}", value):
        raise ValueError("expected SHA-256 must be 64 hexadecimal characters")
    return value.lower()


def timestamp(value):
    if not isinstance(value, str):
        raise ValueError("timestamp must be an ISO-8601 string")
    try:
        result = datetime.fromisoformat(value.replace("Z", "+00:00"))
    except ValueError as exc:
        raise ValueError("invalid ISO-8601 timestamp") from exc
    if result.tzinfo is None:
        raise ValueError("timestamp must include a timezone")
    return result


def normalize_url(value, *, allow_credentials=False):
    if not isinstance(value, str) or any(ord(c) < 33 for c in value):
        raise ValueError("invalid policy URL")
    u = urlsplit(value)
    if (
        u.scheme not in {"http", "https"}
        or not u.hostname
        or u.fragment
        or ((u.username or u.password) and not allow_credentials)
    ):
        raise ValueError("policy URL requires HTTP(S), no credentials or fragments")
    host = u.hostname.lower()
    if ":" in host:
        host = f"[{host}]"
    port = u.port or (443 if u.scheme == "https" else 80)
    default = (u.scheme == "https" and port == 443) or (
        u.scheme == "http" and port == 80
    )
    netloc = host if default else f"{host}:{port}"
    return urlunsplit((u.scheme.lower(), netloc, u.path or "/", u.query, ""))


def origin(value):
    u = urlsplit(normalize_url(value, allow_credentials=True))
    return f"{u.scheme}://{u.netloc}"


@dataclass
class ArtifactPolicy:
    artifacts: list = field(default_factory=list)
    exceptions: list = field(default_factory=list)

    @classmethod
    def load(cls, path):
        if path is None or not path.exists():
            return cls()
        try:
            data = json.loads(path.read_text(encoding="utf-8"))
        except (OSError, ValueError) as exc:
            raise ValueError("cannot read artifact policy") from exc
        if not isinstance(data, dict) or (
            type(data.get("schema_version")) is not int
            or data.get("schema_version") != 1
        ):
            raise ValueError("artifact policy requires schema_version=1")
        ids, urls = set(), set()
        groups = []
        for group in ("artifacts", "exceptions"):
            records = data.get(group, [])
            if not isinstance(records, list):
                raise ValueError(f"policy {group} must be an array")
            validated = []
            for raw in records:
                if not isinstance(raw, dict):
                    raise ValueError("policy record must be an object")
                r = dict(raw)
                identifier = r.get("id")
                if (
                    not isinstance(identifier, str)
                    or not identifier
                    or identifier in ids
                ):
                    raise ValueError("policy IDs must be nonempty and unique")
                ids.add(identifier)
                r["url"] = normalize_url(r.get("url"))
                r["sha256"] = sha256(r.get("sha256"))
                origins = r.get("allowed_final_origins", [origin(r["url"])])
                if not isinstance(origins, list) or not origins:
                    raise ValueError("allowed_final_origins must be a nonempty array")
                for item in origins:
                    parsed = urlsplit(normalize_url(item))
                    if parsed.path != "/" or parsed.query:
                        raise ValueError(
                            "allowed final origin must not contain a path or query"
                        )
                r["allowed_final_origins"] = [origin(o) for o in origins]
                if group == "artifacts":
                    if r["url"] in urls:
                        raise ValueError("duplicate artifact URL")
                    urls.add(r["url"])
                else:
                    rules = r.get("rules")
                    if (
                        not isinstance(rules, list)
                        or not rules
                        or not all(
                            isinstance(s, str) and s and "*" not in s for s in rules
                        )
                    ):
                        raise ValueError("exception requires specific rule identifiers")
                    timestamp(r.get("expires_at"))
                    if not isinstance(r.get("reason"), str) or not r["reason"].strip():
                        raise ValueError("exception requires a reason")
                validated.append(r)
            groups.append(validated)
        return cls(*groups)

    def artifact(self, url):
        return next(
            (
                r
                for r in self.artifacts
                if r["url"] == normalize_url(url, allow_credentials=True)
            ),
            None,
        )

    def expected(self, url, explicit=None):
        record = self.artifact(url)
        configured = record["sha256"] if record else None
        if explicit and configured and explicit != configured:
            raise ValueError("explicit SHA-256 conflicts with artifact policy")
        return explicit or configured

    def final_allowed(self, url, final):
        record = self.artifact(url)
        return not record or origin(final) in record["allowed_final_origins"]

    def suppressed(self, url, final, checksum):
        now = datetime.now(timezone.utc)
        return {
            rule
            for r in self.exceptions
            if r["url"] == normalize_url(url, allow_credentials=True)
            and r["sha256"] == checksum
            and origin(final) in r["allowed_final_origins"]
            and timestamp(r["expires_at"]) > now
            for rule in r["rules"]
        }


def evaluate_findings(result, config, suppressed):
    findings = getattr(result, "findings", [])
    if findings:
        active = [
            f
            for f in findings
            if f.rule not in suppressed and f"{f.namespace}:{f.rule}" not in suppressed
        ]
        actionable = [
            f
            for f in active
            if SEVERITIES[f.severity] >= SEVERITIES[config.severity_threshold]
        ]
    else:
        active = [r for r in result.rules_triggered if r not in suppressed]
        actionable = active
    if not active:
        return Decision("allow", "scoped_exception")
    if not actionable:
        return Decision("allow", "below_severity_threshold")
    return Decision(config.match_policy, "configured_policy")


def hash_file(path):
    digest, size = hashlib.sha256(), 0
    with path.open("rb") as handle:
        for chunk in iter(lambda: handle.read(1024 * 1024), b""):
            digest.update(chunk)
            size += len(chunk)
    return {"sha256": digest.hexdigest(), "size": size}
