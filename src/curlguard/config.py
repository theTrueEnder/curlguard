"""Configuration module for curlguard."""

import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal

from curlguard.edition import EDITION, SECURITY
from curlguard.policy import ArtifactPolicy, sha256


@dataclass
class CurlGuardConfig:
    mode: Literal["per-user", "system-wide"]
    log_path: Path
    rules_dirs: list[Path] = field(default_factory=list)
    quarantine_dir: Path = field(
        default_factory=lambda: Path.home() / ".curlguard" / "quarantine"
    )
    real_curl_path: Path = field(default_factory=lambda: Path("/usr/bin/curl"))
    update_url: str | None = None
    update_interval_hours: int = 24
    ssl_warn_only: bool = True
    match_policy: Literal["prompt", "quarantine", "block", "allow"] = "quarantine"
    scan_failure_mode: Literal["warn", "block"] = "block" if SECURITY else "warn"
    trust_file: Path | None = None
    trusted_hosts: set[str] = field(default_factory=set)
    trusted_sha256: set[str] = field(default_factory=set)
    unsupported_policy: Literal["passthrough", "block"] = (
        "block" if SECURITY else "passthrough"
    )
    scan_timeout_seconds: int = 10
    max_scan_bytes: int = 268435456
    max_staged_bytes: int = 1073741824
    transfer_timeout_seconds: int = 300
    publisher: dict | None = None
    cosign_path: Path = field(default_factory=lambda: Path("/usr/local/bin/cosign"))
    noninteractive: bool = False
    edition: str = EDITION
    require_sha256: bool = SECURITY
    expected_sha256: str | None = None
    require_https: bool = SECURITY
    verify_certificates: bool = SECURITY
    min_tls: str | None = "1.2" if SECURITY else None
    redirect_protocols: tuple = ("https",) if SECURITY else ()
    require_fresh_rules: bool = SECURITY
    severity_threshold: str = "low"
    policy: ArtifactPolicy = field(default_factory=ArtifactPolicy)
    policy_file: Path | None = None
    update_keys_file: Path | None = None
    update_feed_id: str | None = None

    def settings(self):
        return {
            name: getattr(self, name)
            for name in (
                "edition",
                "require_sha256",
                "require_https",
                "verify_certificates",
                "min_tls",
                "redirect_protocols",
                "require_fresh_rules",
                "severity_threshold",
                "scan_failure_mode",
                "unsupported_policy",
                "match_policy",
                "max_staged_bytes",
                "transfer_timeout_seconds",
            )
        }


def _detect_mode() -> Literal["per-user", "system-wide"]:
    argv0 = sys.argv[0] if sys.argv else ""
    if ".local/bin/" in argv0 or str(Path.home()) in argv0:
        return "per-user"
    return "system-wide"


def _detect_real_curl(mode: Literal["per-user", "system-wide"]) -> Path:
    candidates: list[Path] = []
    candidates.extend(
        [
            Path("/usr/bin/curl"),
            Path("/bin/curl"),
        ]
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    discovered = shutil.which("curl", path="/usr/bin:/usr/local/bin:/bin")
    if discovered:
        return Path(discovered)

    return Path("/usr/bin/curl")


def _parse_csv_values(raw: str) -> set[str]:
    return {value.strip() for value in raw.split(",") if value.strip()}


def _normalize_sha256_values(values: set[str]) -> set[str]:
    normalized: set[str] = set()
    for value in values:
        candidate = value.strip().lower()
        if len(candidate) == 64 and all(ch in "0123456789abcdef" for ch in candidate):
            normalized.add(candidate)
    return normalized


def _load_trust_file(path: Path | None) -> tuple[set[str], set[str]]:
    if path is None or not path.exists():
        return set(), set()

    try:
        payload = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, json.JSONDecodeError) as exc:
        raise ValueError(f"Cannot read trust file {path}: {exc}") from exc

    if not isinstance(payload, dict):
        raise ValueError(f"Trust file {path} must contain an object")

    hosts = payload.get("hosts", [])
    checksums = payload.get("sha256", [])
    if not all(
        isinstance(v, list) and all(isinstance(s, str) for s in v)
        for v in (hosts, checksums)
    ):
        raise ValueError("Trust hosts and sha256 must be lists of strings")
    if any(not s.strip() for s in hosts) or any(
        not _normalize_sha256_values({s}) for s in checksums
    ):
        raise ValueError("Trust file contains an empty host or invalid SHA-256")

    trusted_hosts = {str(host).strip().lower() for host in hosts if str(host).strip()}
    trusted_sha256 = _normalize_sha256_values(
        {str(checksum).strip() for checksum in checksums if str(checksum).strip()}
    )
    return trusted_hosts, trusted_sha256


def load_config() -> CurlGuardConfig:
    mode = os.environ.get("CURLGUARD_MODE", _detect_mode())
    if mode not in ("per-user", "system-wide"):
        raise ValueError("CURLGUARD_MODE must be per-user or system-wide")

    home = Path.home()
    if mode == "per-user" or os.geteuid() != 0:
        base = home / ".curlguard"
        default_log = base / "audit.log"
        default_rules = [base / "rules"]
        default_quarantine = base / "quarantine"
        default_trust_file = base / "trust.json"
        if mode == "system-wide":
            default_rules.insert(0, Path("/var/lib/curlguard/rules"))
    else:
        default_log = Path("/var/log/curlguard/audit.log")
        default_rules = [Path("/var/lib/curlguard/rules")]
        default_quarantine = Path("/var/lib/curlguard/quarantine")
        default_trust_file = Path("/var/lib/curlguard/trust.json")
    default_real_curl = _detect_real_curl(mode)

    # Env var overrides
    log_path = Path(os.environ.get("CURLGUARD_LOG_PATH", str(default_log)))
    quarantine_dir = Path(
        os.environ.get("CURLGUARD_QUARANTINE", str(default_quarantine))
    )
    real_curl_path = Path(
        os.environ.get("CURLGUARD_REAL_CURL_PATH", str(default_real_curl))
    )
    update_url = os.environ.get("CURLGUARD_UPDATE_URL")
    update_interval = _positive("CURLGUARD_UPDATE_INTERVAL_HOURS", 24)
    ssl_warn_only = (
        _choice("CURLGUARD_SSL_WARN_ONLY", "true", {"true", "false"}) == "true"
    )
    match_policy = _choice(
        "CURLGUARD_MATCH_POLICY",
        "quarantine",
        {"prompt", "quarantine", "block", "allow"},
    )
    scan_failure_mode = _choice(
        "CURLGUARD_SCAN_FAILURE_MODE",
        "block" if SECURITY else "warn",
        {"warn", "block"},
    )
    unsupported_policy = _choice(
        "CURLGUARD_UNSUPPORTED_POLICY",
        "block" if SECURITY else "passthrough",
        {"passthrough", "block"},
    )
    trust_file_env = os.environ.get("CURLGUARD_TRUST_FILE")
    trust_file = Path(trust_file_env) if trust_file_env else default_trust_file
    trusted_hosts = {
        host.lower()
        for host in _parse_csv_values(os.environ.get("CURLGUARD_TRUSTED_HOSTS", ""))
    }
    trusted_sha256 = _normalize_sha256_values(
        _parse_csv_values(os.environ.get("CURLGUARD_TRUSTED_SHA256", ""))
    )
    if any(
        not _normalize_sha256_values({s})
        for s in _parse_csv_values(os.environ.get("CURLGUARD_TRUSTED_SHA256", ""))
    ):
        raise ValueError("CURLGUARD_TRUSTED_SHA256 contains an invalid SHA-256")
    file_hosts, file_checksums = _load_trust_file(trust_file)
    trusted_hosts.update(file_hosts)
    trusted_sha256.update(file_checksums)

    rules_env = os.environ.get("CURLGUARD_RULES_DIR", "")
    if rules_env:
        rules_dirs = [Path(p) for p in rules_env.split(":") if p]
    else:
        rules_dirs = default_rules
    if trusted_hosts or trusted_sha256:
        raise ValueError(
            "legacy trust allowances removed; migrate to policy.json scoped exceptions"
        )
    if "CURLGUARD_SSL_WARN_ONLY" in os.environ:
        if any(
            name in os.environ
            for name in (
                "CURLGUARD_REQUIRE_HTTPS",
                "CURLGUARD_VERIFY_CERTIFICATES",
                "CURLGUARD_MIN_TLS",
                "CURLGUARD_REDIRECT_PROTOCOLS",
            )
        ):
            raise ValueError(
                "legacy SSL_WARN_ONLY conflicts with new transport settings"
            )
        print(
            "curlguard: SSL_WARN_ONLY is deprecated; migrate to independent transport settings",
            file=sys.stderr,
        )
    strict = SECURITY or not ssl_warn_only
    policy_file = Path(
        os.environ.get(
            "CURLGUARD_POLICY_FILE", str(default_quarantine.parent / "policy.json")
        )
    )
    if "CURLGUARD_POLICY_FILE" in os.environ and not policy_file.is_file():
        raise ValueError("explicit policy file does not exist")
    minimum = os.environ.get("CURLGUARD_MIN_TLS", "1.2" if strict else "none")
    if minimum not in {"none", "1.0", "1.1", "1.2", "1.3"}:
        raise ValueError("invalid CURLGUARD_MIN_TLS")
    redirects = os.environ.get(
        "CURLGUARD_REDIRECT_PROTOCOLS", "https" if strict else ""
    )
    protocols = tuple(v.strip() for v in redirects.split(",") if v.strip())
    if any(v not in {"http", "https"} for v in protocols):
        raise ValueError("redirect protocols must be http and/or https")
    expected = os.environ.get("CURLGUARD_EXPECTED_SHA256")

    return CurlGuardConfig(
        mode=mode,
        log_path=log_path,
        rules_dirs=rules_dirs,
        quarantine_dir=quarantine_dir,
        real_curl_path=real_curl_path,
        update_url=update_url,
        update_interval_hours=update_interval,
        ssl_warn_only=ssl_warn_only,
        match_policy=match_policy,
        scan_failure_mode=scan_failure_mode,
        trust_file=trust_file,
        trusted_hosts=trusted_hosts,
        trusted_sha256=trusted_sha256,
        unsupported_policy=unsupported_policy,
        scan_timeout_seconds=_positive("CURLGUARD_SCAN_TIMEOUT_SECONDS", 10),
        max_scan_bytes=_positive("CURLGUARD_MAX_SCAN_BYTES", 268435456),
        max_staged_bytes=_positive("CURLGUARD_MAX_STAGED_BYTES", 1073741824),
        transfer_timeout_seconds=_positive("CURLGUARD_TRANSFER_TIMEOUT_SECONDS", 300),
        cosign_path=Path(
            os.environ.get("CURLGUARD_COSIGN_PATH", "/usr/local/bin/cosign")
        ),
        require_sha256=_boolean("CURLGUARD_REQUIRE_SHA256", SECURITY),
        expected_sha256=sha256(expected) if expected is not None else None,
        require_https=_boolean("CURLGUARD_REQUIRE_HTTPS", strict),
        verify_certificates=_boolean("CURLGUARD_VERIFY_CERTIFICATES", strict),
        min_tls=None if minimum == "none" else minimum,
        redirect_protocols=protocols,
        require_fresh_rules=_boolean("CURLGUARD_REQUIRE_FRESH_RULES", SECURITY),
        severity_threshold=_choice(
            "CURLGUARD_SEVERITY_THRESHOLD", "low", {"low", "medium", "high", "critical"}
        ),
        policy=ArtifactPolicy.load(policy_file),
        policy_file=policy_file,
        update_keys_file=Path(
            os.environ.get(
                "CURLGUARD_UPDATE_KEYS_FILE",
                str(default_quarantine.parent / "update-keys.json"),
            )
        ),
        update_feed_id=os.environ.get("CURLGUARD_UPDATE_FEED_ID"),
    )


def _choice(name: str, default: str, choices: set[str]) -> str:
    value = os.environ.get(name, default).lower()
    if value not in choices:
        raise ValueError(f"{name} must be one of: {', '.join(sorted(choices))}")
    return value


def _positive(name: str, default: int) -> int:
    try:
        value = int(os.environ.get(name, str(default)))
    except ValueError as exc:
        raise ValueError(f"{name} must be a positive integer") from exc
    if value <= 0:
        raise ValueError(f"{name} must be a positive integer")
    return value


def _boolean(name, default):
    return _choice(name, "true" if default else "false", {"true", "false"}) == "true"
