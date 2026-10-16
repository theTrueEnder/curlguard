"""Configuration module for curlguard."""

import json
import os
import shutil
import sys
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal


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
    scan_failure_mode: Literal["warn", "block"] = "warn"
    trust_file: Path | None = None
    trusted_hosts: set[str] = field(default_factory=set)
    trusted_sha256: set[str] = field(default_factory=set)
    unsupported_policy: Literal["passthrough", "block"] = "passthrough"
    scan_timeout_seconds: int = 10
    max_scan_bytes: int = 268435456


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
        "CURLGUARD_SCAN_FAILURE_MODE", "warn", {"warn", "block"}
    )
    unsupported_policy = _choice(
        "CURLGUARD_UNSUPPORTED_POLICY", "passthrough", {"passthrough", "block"}
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
    if update_url and quarantine_dir.parent / "rules" not in rules_dirs:
        rules_dirs.append(quarantine_dir.parent / "rules")

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
