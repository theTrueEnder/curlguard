"""Configuration module for curlguard."""
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
    quarantine_dir: Path = field(default_factory=lambda: Path.home() / ".curlguard" / "quarantine")
    real_curl_path: Path = field(default_factory=lambda: Path("/usr/bin/curl"))
    update_url: str | None = None
    update_interval_hours: int = 24
    ssl_warn_only: bool = True
    scan_failure_mode: Literal["warn", "block"] = "warn"


def _detect_mode() -> Literal["per-user", "system-wide"]:
    argv0 = sys.argv[0] if sys.argv else ""
    if ".local/bin/" in argv0 or str(Path.home()) in argv0:
        return "per-user"
    return "system-wide"


def _detect_real_curl(mode: Literal["per-user", "system-wide"]) -> Path:
    candidates: list[Path] = []
    if mode == "system-wide":
        candidates.append(Path("/usr/bin/curl.real"))

    candidates.extend(
        [
            Path("/usr/bin/curl"),
            Path("/usr/local/bin/curl"),
            Path("/bin/curl"),
        ]
    )

    for candidate in candidates:
        if candidate.exists():
            return candidate

    discovered = shutil.which("curl", path="/usr/bin:/usr/local/bin:/bin")
    if discovered:
        return Path(discovered)

    return Path("/usr/bin/curl.real" if mode == "system-wide" else "/usr/bin/curl")


def load_config() -> CurlGuardConfig:
    mode = os.environ.get("CURLGUARD_MODE", _detect_mode())
    if mode not in ("per-user", "system-wide"):
        mode = "system-wide"

    home = Path.home()
    if mode == "per-user":
        base = home / ".curlguard"
        default_log = base / "audit.log"
        default_rules = [base / "rules"]
        default_quarantine = base / "quarantine"
    else:
        default_log = Path("/var/log/curlguard/audit.log")
        default_rules = [Path("/var/lib/curlguard/rules")]
        default_quarantine = Path("/var/lib/curlguard/quarantine")
    default_real_curl = _detect_real_curl(mode)

    # Env var overrides
    log_path = Path(os.environ.get("CURLGUARD_LOG_PATH", str(default_log)))
    quarantine_dir = Path(os.environ.get("CURLGUARD_QUARANTINE", str(default_quarantine)))
    real_curl_path = Path(os.environ.get("CURLGUARD_REAL_CURL_PATH", str(default_real_curl)))
    update_url = os.environ.get("CURLGUARD_UPDATE_URL")
    update_interval = int(os.environ.get("CURLGUARD_UPDATE_INTERVAL_HOURS", "24"))
    ssl_warn_only = os.environ.get("CURLGUARD_SSL_WARN_ONLY", "true").lower() != "false"
    scan_failure_mode = os.environ.get("CURLGUARD_SCAN_FAILURE_MODE", "warn").lower()
    if scan_failure_mode not in {"warn", "block"}:
        scan_failure_mode = "warn"

    rules_env = os.environ.get("CURLGUARD_RULES_DIR", "")
    if rules_env:
        rules_dirs = [Path(p) for p in rules_env.split(":") if p]
    else:
        rules_dirs = default_rules

    # Create parent directories
    try:
        log_path.parent.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass  # system-wide log dir may need sudo; will fail later if truly inaccessible
    try:
        quarantine_dir.mkdir(parents=True, exist_ok=True)
    except PermissionError:
        pass

    return CurlGuardConfig(
        mode=mode,
        log_path=log_path,
        rules_dirs=rules_dirs,
        quarantine_dir=quarantine_dir,
        real_curl_path=real_curl_path,
        update_url=update_url,
        update_interval_hours=update_interval,
        ssl_warn_only=ssl_warn_only,
        scan_failure_mode=scan_failure_mode,
    )
