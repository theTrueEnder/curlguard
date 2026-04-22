"""Configuration module for curlguard."""
from dataclasses import dataclass, field
from pathlib import Path
from typing import Literal, Optional
import os
import sys


@dataclass
class CurlGuardConfig:
    mode: Literal["per-user", "system-wide"]
    log_path: Path
    rules_dirs: list[Path] = field(default_factory=list)
    quarantine_dir: Path = field(default_factory=Path.home() / ".curlguard" / "quarantine")
    real_curl_path: Path = field(default_factory=Path("/usr/bin/curl.real"))
    update_url: Optional[str] = None
    update_interval_hours: int = 24
    ssl_warn_only: bool = True


def _detect_mode() -> Literal["per-user", "system-wide"]:
    argv0 = sys.argv[0] if sys.argv else ""
    if ".local/bin/" in argv0 or str(Path.home()) in argv0:
        return "per-user"
    return "system-wide"


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
        default_real_curl = home / ".local/bin/curl.real"
    else:
        default_log = Path("/var/log/curlguard/audit.log")
        default_rules = [Path("/var/lib/curlguard/rules")]
        default_quarantine = Path("/var/lib/curlguard/quarantine")
        default_real_curl = Path("/usr/bin/curl.real")

    # Env var overrides
    log_path = Path(os.environ.get("CURLGUARD_LOG_PATH", str(default_log)))
    quarantine_dir = Path(os.environ.get("CURLGUARD_QUARANTINE", str(default_quarantine)))
    real_curl_path = Path(os.environ.get("CURLGUARD_REAL_CURL_PATH", str(default_real_curl)))
    update_url = os.environ.get("CURLGUARD_UPDATE_URL")
    update_interval = int(os.environ.get("CURLGUARD_UPDATE_INTERVAL_HOURS", "24"))
    ssl_warn_only = os.environ.get("CURLGUARD_SSL_WARN_ONLY", "true").lower() != "false"

    rules_env = os.environ.get("CURLGUARD_RULES_DIR", "")
    if rules_env:
        rules_dirs = [Path(p) for p in rules_env.split(":") if p]
    else:
        rules_dirs = default_rules

    # Create parent directories
    log_path.parent.mkdir(parents=True, exist_ok=True)
    quarantine_dir.mkdir(parents=True, exist_ok=True)

    return CurlGuardConfig(
        mode=mode,
        log_path=log_path,
        rules_dirs=rules_dirs,
        quarantine_dir=quarantine_dir,
        real_curl_path=real_curl_path,
        update_url=update_url,
        update_interval_hours=update_interval,
        ssl_warn_only=ssl_warn_only,
    )