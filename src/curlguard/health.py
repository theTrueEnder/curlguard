"""Read-only runtime and scanner diagnostics; never download or require a pin."""

import os
import re
import stat
import subprocess
import sys
from pathlib import Path

from curlguard.auto_updater import AutoUpdater


def runtime_ownership(mode="per-user"):
    prefix = Path(sys.prefix).resolve()
    paths = [prefix, Path(__file__).resolve(), Path(sys.executable).absolute()]
    expected_uid = 0 if mode == "system-wide" else os.geteuid()
    checked = set()
    problems = []
    for path in paths:
        for item in (path, *path.parents):
            if item in checked:
                continue
            checked.add(item)
            info = item.stat()
            # Root-owned system ancestors are permitted for per-user installs.
            if info.st_uid not in {0, expected_uid} or (
                stat.S_IMODE(info.st_mode) & 0o022 and not info.st_mode & stat.S_ISVTX
            ):
                problems.append(str(item))
    return {
        "uid": expected_uid,
        "prefix": str(prefix),
        "safe": not problems,
        "problems": problems,
        "isolated": sys.prefix != sys.base_prefix,
        "package_in_runtime": Path(__file__).resolve().is_relative_to(prefix),
    }


def inspect(config, scanner):
    feed = AutoUpdater(config, scanner).load_active()
    scan = scanner.scan(b"curlguard inert health check")
    binary = config.real_curl_path
    try:
        with binary.open("rb") as handle:
            recursive = b"curlguard" in handle.read(8192)
        if recursive:
            raise ValueError("real curl is a curlguard wrapper")
        result = subprocess.run(
            [str(binary), "--version"], capture_output=True, timeout=5
        )
        match = re.match(rb"curl (\d+)\.(\d+)\.(\d+)", result.stdout)
        capable = (
            result.returncode == 0
            and match is not None
            and tuple(map(int, match.groups())) >= (7, 70, 0)
        )
    except (OSError, ValueError, subprocess.SubprocessError):
        capable = False
    ownership = runtime_ownership(config.mode)
    data = {
        "schema_version": 1,
        "edition": config.edition,
        "settings": config.settings(),
        "scanner_status": scan.status,
        "scanner_error": scan.error,
        "ruleset_id": scanner.ruleset_id,
        "rules_source_count": scanner.get_rules_count(),
        "curl_capable": capable,
        "rule_feed": feed,
        "runtime_ownership": ownership,
    }
    if not capable or not ownership["safe"]:
        return data, 15
    if scan.status in {"unavailable", "error"} or (
        config.require_fresh_rules and not feed["usable"]
    ):
        return data, 13
    return data, 0
