"""Optional live APT comparison; all metadata, packages and install layouts are private."""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).resolve().parents[1] / "src"))
from curlguard.curl_manager import CurlManager


def digest(path):
    return hashlib.sha256(path.read_bytes()).hexdigest()


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--output", required=True, type=Path)
    root = parser.parse_args().output.resolve()
    root.mkdir(parents=True, exist_ok=False)
    layout = root / "layout"
    real = layout / "usr/bin/curl"
    real.parent.mkdir(parents=True)
    shutil.copy2("/usr/bin/curl", real)
    manager = CurlManager("system-wide", root=layout)
    manager.install()
    env = {k: v for k, v in os.environ.items() if not k.startswith("CURLGUARD_")}
    env.update(
        PYTHONPATH=str(Path(__file__).resolve().parents[1] / "src"),
        CURLGUARD_LOG_PATH=str(root / "audit.log"),
        CURLGUARD_QUARANTINE=str(root / "quarantine"),
    )
    results = []

    def run(name, command, guarded, cwd=None):
        process = subprocess.run(
            command,
            capture_output=True,
            text=True,
            timeout=180,
            cwd=cwd or root,
            env={
                **env,
                "PATH": (str(manager._curl_path.parent) + ":" if guarded else "")
                + "/usr/bin:/bin",
            },
        )
        results.append(
            {
                "name": name,
                "command": list(map(str, command)),
                "exit_code": process.returncode,
                "stdout": process.stdout,
                "stderr": process.stderr,
            }
        )
        (root / "results.json").write_text(json.dumps(results, indent=2))
        print(f"{name}: exit {process.returncode}", flush=True)
        if process.returncode:
            raise RuntimeError(f"{name} failed; see {root}/results.json")
        return process

    for guarded in (False, True):
        label = "guarded" if guarded else "baseline"
        base = root / label
        for subdir in ("lists/partial", "cache/archives/partial", "log", "downloads"):
            (base / subdir).mkdir(parents=True, exist_ok=True)
        options = [
            "-o",
            f"Dir::State::lists={base}/lists",
            "-o",
            f"Dir::Cache={base}/cache",
            "-o",
            f"Dir::Log={base}/log",
            "-o",
            "Debug::NoLocking=1",
            "-o",
            f"APT::Sandbox::User={os.environ.get('USER', 'user')}",
            "-o",
            "Acquire::Retries=0",
            "-o",
            "Acquire::http::Timeout=30",
            "-o",
            "Acquire::https::Timeout=30",
        ]
        run(
            label + "-update",
            ["apt-get", *options, "update", "--error-on=any"],
            guarded,
        )
        run(label + "-simulate", ["apt-get", *options, "-s", "upgrade"], guarded)
        run(
            label + "-download",
            ["apt-get", *options, "download", "hello", "curl"],
            guarded,
            base / "downloads",
        )
    packages = [
        {p.name: digest(p) for p in (root / label / "downloads").glob("*.deb")}
        for label in ("baseline", "guarded")
    ]
    plan = [
        next(r["stdout"] for r in results if r["name"] == label + "-simulate")
        for label in ("baseline", "guarded")
    ]
    wrapper_before = digest(manager._curl_path)
    package = next((root / "guarded/downloads").glob("curl_*.deb"))
    run("package-unpack", ["dpkg-deb", "-x", str(package), str(layout)], False)
    checks = {
        "package_hashes_match": packages[0] == packages[1],
        "upgrade_plans_match": plan[0] == plan[1],
        "wrapper_survives_package_unpack": digest(manager._curl_path) == wrapper_before,
        "packaged_curl_is_elf": real.read_bytes().startswith(b"\x7fELF"),
        "apt_curlguard_audit_events": len((root / "audit.log").read_text().splitlines())
        if (root / "audit.log").exists()
        else 0,
    }
    manager.uninstall()
    checks["uninstall_preserves_packaged_curl"] = (
        real.exists() and not manager._curl_path.exists()
    )
    (root / "summary.json").write_text(json.dumps(checks, indent=2))
    print(json.dumps(checks, indent=2))
    return (
        0
        if all(v for k, v in checks.items() if k != "apt_curlguard_audit_events")
        else 1
    )


if __name__ == "__main__":
    raise SystemExit(main())
