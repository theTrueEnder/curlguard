"""Install a wheelhouse into a candidate runtime, validate, then publish wrappers.

Standard library only: system installation runs a root-owned copy of this file.
Use --root and --prefix for isolated installation verification.
"""

import argparse
import hashlib
import json
import os
import shutil
import subprocess
import sys
import tempfile
import uuid
from pathlib import Path


def install(args):
    prefix = args.prefix.resolve()
    root = args.root.resolve()
    if args.mode == "system-wide" and root == Path("/") and os.geteuid() != 0:
        raise ValueError("system runtime installation requires root")
    prefix.mkdir(parents=True, exist_ok=True, mode=0o755)
    for parent in (prefix, *prefix.parents):
        info = parent.stat()
        if info.st_uid not in {0, os.geteuid()} or (
            info.st_mode & 0o022 and not info.st_mode & 0o1000
        ):
            raise ValueError("runtime prefix has unsafe ownership or permissions")
    # Copy all inputs into a private destination before invoking pip or package code.
    stage = Path(tempfile.mkdtemp(prefix=".install-", dir=prefix))
    runtime = None
    published = False
    try:
        wheels = stage / "wheels"
        wheels.mkdir(mode=0o700)
        for source in args.wheelhouse.glob("*.whl"):
            if source.is_symlink():
                raise ValueError("wheel inputs must not be symlinks")
            destination = wheels / source.name
            shutil.copyfile(source, destination)
            os.chmod(destination, 0o600)
        project = list(wheels.glob("curlguard-*.whl"))
        if len(project) != 1:
            raise ValueError("wheelhouse must contain exactly one curlguard wheel")
        digest = hashlib.sha256(project[0].read_bytes()).hexdigest()[:12]
        runtime = prefix / (
            project[0].name.split("-")[1] + "-" + digest + "-" + uuid.uuid4().hex[:8]
        )
        # Venv paths are embedded in scripts, so build at the final versioned path.
        subprocess.run([sys.executable, "-m", "venv", str(runtime)], check=True)
        python = runtime / "bin/python"
        env = {
            k: v
            for k, v in os.environ.items()
            if not k.startswith(("CURLGUARD_", "PYTHON"))
        }
        env.update(
            PYTHONNOUSERSITE="1",
            CURLGUARD_MODE=args.mode,
            CURLGUARD_QUARANTINE=str(stage / "health/quarantine"),
            CURLGUARD_POLICY_FILE=str(stage / "empty-policy.json"),
            CURLGUARD_REAL_CURL_PATH=str(root / "usr/bin/curl"),
        )
        (stage / "empty-policy.json").write_text('{"schema_version":1}')
        env["HOME"] = str(stage / "health-home")
        subprocess.run(
            [
                str(python),
                "-m",
                "pip",
                "install",
                "--no-index",
                "--only-binary=:all:",
                "--find-links",
                str(wheels),
                str(project[0]),
            ],
            env=env,
            cwd=stage,
            check=True,
        )
        health = subprocess.run(
            [str(python), "-m", "curlguard.cli", "doctor", "--json"],
            env=env,
            cwd=stage,
            check=True,
            capture_output=True,
            text=True,
        )
        report = json.loads(health.stdout)
        ownership = report["runtime_ownership"]
        if (
            not ownership["safe"]
            or not ownership["isolated"]
            or not ownership["package_in_runtime"]
        ):
            raise ValueError("candidate is not an isolated, owned runtime")
        # Runtime must be accessible to regular users of a system wrapper.
        os.chmod(runtime, 0o755)
        publish_env = dict(env)
        publish_env["HOME"] = str(Path.home())
        command = (
            "import sys; from pathlib import Path; from curlguard.curl_manager import CurlManager; "
            "CurlManager(sys.argv[1], root=Path(sys.argv[2])).install(migrate_legacy=sys.argv[3]=='true')"
        )
        subprocess.run(
            [
                str(python),
                "-c",
                command,
                args.mode,
                str(root),
                "true" if args.migrate_legacy else "false",
            ],
            env=publish_env,
            cwd=stage,
            check=True,
        )
        published = True
        print(f"Installed {report['edition']} runtime: {runtime}")
    finally:
        shutil.rmtree(stage)
        if runtime and not published:
            shutil.rmtree(runtime, ignore_errors=True)


def main():
    parser = argparse.ArgumentParser(description=__doc__)
    parser.add_argument("--mode", choices=["per-user", "system-wide"], required=True)
    parser.add_argument("--wheelhouse", type=Path, required=True)
    parser.add_argument("--prefix", type=Path, required=True)
    parser.add_argument("--root", type=Path, default=Path("/"))
    parser.add_argument("--migrate-legacy", action="store_true")
    args = parser.parse_args()
    try:
        install(args)
    except (OSError, ValueError, subprocess.SubprocessError) as exc:
        print(f"curlguard: installation failed: {exc}", file=sys.stderr)
        return 1
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
