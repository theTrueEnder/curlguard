"""Build and import installed distributions without checkout path injection."""

import importlib.util
import json
import os
import shutil
import subprocess
import sys
import tarfile
import types
import zipfile
from pathlib import Path
from unittest.mock import patch

import pytest


@pytest.fixture(scope="module")
def artifacts(tmp_path_factory):
    root = tmp_path_factory.mktemp("distribution")
    source = root / "source"
    source.mkdir()
    project = Path(__file__).resolve().parents[1]
    shutil.copy(project / "pyproject.toml", source)
    shutil.copytree(
        project / "src",
        source / "src",
        ignore=shutil.ignore_patterns("__pycache__", "*.egg-info"),
    )
    env = {k: v for k, v in os.environ.items() if not k.startswith("PYTHON")}
    subprocess.run(
        [
            sys.executable,
            "-m",
            "build",
            "--no-isolation",
            "--outdir",
            str(root / "dist"),
        ],
        cwd=source,
        env=env,
        check=True,
        capture_output=True,
    )
    wheel = next((root / "dist").glob("*.whl"))
    sdist = next((root / "dist").glob("*.tar.gz"))
    return root, wheel, sdist


def test_wheel_and_sdist_include_rules(artifacts):
    _, wheel, sdist = artifacts
    with zipfile.ZipFile(wheel) as archive:
        assert "curlguard/rules/foundation.yar" in archive.namelist()
    with tarfile.open(sdist) as archive:
        assert any(
            name.endswith("/curlguard/rules/foundation.yar")
            for name in archive.getnames()
        )


def test_installed_wheel_outside_checkout(artifacts):
    root, wheel, _ = artifacts
    installed = root / "installed"
    env = {
        k: v
        for k, v in os.environ.items()
        if not k.startswith(("PYTHON", "CURLGUARD_"))
    }
    subprocess.run(
        [
            sys.executable,
            "-m",
            "pip",
            "install",
            "--no-index",
            "--no-deps",
            "--target",
            str(installed),
            str(wheel),
        ],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
    )
    env["PYTHONPATH"] = str(installed)
    code = (
        "import pathlib,curlguard; from curlguard.scanner import YaraScanner; "
        "s=YaraScanner(); assert s.scan(b'inert').status=='clean'; "
        "assert s.scan(b'base64 -d | bash').status=='flagged'; print(curlguard.__file__)"
    )
    result = subprocess.run(
        [sys.executable, "-c", code],
        cwd=root,
        env=env,
        check=True,
        capture_output=True,
        text=True,
    )
    assert Path(result.stdout.strip()).is_relative_to(installed)
    # Missing packaged rules must be diagnosed as an unsuccessful scan.
    (installed / "curlguard/rules/foundation.yar").unlink()
    result = subprocess.run(
        [
            sys.executable,
            "-c",
            "from curlguard.scanner import YaraScanner; assert YaraScanner().scan(b'inert').status=='unavailable'",
        ],
        cwd=root,
        env=env,
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr


def test_health_failure_does_not_require_artifact_pin(tmp_path):
    from curlguard.config import CurlGuardConfig
    from curlguard.health import inspect
    from curlguard.scanner import YaraScanner

    config = CurlGuardConfig("per-user", tmp_path / "audit", require_sha256=True)
    scanner = YaraScanner()
    with patch("curlguard.health.runtime_ownership", return_value={"safe": True}):
        report, code = inspect(config, scanner)
        assert code == 0 and report["settings"]["require_sha256"]
        scanner._rules = None
        assert inspect(config, scanner)[1] == 13
        config.real_curl_path = tmp_path / "missing-curl"
        assert inspect(config, scanner)[1] == 15


@pytest.mark.parametrize("fail_at", ["pip", "health", "publish"])
def test_candidate_failure_preserves_previous_runtime(tmp_path, fail_at):
    helper = Path(__file__).resolve().parents[1] / "scripts/install-runtime.py"
    spec = importlib.util.spec_from_file_location("install_runtime", helper)
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    prefix, wheels = tmp_path / "runtimes", tmp_path / "wheels"
    prefix.mkdir()
    previous = prefix / "previous"
    previous.mkdir()
    (previous / "sentinel").write_text("preserved")
    wheels.mkdir()
    (wheels / "curlguard-0.1.0-py3-none-any.whl").write_bytes(b"inert wheel fixture")
    args = types.SimpleNamespace(
        prefix=prefix,
        root=tmp_path / "root",
        mode="per-user",
        wheelhouse=wheels,
        migrate_legacy=False,
    )
    calls = []

    def run(command, **kwargs):
        calls.append(command)
        stage = (
            "pip"
            if "pip" in command
            else "health"
            if "doctor" in command
            else "publish"
            if "-c" in command
            else "venv"
        )
        if stage == "venv":
            Path(command[-1]).mkdir()
        if stage == fail_at:
            raise subprocess.CalledProcessError(1, command)
        return subprocess.CompletedProcess(
            command,
            0,
            json.dumps(
                {
                    "edition": "test",
                    "runtime_ownership": {
                        "safe": True,
                        "isolated": True,
                        "package_in_runtime": True,
                    },
                }
            ),
        )

    with (
        patch.object(module.subprocess, "run", side_effect=run),
        pytest.raises(subprocess.CalledProcessError),
    ):
        module.install(args)
    assert list(prefix.iterdir()) == [previous]
    assert (previous / "sentinel").read_text() == "preserved"
    pip_calls = [c for c in calls if "pip" in c]
    assert (
        pip_calls
        and "--no-index" in pip_calls[0]
        and "--only-binary=:all:" in pip_calls[0]
    )


def test_wrapper_pair_rollback(tmp_path, monkeypatch):
    from curlguard.curl_manager import CurlManager

    root = tmp_path / "root"
    (root / "usr/bin").mkdir(parents=True)
    shutil.copyfile("/usr/bin/curl", root / "usr/bin/curl")
    manager = CurlManager("system-wide", root=root)
    manager.install()
    wrapper = root / "usr/local/bin/curl"
    cli = wrapper.with_name("curlguard")
    old_wrapper, old_cli = wrapper.read_bytes(), cli.read_bytes()
    replace = os.replace

    def fail_second(source, destination):
        if Path(destination) == cli:
            raise OSError("simulated publication failure")
        return replace(source, destination)

    monkeypatch.setattr("curlguard.curl_manager.os.replace", fail_second)
    with pytest.raises(OSError):
        manager.install()
    assert wrapper.read_bytes() == old_wrapper and cli.read_bytes() == old_cli
