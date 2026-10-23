"""Promotion compares shared trees without blocking ordinary edition PRs."""

import importlib.util
import subprocess
from pathlib import Path

import pytest


def test_release_parity_gate(tmp_path, monkeypatch):
    project = Path(__file__).resolve().parents[1]
    spec = importlib.util.spec_from_file_location(
        "edition_parity", project / "scripts/check-edition-parity.py"
    )
    module = importlib.util.module_from_spec(spec)
    spec.loader.exec_module(module)
    monkeypatch.chdir(tmp_path)

    def git(*args):
        return subprocess.check_output(["git", *args]).decode().strip()

    def commit(message):
        git("add", ".")
        git(
            "-c",
            "user.name=Test",
            "-c",
            "user.email=test@example.invalid",
            "commit",
            "-m",
            message,
        )
        return git("rev-parse", "HEAD")

    git("init")
    edition = tmp_path / "src/curlguard/edition.py"
    edition.parent.mkdir(parents=True)
    module_text = (
        '"""Shipped defaults; variant branches change only this module."""\n\n'
    )
    edition.write_text(module_text + 'EDITION = "general-users"\nSECURITY = False\n')
    readme = tmp_path / "README.md"
    readme.write_text(
        "The current branch is **codex/general-users**. The maintained security variant is\n"
        "**codex/security-users**. Shared implementation.\n"
    )
    general = commit("general")
    edition.write_text(module_text + 'EDITION = "security-users"\nSECURITY = True\n')
    readme.write_text(
        "The current branch is **codex/security-users**. The maintained general variant is\n"
        "**codex/general-users**. Shared implementation.\n"
    )
    security = commit("security")
    module.check(general, security)
    readme.write_text(readme.read_text() + "Unreviewed extra change.\n")
    with pytest.raises(ValueError, match="README differs"):
        module.check(general, commit("drift"))
    (tmp_path / "shared.py").write_text("changed shared code\n")
    with pytest.raises(ValueError, match="shared trees differ"):
        module.check(general, commit("shared drift"))
    with pytest.raises(ValueError, match="unexpected defaults"):
        module.check(general, general)
