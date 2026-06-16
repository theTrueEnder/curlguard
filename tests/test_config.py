import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

import pytest
from curlguard.config import CurlGuardConfig, load_config


def test_config_import():
    assert CurlGuardConfig is not None
    assert load_config is not None


def test_config_defaults():
    config = CurlGuardConfig(
        mode="system-wide",
        log_path=Path("/var/log/curlguard/audit.log"),
    )
    assert config.mode == "system-wide"
    assert config.review_interface == "tui"


def test_load_config_accepts_console_review_interface(monkeypatch, tmp_path):
    monkeypatch.setenv("CURLGUARD_MODE", "per-user")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CURLGUARD_REVIEW_INTERFACE", "console")

    config = load_config()

    assert config.review_interface == "console"


def test_load_config_rejects_invalid_review_interface(monkeypatch, tmp_path):
    monkeypatch.setenv("CURLGUARD_MODE", "per-user")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CURLGUARD_REVIEW_INTERFACE", "dialog")

    config = load_config()

    assert config.review_interface == "tui"


def test_load_config_accepts_context_aware_bypass_overrides(monkeypatch, tmp_path):
    monkeypatch.setenv("CURLGUARD_MODE", "per-user")
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CURLGUARD_CONTEXT_AWARE_BYPASS", "false")
    monkeypatch.setenv("CURLGUARD_FORCE_INTERCEPT", "true")
    monkeypatch.setenv("CURLGUARD_PASSTHROUGH_PROCESSES", "apt,cloud-init")

    config = load_config()

    assert config.context_aware_bypass is False
    assert config.force_intercept is True
    assert config.passthrough_process_names == ("apt", "cloud-init")
