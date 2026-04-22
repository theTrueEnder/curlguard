import pytest
from curlguard.config import CurlGuardConfig, load_config


def test_config_import():
    assert CurlGuardConfig is not None
    assert load_config is not None


def test_config_defaults():
    config = CurlGuardConfig(
        mode="system-wide",
        log_path="/var/log/curlguard/audit.log",
    )
    assert config.mode == "system-wide"