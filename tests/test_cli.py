import sys
from pathlib import Path
sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from unittest.mock import MagicMock, patch

from curlguard.cli import main


def test_main_passes_leading_curl_flags_to_wrapper(tmp_path):
    config = MagicMock()
    config.rules_dirs = []
    config.log_path = tmp_path / "audit.log"
    wrapper = MagicMock()
    wrapper.dispatch.return_value = 0
    logger = MagicMock()

    with patch("curlguard.cli.load_config", return_value=config), \
         patch("curlguard.cli.YaraScanner"), \
         patch("curlguard.cli.AuditLogger", return_value=logger), \
         patch("curlguard.cli.SslBypassDetector"), \
         patch("curlguard.cli.CurlWrapper", return_value=wrapper):
        exit_code = main(["-fsSL", "https://example.com/install.sh"])

    assert exit_code == 0
    wrapper.dispatch.assert_called_once_with(["-fsSL", "https://example.com/install.sh"])
    logger.close.assert_called_once()


def test_main_keeps_curl_version_as_curl_arg(tmp_path):
    config = MagicMock()
    config.rules_dirs = []
    config.log_path = tmp_path / "audit.log"
    wrapper = MagicMock()
    wrapper.dispatch.return_value = 0

    with patch("curlguard.cli.load_config", return_value=config), \
         patch("curlguard.cli.YaraScanner"), \
         patch("curlguard.cli.AuditLogger", return_value=MagicMock()), \
         patch("curlguard.cli.SslBypassDetector"), \
         patch("curlguard.cli.CurlWrapper", return_value=wrapper):
        exit_code = main(["--version", "https://example.com"])

    assert exit_code == 0
    wrapper.dispatch.assert_called_once_with(["--version", "https://example.com"])
