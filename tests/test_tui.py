import sys
from pathlib import Path
from unittest.mock import MagicMock, patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.tui import main, prompt_user


class DummyScanResult:
    rules_triggered = ["suspicious_pipe_bash"]


def test_prompt_user_returns_block_when_no_terminal(monkeypatch, capsys):
    monkeypatch.setattr("curlguard.tui._launch_tui_subprocess", MagicMock(side_effect=RuntimeError("no tty")))

    decision = prompt_user(DummyScanResult(), "https://example.com/install.sh")

    captured = capsys.readouterr()
    assert decision == "block"
    assert "unable to open an interactive review prompt" in captured.err


def test_prompt_user_maps_quarantine_exit_code(monkeypatch):
    monkeypatch.setattr("curlguard.tui._launch_tui_subprocess", MagicMock(return_value=2))

    decision = prompt_user(DummyScanResult(), "https://example.com/install.sh", ssl_warn=True)

    assert decision == "quarantine"


def test_tui_main_invokes_run_tui():
    with patch("curlguard.tui._TEXTUAL_AVAILABLE", True), \
         patch("curlguard.tui.run_tui", return_value=1) as mock_run_tui:
        exit_code = main(
            [
                "--rules-json",
                '["suspicious_pipe_bash","known_malware_header"]',
                "--url",
                "https://example.com/install.sh",
                "--ssl-warn",
            ]
        )

    assert exit_code == 1
    mock_run_tui.assert_called_once_with(
        rules=["suspicious_pipe_bash", "known_malware_header"],
        url="https://example.com/install.sh",
        ssl_warn=True,
    )
