import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.review import prompt_user


class DummyScanResult:
    rules_triggered = ["suspicious_pipe_bash"]


def test_review_falls_back_to_console_when_textual_is_missing(monkeypatch, capsys):
    monkeypatch.setattr("curlguard.tui._TEXTUAL_AVAILABLE", False)
    monkeypatch.setattr(
        "curlguard.console_ui.prompt_user",
        lambda scan_result, url, ssl_warn=False: "allow",
    )

    decision = prompt_user(DummyScanResult(), "https://example.com/install.sh")

    captured = capsys.readouterr()
    assert decision == "allow"
    assert "falling back to the console review prompt" in captured.err
