import io
import sys
from pathlib import Path

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.console_ui import prompt_user


class DummyScanResult:
    rules_triggered = ["suspicious_pipe_bash"]


class NonClosingStringIO(io.StringIO):
    def close(self) -> None:
        self.seek(0, io.SEEK_END)


def test_console_prompt_accepts_quarantine_after_retry(monkeypatch):
    reader = NonClosingStringIO("maybe\nQ\n")
    writer = NonClosingStringIO()

    monkeypatch.setattr(
        "curlguard.console_ui._open_interactive_terminal",
        lambda: (reader, writer),
    )

    decision = prompt_user(
        DummyScanResult(), "https://example.com/install.sh", ssl_warn=True
    )

    assert decision == "quarantine"
    output = writer.getvalue()
    assert "TLS warning" in output
    assert "Please enter B, Q, or A." in output


def test_console_prompt_blocks_when_terminal_is_unavailable(monkeypatch, capsys):
    monkeypatch.setattr("curlguard.console_ui._open_interactive_terminal", lambda: None)

    decision = prompt_user(DummyScanResult(), "https://example.com/install.sh")

    captured = capsys.readouterr()
    assert decision == "block"
    assert "unable to open an interactive console review prompt" in captured.err
