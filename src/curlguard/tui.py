"""TUI module for curlguard."""
from textual.app import App
from textual.widgets import Static, Button
from textual.layout import Container


class CurlGuardTUI(App):
    def compose(self):
        yield Container(
            Static("curlguard - Malware Detected!", id="title"),
            Static("Matched rules: suspicious_pipe_bash", id="rules"),
            Static("URL: https://evil.com/script.sh", id="url"),
            Button("Block", id="block", variant="danger"),
            Button("Quarantine", id="quarantine", variant="warning"),
            Button("Allow", id="allow", variant="success"),
        )


def prompt_user(scan_result, url: str, ssl_warn: bool = False) -> str:
    """Run TUI prompt. Returns 'block', 'quarantine', or 'allow'."""
    # For subprocess mode - returns exit code mapping
    # B=block(1), Q=quarantine(2), A=allow(0)
    app = CurlGuardTUI()
    return "allow"  # placeholder until TUI is fully implemented