from textual.app import App, ComposeResult
from textual.widgets import Static, Button
from textual.containers import Container, Vertical
from textual.binding import Binding
from textual.reactive import reactive
import sys


class CurlGuardTUI(App):
    CSS = """
    Screen { background: #1e1e2e; }
    #title { dock: top; height: 3; background: #f0384e; color: white; padding: 0 2; text-style: bold; }
    #ssl_warning { dock: top; height: 3; background: #f0a04e; color: black; padding: 0 2; }
    #info_container { dock: top; height: 5; background: #2e2e3e; padding: 1 2; }
    #rules_container { dock: top; height: 4; background: #3e2e2e; padding: 1 2; }
    Button { width: 100%; margin: 1 0; }
    #block_btn { background: #f0384e; }
    #quarantine_btn { background: #f0a04e; }
    #allow_btn { background: #38b04e; }
    """

    BINDINGS = [
        Binding("b", "block", "Block", priority=True),
        Binding("q", "quarantine", "Quarantine", priority=True),
        Binding("a", "allow", "Allow", priority=True),
        Binding("ctrl+c", "exit", "Exit", show=False),
    ]

    scan_result = reactive(None)
    matched_rules = reactive([])
    url = reactive("")
    ssl_warn = reactive(False)

    def __init__(self, rules: list, url: str, ssl_warn: bool = False):
        super().__init__()
        self.matched_rules = rules
        self.url = url
        self.ssl_warn = ssl_warn

    def compose(self) -> ComposeResult:
        if self.ssl_warn:
            yield Static("WARNING: SSL BYPASS DETECTED -- Connection may be insecure", id="ssl_warning")
        yield Static("curlguard -- MALWARE DETECTED", id="title")
        yield Container(Static(f"URL: {self.url}"), id="info_container")
        yield Container(Static(f"Matched rules: {', '.join(self.matched_rules)}"), id="rules_container")
        with Vertical():
            yield Button("Block (B)", id="block_btn", variant="error")
            yield Button("Quarantine (Q)", id="quarantine_btn", variant="warning")
            yield Button("Allow (A)", id="allow_btn", variant="success")

    def action_block(self) -> None:
        self.exit(1)

    def action_quarantine(self) -> None:
        self.exit(2)

    def action_allow(self) -> None:
        self.exit(0)

    def action_exit(self) -> None:
        self.exit(3)


def prompt_user(scan_result, url: str, ssl_warn: bool = False) -> str:
    import subprocess
    rules = getattr(scan_result, 'rules_triggered', []) or []
    code_map = {0: "allow", 1: "block", 2: "quarantine", 3: "block"}
    try:
        result = subprocess.run(
            [sys.executable, "-c",
             f"from curlguard.tui import CurlGuardTUI; "
             f"app = CurlGuardTUI(rules={rules!r}, url={url!r}, ssl_warn={ssl_warn!r}); "
             f"app.run()"],
            timeout=60, capture_output=True,
        )
        return code_map.get(result.returncode, "block")
    except Exception:
        return "block"