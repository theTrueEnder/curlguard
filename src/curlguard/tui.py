"""Interactive terminal prompt for curlguard malware decisions."""

import argparse
import json
import os
import subprocess
import sys
from pathlib import Path

try:
    from textual.app import App, ComposeResult
    from textual.binding import Binding
    from textual.containers import Container, Horizontal
    from textual.reactive import reactive
    from textual.widgets import Button, Static
except ModuleNotFoundError as exc:
    _TEXTUAL_IMPORT_ERROR = exc
    _TEXTUAL_AVAILABLE = False
else:
    _TEXTUAL_IMPORT_ERROR = None
    _TEXTUAL_AVAILABLE = True


if _TEXTUAL_AVAILABLE:
    class CurlGuardTUI(App[int]):
        """Textual app shown when curlguard flags suspicious content."""

        CSS = """
        Screen {
            background: #111827;
            color: #f9fafb;
        }

        #title {
            dock: top;
            background: #7f1d1d;
            color: #ffffff;
            padding: 0 1;
            text-style: bold;
        }

        #subtitle {
            dock: top;
            background: #1f2937;
            color: #d1d5db;
            padding: 0 1;
        }

        #ssl_warning {
            dock: top;
            background: #92400e;
            color: #fff7ed;
            padding: 0 1;
        }

        .panel {
            background: #1f2937;
            border: round #374151;
            padding: 0 1;
            margin: 0 1 1 1;
        }

        #actions {
            height: auto;
            margin: 0 1 1 1;
        }

        Button {
            width: 1fr;
            min-width: 16;
            margin: 0 1 0 0;
        }

        #allow_btn {
            margin: 0;
        }

        #keys {
            dock: bottom;
            background: #0f172a;
            color: #cbd5e1;
            padding: 0 1;
        }
        """

        BINDINGS = [
            Binding("b", "block", "Block", priority=True),
            Binding("q", "quarantine", "Quarantine", priority=True),
            Binding("a", "allow", "Allow", priority=True),
            Binding("ctrl+c", "cancel", "Cancel", show=False),
        ]

        matched_rules = reactive[list[str]]([])
        url = reactive("")
        ssl_warn = reactive(False)

        def __init__(self, rules: list[str], url: str, ssl_warn: bool = False) -> None:
            super().__init__()
            self.matched_rules = rules
            self.url = url
            self.ssl_warn = ssl_warn

        def compose(self) -> ComposeResult:
            yield Static("curlguard review required", id="title")
            yield Static(
                "Suspicious content was detected before delivery. Choose block, quarantine, or allow.",
                id="subtitle",
            )
            if self.ssl_warn:
                yield Static(
                    "TLS warning: the request used an insecure or downgraded transport option.",
                    id="ssl_warning",
                )
            yield Container(Static(f"Source URL: {self.url}"), classes="panel")
            yield Container(
                Static(f"Matched rules: {', '.join(self.matched_rules)}"),
                classes="panel",
            )
            with Horizontal(id="actions"):
                yield Button("Block [B]", id="block_btn", variant="error")
                yield Button("Quarantine [Q]", id="quarantine_btn", variant="warning")
                yield Button("Allow [A]", id="allow_btn", variant="success")
            yield Static(
                "Keys: [B] block   [Q] quarantine   [A] allow   [Ctrl+C] cancel",
                id="keys",
            )

        def on_button_pressed(self, event: Button.Pressed) -> None:
            if event.button.id == "block_btn":
                self.action_block()
            elif event.button.id == "quarantine_btn":
                self.action_quarantine()
            elif event.button.id == "allow_btn":
                self.action_allow()

        def action_block(self) -> None:
            self.exit(1)

        def action_quarantine(self) -> None:
            self.exit(2)

        def action_allow(self) -> None:
            self.exit(0)

        def action_cancel(self) -> None:
            self.exit(3)
else:
    CurlGuardTUI = None


def run_tui(rules: list[str], url: str, ssl_warn: bool = False) -> int:
    """Run the Textual app in the current process and return a decision code."""

    if not _TEXTUAL_AVAILABLE:
        raise RuntimeError(
            "Textual is not installed; install curlguard[tui] or textual>=0.50.0 to use the TUI"
        ) from _TEXTUAL_IMPORT_ERROR

    app = CurlGuardTUI(rules=rules, url=url, ssl_warn=ssl_warn)
    result = app.run()
    if isinstance(result, int):
        return result
    return 3


def _interactive_tty_path() -> Path | None:
    if os.name == "posix":
        tty_path = Path("/dev/tty")
        if tty_path.exists():
            return tty_path
    return None


def _launch_tui_subprocess(rules: list[str], url: str, ssl_warn: bool) -> int:
    tty_path = _interactive_tty_path()
    if tty_path is None:
        raise RuntimeError("no interactive terminal is available")

    cmd = [
        sys.executable,
        "-m",
        "curlguard.tui",
        "--rules-json",
        json.dumps(rules),
        "--url",
        url,
    ]
    if ssl_warn:
        cmd.append("--ssl-warn")

    with tty_path.open("r", encoding="utf-8", errors="ignore") as tty_in, tty_path.open(
        "w", encoding="utf-8", errors="ignore"
    ) as tty_out:
        result = subprocess.run(cmd, stdin=tty_in, stdout=tty_out, stderr=tty_out)

    return result.returncode


def prompt_user(scan_result, url: str, ssl_warn: bool = False) -> str:
    """Prompt the user for a malware decision via the controlling terminal."""

    rules = getattr(scan_result, "rules_triggered", []) or []
    code_map = {0: "allow", 1: "block", 2: "quarantine", 3: "block"}

    try:
        exit_code = _launch_tui_subprocess(rules=rules, url=url, ssl_warn=ssl_warn)
    except Exception as exc:
        print(
            f"curlguard: unable to open an interactive review prompt ({exc}); blocking download.",
            file=sys.stderr,
        )
        return "block"

    return code_map.get(exit_code, "block")


def main(argv: list[str] | None = None) -> int:
    """CLI entry point for the standalone TUI subprocess."""

    if not _TEXTUAL_AVAILABLE:
        print(
            "curlguard: Textual is not installed; install curlguard[tui] or textual>=0.50.0.",
            file=sys.stderr,
        )
        return 1

    parser = argparse.ArgumentParser(prog="python -m curlguard.tui")
    parser.add_argument("--rules-json", required=True, help="JSON array of matched rule names")
    parser.add_argument("--url", required=True, help="The URL that was scanned")
    parser.add_argument(
        "--ssl-warn",
        action="store_true",
        help="Show the TLS warning banner in the interface",
    )
    args = parser.parse_args(argv)

    try:
        rules = json.loads(args.rules_json)
    except json.JSONDecodeError:
        rules = []

    if not isinstance(rules, list):
        rules = []

    normalized_rules = [str(rule) for rule in rules]
    return run_tui(rules=normalized_rules, url=args.url, ssl_warn=args.ssl_warn)


if __name__ == "__main__":
    raise SystemExit(main())
