"""Console review prompt for curlguard flagged downloads."""

import os
import sys
from typing import TextIO


def _open_interactive_terminal() -> tuple[TextIO, TextIO] | None:
    try:
        if os.name == "posix":
            return (
                open("/dev/tty", encoding="utf-8", errors="ignore"),
                open("/dev/tty", "w", encoding="utf-8", errors="ignore"),
            )
        if os.name == "nt":
            return (
                open("CONIN$", encoding="utf-8", errors="ignore"),
                open("CONOUT$", "w", encoding="utf-8", errors="ignore"),
            )
    except OSError:
        return None
    return None


def _close_terminal(reader: TextIO, writer: TextIO) -> None:
    try:
        reader.close()
    finally:
        if writer is not reader:
            writer.close()


def prompt_user(scan_result, url: str, ssl_warn: bool = False) -> str:
    """Prompt the user for a review decision in a plain console UI."""

    rules = getattr(scan_result, "rules_triggered", []) or []
    terminal = _open_interactive_terminal()
    if terminal is None:
        print(
            "curlguard: unable to open an interactive console review prompt; blocking download.",
            file=sys.stderr,
        )
        return "block"

    reader, writer = terminal
    try:
        writer.write("\ncurlguard review required\n")
        writer.write("Suspicious content was detected before delivery.\n")
        writer.write(f"Source URL: {url}\n")
        writer.write(f"Matched rules: {', '.join(rules) or 'none'}\n")
        if ssl_warn:
            writer.write(
                "TLS warning: the request used an insecure or downgraded transport option.\n"
            )
        writer.write("Choose [B]lock, [Q]uarantine, or [A]llow.\n")
        while True:
            writer.write("Decision [B/Q/A]: ")
            writer.flush()
            response = reader.readline()
            if response == "":
                raise RuntimeError("interactive terminal closed")

            choice = response.strip().lower()
            if choice in {"b", "block"}:
                return "block"
            if choice in {"q", "quarantine"}:
                return "quarantine"
            if choice in {"a", "allow"}:
                return "allow"

            writer.write("Please enter B, Q, or A.\n")
    except (KeyboardInterrupt, OSError, RuntimeError) as exc:
        print(
            f"curlguard: unable to complete console review prompt ({exc}); blocking download.",
            file=sys.stderr,
        )
        return "block"
    finally:
        _close_terminal(reader, writer)
