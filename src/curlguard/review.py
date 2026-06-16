"""Review interface selection for curlguard flagged downloads."""

import sys


def prompt_user(
    scan_result,
    url: str,
    ssl_warn: bool = False,
    interface: str = "tui",
) -> str:
    """Prompt the user through the configured review interface."""

    if interface == "console":
        from curlguard.console_ui import prompt_user as prompt_console_user

        return prompt_console_user(scan_result, url, ssl_warn=ssl_warn)

    try:
        import curlguard.tui as tui_module
    except ModuleNotFoundError as exc:
        if exc.name and exc.name.startswith("textual"):
            print(
                "curlguard: Textual is not installed; falling back to the console review prompt.",
                file=sys.stderr,
            )
            from curlguard.console_ui import prompt_user as prompt_console_user

            return prompt_console_user(scan_result, url, ssl_warn=ssl_warn)
        raise

    if not getattr(tui_module, "_TEXTUAL_AVAILABLE", True):
        print(
            "curlguard: Textual is not installed; falling back to the console review prompt.",
            file=sys.stderr,
        )
        from curlguard.console_ui import prompt_user as prompt_console_user

        return prompt_console_user(scan_result, url, ssl_warn=ssl_warn)

    return tui_module.prompt_user(scan_result, url, ssl_warn=ssl_warn)
