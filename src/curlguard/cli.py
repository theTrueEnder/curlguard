"""CLI entry point for curlguard."""
import argparse
import sys

from curlguard import __version__
from curlguard.auto_updater import AutoUpdater
from curlguard.config import load_config
from curlguard.logger import AuditLogger
from curlguard.scanner import YaraScanner
from curlguard.ssl_detector import SslBypassDetector
from curlguard.wrapper import CurlWrapper


def _build_parser() -> argparse.ArgumentParser:
    return argparse.ArgumentParser(
        prog="curlguard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Linux-first curl safety wrapper.\n"
            "Downloads supported single-URL requests with the real curl, scans the content,\n"
            "and prompts before delivery when suspicious patterns are detected."
        ),
        epilog="""Examples:
  curlguard https://example.com/install.sh
  curlguard -fsSL https://example.com/install.sh -o install.sh
  curlguard --version

Best-supported flows:
  - single-URL downloads
  - installer-style commands such as: curl ... | bash
  - explicit output files with -o / --output

Pass-through behavior:
  Requests outside the supported interception path are delegated to the real curl.

Testing:
  python3 examples/true_positive/start_server.py
  curl http://127.0.0.1:8888/test.sh | bash

Logs:
  Per-user:    ~/.curlguard/audit.log
  System-wide: /var/log/curlguard/audit.log""",
    )


def main(argv: list[str] | None = None) -> int:
    curl_args = list(sys.argv[1:] if argv is None else argv)
    parser = _build_parser()

    if not curl_args:
        parser.print_help()
        return 0
    if curl_args in (["-h"], ["--help"]):
        parser.print_help()
        return 0
    if curl_args == ["--version"]:
        print(f"curlguard {__version__}")
        return 0

    config = load_config()
    scanner = YaraScanner(config.rules_dirs)
    AutoUpdater(config, scanner).check_and_update()
    logger = AuditLogger(config.log_path)
    ssl_detector = SslBypassDetector()
    wrapper = CurlWrapper(config, scanner, logger, ssl_detector)

    try:
        return wrapper.dispatch(curl_args)
    finally:
        logger.close()


if __name__ == "__main__":
    sys.exit(main())
