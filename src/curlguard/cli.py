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


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="curlguard",
        description="Secure curl wrapper with YARA malware scanning",
        epilog="""Test your install:
  Terminal 1: python3 examples/true_positive/start_server.py
  Terminal 2: curl http://127.0.0.1:8888/test.sh | bash
  (server auto-expires after 60s; malware triggers TUI prompt)

SSL bypass detection is always on. Logs: ~/.curlguard/audit.log (per-user)
or /var/log/curlguard/audit.log (system-wide).""",
    )
    parser.add_argument("--version", action="version", version=f"curlguard {__version__}")
    parser.add_argument("curl_args", nargs=argparse.REMAINDER, help="Arguments to pass to curl")
    args = parser.parse_args()

    if not args.curl_args:
        parser.print_help()
        return 0

    config = load_config()
    scanner = YaraScanner(config.rules_dirs)
    AutoUpdater(config, scanner).check_and_update()
    logger = AuditLogger(config.log_path)
    ssl_detector = SslBypassDetector()
    wrapper = CurlWrapper(config, scanner, logger, ssl_detector)

    try:
        return wrapper.dispatch(args.curl_args)
    finally:
        logger.close()


if __name__ == "__main__":
    sys.exit(main())
