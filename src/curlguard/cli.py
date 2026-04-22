"""CLI entry point for curlguard."""
import argparse
import sys
from pathlib import Path

from curlguard import __version__
from curlguard.config import load_config
from curlguard.scanner import YaraScanner
from curlguard.logger import AuditLogger, AuditEvent
from curlguard.ssl_detector import SslBypassDetector
from curlguard.wrapper import CurlWrapper


def main() -> int:
    parser = argparse.ArgumentParser(
        prog="curlguard",
        description="Secure curl wrapper with YARA malware scanning",
    )
    parser.add_argument("--version", action="version", version=f"curlguard {__version__}")
    parser.add_argument("curl_args", nargs=argparse.REMAINDER, help="Arguments to pass to curl")
    args = parser.parse_args()

    if not args.curl_args:
        parser.print_help()
        return 0

    config = load_config()
    scanner = YaraScanner(config.rules_dirs)
    logger = AuditLogger(config.log_path)
    ssl_detector = SslBypassDetector()
    wrapper = CurlWrapper(config, scanner, logger, ssl_detector)

    try:
        return wrapper.dispatch(args.curl_args)
    finally:
        logger.close()


if __name__ == "__main__":
    sys.exit(main())