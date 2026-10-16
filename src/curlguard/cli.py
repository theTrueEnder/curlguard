"""CLI entry point for curlguard."""

import argparse
import sys

from curlguard import __version__
from curlguard.config import load_config
from curlguard.logger import AuditLogger
from curlguard.process import Interrupted, cancellation
from curlguard.quarantine import (
    format_size,
    format_timestamp,
    list_entries,
    resolve_entry,
)
from curlguard.scanner import YaraScanner
from curlguard.ssl_detector import SslBypassDetector
from curlguard.wrapper import CurlWrapper


def main() -> int:
    try:
        with cancellation():
            return _main()
    except Interrupted as exc:
        return 128 + exc.signum
    except ValueError as exc:
        print(f"curlguard: {exc}", file=sys.stderr)
        return 15
    except KeyboardInterrupt:
        return 130
    except Exception as exc:
        print(
            f"curlguard: initialization failed ({type(exc).__name__})", file=sys.stderr
        )
        return 16


def _main() -> int:
    argv = sys.argv[1:]
    as_curl = bool(argv and argv[0] == "--as-curl")
    if as_curl:
        argv = argv[1:]
    if not as_curl and argv and argv[0] == "quarantine":
        return _handle_quarantine_cli(argv[1:])

    parser = argparse.ArgumentParser(
        prog="curlguard",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description=(
            "Linux-first safe-curl wrapper.\n"
            "curlguard intercepts supported download flows, fetches them with the real curl,\n"
            "scans the payload before delivery, and applies lightweight trust and quarantine policy."
        ),
        epilog="""Examples:
  curlguard https://example.com/install.sh
  curlguard -fsSL https://example.com/install.sh -o install.sh
  curlguard -fsSL -O https://example.com/releases/tool.sh
  curlguard quarantine list
  curlguard quarantine inspect 1713900000_payload.download
  curlguard --version

Best-supported flows:
  - single-URL downloads
  - installer-style commands such as: curl ... | bash
  - explicit output files with -o / --output
  - remote-name downloads with -O / --remote-name

Pass-through behavior:
  Requests outside the supported interception path are delegated to the real curl.

Quarantine tools:
  curlguard quarantine list      show stored suspicious payloads
  curlguard quarantine inspect   show metadata for one quarantined payload

Flagged content policy:
  CURLGUARD_MATCH_POLICY=quarantine   default; store file locally and stop delivery
  CURLGUARD_MATCH_POLICY=prompt       open the interactive review TUI
  CURLGUARD_MATCH_POLICY=block        refuse delivery
  CURLGUARD_MATCH_POLICY=allow        deliver with a warning

Trust controls:
  CURLGUARD_TRUSTED_HOSTS=downloads.example.com,artifacts.example.com
  CURLGUARD_TRUSTED_SHA256=<sha256>,<sha256>
  CURLGUARD_TRUST_FILE=~/.curlguard/trust.json

Exit codes:
  0   delivered or allowed
  10  blocked due to suspicious content
  11  quarantined due to suspicious content
  12  blocked by SSL/TLS policy
  13  blocked because scanning failed and fail-closed mode is enabled
  14  unsupported request blocked
  15  invalid configuration
  16  internal or delivery failure

Testing:
  python3 examples/true_positive/start_server.py
  curl http://127.0.0.1:8888/test.sh | bash

Logs:
  Per-user:    ~/.curlguard/audit.log
  System-wide: /var/log/curlguard/audit.log""",
    )
    parser.add_argument(
        "--version", action="version", version=f"curlguard {__version__}"
    )
    parser.add_argument(
        "curl_args",
        nargs=argparse.REMAINDER,
        help="Arguments to pass through to curlguard and then curl",
    )
    if not as_curl and (not argv or argv == ["--help"] or argv == ["-h"]):
        parser.print_help()
        return 0
    if not as_curl and argv == ["--version"]:
        print(f"curlguard {__version__}")
        return 0

    config = load_config()
    scanner = YaraScanner(
        config.rules_dirs,
        timeout=config.scan_timeout_seconds,
        max_bytes=config.max_scan_bytes,
    )
    logger = AuditLogger(config.log_path)
    ssl_detector = SslBypassDetector()
    wrapper = CurlWrapper(config, scanner, logger, ssl_detector)

    try:
        return wrapper.dispatch(argv)
    finally:
        logger.close()


def _handle_quarantine_cli(argv: list[str]) -> int:
    parser = argparse.ArgumentParser(
        prog="curlguard quarantine",
        formatter_class=argparse.RawDescriptionHelpFormatter,
        description="Inspect quarantined payloads and their metadata.",
    )
    subparsers = parser.add_subparsers(dest="command")

    subparsers.add_parser("list", help="List quarantined payloads")

    inspect_parser = subparsers.add_parser(
        "inspect", help="Show one quarantined payload"
    )
    inspect_parser.add_argument(
        "identifier", help="Payload name, prefix, or metadata path"
    )

    args = parser.parse_args(argv)
    config = load_config()

    if args.command == "list":
        return _quarantine_list_command(config.quarantine_dir)
    if args.command == "inspect":
        return _quarantine_inspect_command(config.quarantine_dir, args.identifier)

    parser.print_help()
    return 0


def _quarantine_list_command(quarantine_dir) -> int:
    entries = list_entries(quarantine_dir)
    if not entries:
        print(f"curlguard: no quarantined payloads found in {quarantine_dir}.")
        return 0

    print(f"curlguard quarantine: {len(entries)} item(s) in {quarantine_dir}")
    for entry in entries:
        rules = ", ".join(entry.rules_triggered) if entry.rules_triggered else "none"
        print(
            f"- {entry.identifier} | {format_timestamp(entry.timestamp)} | "
            f"{format_size(entry.size_bytes)} | {entry.host or 'unknown host'} | {rules}"
        )
    return 0


def _quarantine_inspect_command(quarantine_dir, identifier: str) -> int:
    entry = resolve_entry(quarantine_dir, identifier)
    if entry is None:
        print(
            f"curlguard: no quarantined payload matched '{identifier}' in {quarantine_dir}.",
            file=sys.stderr,
        )
        return 1

    rules = ", ".join(entry.rules_triggered) if entry.rules_triggered else "none"
    print(f"Identifier:    {entry.identifier}")
    print(f"Captured:      {format_timestamp(entry.timestamp)}")
    print(f"Source URL:    {entry.url or 'unknown'}")
    print(f"Source Host:   {entry.host or 'unknown'}")
    print(f"Rules:         {rules}")
    print(f"Size:          {format_size(entry.size_bytes)}")
    print(f"SHA-256:       {entry.sha256 or 'unknown'}")
    print(f"Payload Path:  {entry.payload_path}")
    print(f"Metadata Path: {entry.metadata_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
