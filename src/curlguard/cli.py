"""CLI entry point for curlguard."""

import argparse
import json
import sys

from curlguard import __version__
from curlguard.config import load_config
from curlguard.edition import EDITION
from curlguard.evidence import safe_text
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

    if not as_curl and argv == ["--version"]:
        print(f"curlguard {__version__} ({EDITION})")
        return 0
    config = load_config()
    if not as_curl and (not argv or argv in (["--help"], ["-h"])):
        print(
            f"curlguard {__version__} ({config.edition})\n"
            "Linux-first staged downloads; scan findings are not proof of safety.\n"
            "Usage: curlguard fetch URL [-o PATH] [--sha256 HEX]\n"
            "       curlguard fetch [URL] --lock FILE [--report FILE|-] [--write-lock FILE]\n"
            "       curlguard scan PATH [--json]\n"
            "       curlguard bootstrap MANIFEST --output-dir NEW_DIR [--json]\n"
            "       curlguard doctor [--json]\n"
            "       curlguard rules {status [--json],update}\n"
            "       curlguard quarantine {list,inspect,rescan,export} [--help]\n"
            "       curlguard <curl arguments>\n"
            "Resolved settings: " + json.dumps(config.settings(), sort_keys=True) + "\n"
            "Exit codes: 10 blocked, 11 quarantined, 12 transport, 13 scanner/rules,\n"
            "14 unsupported, 15 configuration, 16 internal/delivery, 17 integrity,\n"
            "18 transfer budget. Local scan exits 10 for findings even when allowed.\n"
            "Unsupported pass-through is unscanned. Absolute curl calls bypass this wrapper."
        )
        return 0
    if not as_curl and argv and argv[0] == "fetch":
        from curlguard.workflows import handle_fetch

        return handle_fetch(argv[1:], config)
    if not as_curl and argv and argv[0] == "bootstrap":
        from curlguard.workflows import handle_bootstrap

        return handle_bootstrap(argv[1:], config)
    scanner = YaraScanner(
        config.rules_dirs,
        timeout=config.scan_timeout_seconds,
        max_bytes=config.max_scan_bytes,
    )
    if not as_curl and argv and argv[0] == "scan":
        from curlguard.inspection import inspect_file

        parser = argparse.ArgumentParser(prog="curlguard scan")
        parser.add_argument("path")
        parser.add_argument("--json", action="store_true")
        options = parser.parse_args(argv[1:])
        report, code = inspect_file(options.path, config, scanner)
        _report(report, options.json)
        return code
    if not as_curl and argv and argv[0] == "doctor":
        from curlguard.health import inspect

        parser = argparse.ArgumentParser(prog="curlguard doctor")
        parser.add_argument("--json", action="store_true")
        options = parser.parse_args(argv[1:])
        report, code = inspect(config, scanner)
        _report(report, options.json)
        return code
    if not as_curl and argv and argv[0] == "rules":
        from curlguard.auto_updater import AutoUpdater

        parser = argparse.ArgumentParser(prog="curlguard rules")
        parser.add_argument("command", choices=["status", "update"])
        parser.add_argument("--json", action="store_true")
        options = parser.parse_args(argv[1:])
        updater = AutoUpdater(config, scanner)
        if options.command == "update" and not updater.check_and_update():
            _report(updater.status(), options.json)
            return 13
        report = updater.status()
        report.update(edition=config.edition, settings=config.settings())
        _report(report, options.json)
        return 0 if report["usable"] else 13
    logger = AuditLogger(config.log_path)
    wrapper = CurlWrapper(config, scanner, logger, SslBypassDetector())
    try:
        return wrapper.dispatch(argv)
    finally:
        logger.close()


def _report(data, as_json):
    if as_json:
        print(json.dumps(data, sort_keys=True))
    else:
        for key, value in data.items():
            print(safe_text(f"{key}: {value}"))


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
    inspect_parser.add_argument("--json", action="store_true")
    for command in ("rescan", "export"):
        command_parser = subparsers.add_parser(command)
        command_parser.add_argument("identifier")
        command_parser.add_argument("--json", action="store_true")
        if command == "export":
            command_parser.add_argument("destination")

    args = parser.parse_args(argv)
    config = load_config()

    if args.command == "list":
        return _quarantine_list_command(config.quarantine_dir)
    if args.command == "inspect":
        if args.json:
            from curlguard.quarantine import investigate

            report, code = investigate(config, args.identifier, "inspect")
            _report(report, True)
            return code
        return _quarantine_inspect_command(config.quarantine_dir, args.identifier)
    if args.command in {"rescan", "export"}:
        from curlguard.quarantine import investigate

        report, code = investigate(
            config, args.identifier, args.command, getattr(args, "destination", None)
        )
        _report(report, args.json)
        return code

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
            f"- {safe_text(entry.identifier)} | {format_timestamp(entry.timestamp)} | "
            f"{format_size(entry.size_bytes)} | {safe_text(entry.host or 'unknown host')} | {safe_text(rules)}"
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
    print(safe_text(f"Source URL:    {entry.url or 'unknown'}"))
    print(f"Source Host:   {entry.host or 'unknown'}")
    print(safe_text(f"Rules:         {rules}"))
    print(f"Size:          {format_size(entry.size_bytes)}")
    print(f"SHA-256:       {entry.sha256 or 'unknown'}")
    print(f"Payload Path:  {entry.payload_path}")
    print(f"Metadata Path: {entry.metadata_path}")
    return 0


if __name__ == "__main__":
    sys.exit(main())
