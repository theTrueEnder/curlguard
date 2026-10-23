"""Versioned fetch requirements and manifest-driven, fetch-only workflows."""

import argparse
import json
import os
import re
import sys
import tempfile
from contextlib import ExitStack
from dataclasses import replace
from pathlib import Path

from curlguard.policy import normalize_url, sha256
from curlguard.publisher import validate_publisher


def read_lock(path):
    path = Path(path)
    try:
        data = json.loads(path.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read artifact lock") from exc
    if (
        not isinstance(data, dict)
        or type(data.get("schema_version")) is not int
        or data["schema_version"] != 1
        or data.get("kind") != "artifact_lock"
    ):
        raise ValueError(
            "artifact lock requires schema_version=1 and kind=artifact_lock"
        )
    return validate_lock(data, path.parent)


def validate_lock(data, base):
    if set(data) != {"schema_version", "kind", "source", "sha256", "verification"}:
        raise ValueError("unknown or missing artifact lock fields")
    result = dict(data)
    result["source"] = normalize_url(data.get("source"))
    result["sha256"] = sha256(data.get("sha256"))
    requirements = data.get("verification")
    if (
        not isinstance(requirements, dict)
        or set(requirements) - {"scan_required", "publisher"}
        or requirements.get("scan_required") is not True
    ):
        raise ValueError("artifact locks require scan_required=true")
    result["verification"] = dict(requirements)
    if "publisher" in requirements:
        result["verification"]["publisher"] = validate_publisher(
            requirements["publisher"], base
        )
    return result


def handle_fetch(argv, config):
    from curlguard.logger import AuditLogger
    from curlguard.scanner import YaraScanner
    from curlguard.ssl_detector import SslBypassDetector
    from curlguard.wrapper import CurlWrapper

    parser = argparse.ArgumentParser(prog="curlguard fetch")
    parser.add_argument("url", nargs="?")
    parser.add_argument("-o", "--output")
    parser.add_argument("--sha256", type=sha256)
    parser.add_argument("--lock", type=Path)
    parser.add_argument("--write-lock", type=Path)
    parser.add_argument("--report", help="new JSON file, or '-' for stderr")
    options = parser.parse_args(argv)
    lock = read_lock(options.lock) if options.lock else None
    try:
        source = normalize_url(options.url or (lock and lock["source"]))
    except ValueError as exc:
        parser.error(str(exc))
    if lock and source != lock["source"]:
        raise ValueError("URL conflicts with artifact lock")
    pins = {
        p
        for p in (options.sha256, config.expected_sha256, lock and lock["sha256"])
        if p
    }
    if len(pins) > 1:
        raise ValueError("conflicting expected SHA-256 values")
    config.expected_sha256 = next(iter(pins), None)
    config.publisher = lock["verification"].get("publisher") if lock else None
    config.unsupported_policy = "block"
    config.scan_failure_mode = "block"
    config.noninteractive = True
    if options.output == "":
        parser.error("output path must not be empty")
    args = ["--disable", "--fail", "--location", "--url", source]
    if options.output:
        args += ["--output", options.output]
    paths = [
        Path(p).resolve()
        for p in (
            options.output,
            options.report if options.report != "-" else None,
            options.write_lock,
            options.lock,
            config.log_path,
            *(
                config.publisher[key]
                for key in ("bundle", "trusted_root")
                if config.publisher
            ),
        )
        if p
    ]
    if len(set(paths)) != len(paths):
        raise ValueError("payload, report, lock and audit paths must be distinct")
    scanner = YaraScanner(
        config.rules_dirs,
        timeout=config.scan_timeout_seconds,
        max_bytes=config.max_scan_bytes,
    )
    logger = AuditLogger(config.log_path)
    wrapper = CurlWrapper(config, scanner, logger, SslBypassDetector())
    # Reserve machine-readable outputs before the request, without overwriting.
    with ExitStack() as stack:
        streams = {}
        for key, path in (("report", options.report), ("lock", options.write_lock)):
            if path and path != "-":
                fd = os.open(
                    path, os.O_WRONLY | os.O_CREAT | os.O_EXCL | os.O_NOFOLLOW, 0o600
                )
                streams[key] = stack.enter_context(os.fdopen(fd, "w"))
        try:
            code = wrapper.dispatch(args)
            report = wrapper.report(code)
            if options.report == "-":
                print(json.dumps(report, sort_keys=True), file=sys.stderr)
            elif "report" in streams:
                json.dump(report, streams["report"], sort_keys=True)
                streams["report"].write("\n")
            if "lock" in streams and code == 0:
                requirements = {"scan_required": True}
                if config.publisher:
                    requirements["publisher"] = config.publisher
                json.dump(
                    {
                        "schema_version": 1,
                        "kind": "artifact_lock",
                        "source": source,
                        "sha256": report["sha256"],
                        "verification": requirements,
                    },
                    streams["lock"],
                    sort_keys=True,
                )
                streams["lock"].write("\n")
            return code
        finally:
            logger.close()


def handle_bootstrap(argv, config):
    from curlguard.evidence import safe_text
    from curlguard.logger import AuditLogger
    from curlguard.reports import publish_new
    from curlguard.scanner import YaraScanner
    from curlguard.ssl_detector import SslBypassDetector
    from curlguard.wrapper import CurlWrapper

    parser = argparse.ArgumentParser(prog="curlguard bootstrap")
    parser.add_argument("manifest", type=Path)
    parser.add_argument("--output-dir", type=Path, required=True)
    parser.add_argument("--json", action="store_true")
    options = parser.parse_args(argv)
    try:
        manifest = json.loads(options.manifest.read_text(encoding="utf-8"))
    except (OSError, ValueError) as exc:
        raise ValueError("cannot read bootstrap manifest") from exc
    if (
        not isinstance(manifest, dict)
        or set(manifest) != {"schema_version", "kind", "artifacts"}
        or type(manifest["schema_version"]) is not int
        or manifest["schema_version"] != 1
        or manifest["kind"] != "bootstrap_manifest"
        or not isinstance(manifest["artifacts"], list)
        or not manifest["artifacts"]
    ):
        raise ValueError("invalid bootstrap manifest schema")
    artifacts, names = [], set()
    for raw in manifest["artifacts"]:
        if (
            not isinstance(raw, dict)
            or set(raw) != {"id", "role", "lock"}
            or not isinstance(raw["id"], str)
            or not re.fullmatch(r"[A-Za-z0-9][A-Za-z0-9_.-]{0,127}", raw["id"])
            or raw["id"] in names
            or not isinstance(raw["role"], str)
            or raw["role"] not in {"bootstrap", "secondary"}
        ):
            raise ValueError("invalid or duplicate bootstrap artifact")
        names.add(raw["id"])
        if (
            not isinstance(raw["lock"], dict)
            or type(raw["lock"].get("schema_version")) is not int
            or raw["lock"].get("schema_version") != 1
            or raw["lock"].get("kind") != "artifact_lock"
        ):
            raise ValueError("invalid embedded artifact lock")
        lock = validate_lock(raw["lock"], options.manifest.parent)
        if config.expected_sha256 and config.expected_sha256 != lock["sha256"]:
            raise ValueError("manifest conflicts with configured hash")
        if (options.output_dir / raw["id"]).resolve() == config.log_path.resolve():
            raise ValueError("artifact path conflicts with audit path")
        artifacts.append((raw, lock))
    if not any(raw["role"] == "bootstrap" for raw, _ in artifacts):
        raise ValueError("manifest must declare a bootstrap artifact")
    options.output_dir.mkdir(mode=0o700)
    report = {
        "schema_version": 1,
        "kind": "bootstrap_report",
        "coverage": "declared_artifacts_only",
        "undeclared_secondary_downloads": "outside_coverage",
        "artifacts": [],
    }
    code = 0
    logger = AuditLogger(config.log_path)
    try:
        with tempfile.TemporaryDirectory(
            prefix="curlguard-bootstrap-", dir=options.output_dir
        ) as directory:
            for raw, lock in artifacts:
                cfg = replace(
                    config,
                    expected_sha256=lock["sha256"],
                    publisher=lock["verification"].get("publisher"),
                    noninteractive=True,
                    scan_failure_mode="block",
                    unsupported_policy="block",
                )
                scanner = YaraScanner(
                    cfg.rules_dirs,
                    timeout=cfg.scan_timeout_seconds,
                    max_bytes=cfg.max_scan_bytes,
                )
                wrapper = CurlWrapper(cfg, scanner, logger, SslBypassDetector())
                staged = Path(directory) / raw["id"]
                code = wrapper.dispatch(
                    [
                        "--disable",
                        "--fail",
                        "--location",
                        "--url",
                        lock["source"],
                        "--output",
                        str(staged),
                    ]
                )
                item = {"id": raw["id"], "role": raw["role"], **wrapper.report(code)}
                report["artifacts"].append(item)
                if code:
                    break
                try:
                    publish_new(staged, options.output_dir / raw["id"])
                except OSError:
                    code = item["exit_code"] = 16
                    item["publication"] = "failed"
                    break
    finally:
        logger.close()
    report["exit_code"] = code
    print(json.dumps(report, sort_keys=True) if options.json else safe_text(report))
    return code
