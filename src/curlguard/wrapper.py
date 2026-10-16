"""Prepare, fetch, validate, scan, and atomically commit supported GET downloads."""

import json
import os
import re
import shutil
import stat
import subprocess
import sys
import tempfile
import time
import uuid
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlsplit

from curlguard.arguments import parse
from curlguard.evidence import safe_text
from curlguard.logger import AuditEvent, redact_url
from curlguard.policy import evaluate_findings, hash_file
from curlguard.process import Interrupted, run
from curlguard.ssl_detector import enforce_transport
from curlguard.transfer import TransferState


def fingerprint(path):
    try:
        s = Path(path).lstat()
        return s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode
    except FileNotFoundError:
        return None


class CurlWrapper:
    EXIT_BLOCKED = 10
    EXIT_QUARANTINED = 11
    EXIT_SSL_BLOCKED = 12
    EXIT_SCAN_FAILURE_BLOCKED = 13
    EXIT_UNSUPPORTED = 14
    EXIT_CONFIG = 15
    EXIT_INTERNAL = 16
    EXIT_INTEGRITY = 17

    def __init__(self, config, scanner, logger, ssl_detector):
        self._config, self._scanner = config, scanner
        self._logger, self._ssl_detector = logger, ssl_detector
        self._state = TransferState()

    def dispatch(self, args):
        started = time.monotonic()
        self._state = TransferState()
        code = self.EXIT_INTERNAL
        try:
            self._validate_binary()
            if args and args[0] in {
                "--help",
                "-h",
                "--version",
                "-V",
                "--manual",
                "-M",
            }:
                self._state.reason = "native_information"
                code = self._call_real_curl(args)
                return code
            r = self._state.request = parse(args)
            if not r.reason and not self._metadata_supported():
                r.reason = "curl lacks JSON transfer metadata (requires curl >= 7.70)"
            if r.reason:
                self._state.reason = "unsupported_request"
                if (
                    self._config.unsupported_policy == "block"
                    or self._config.require_sha256
                    or self._config.expected_sha256
                    or self._config.policy.artifacts
                ):
                    self._state.decision = "block"
                    print(
                        safe_text(
                            f"curlguard: unsupported request blocked: {r.reason}"
                        ),
                        file=sys.stderr,
                    )
                    code = self.EXIT_UNSUPPORTED
                else:
                    print(
                        f"curlguard: unscanned pass-through: {safe_text(r.reason)}",
                        file=sys.stderr,
                    )
                    code = self._call_real_curl(args)
                return code
            self._state.reason = "supported_get"
            url = r.urls[0]
            rejection = self._prepare_request(r)
            if rejection is not None:
                code = rejection
                return code
            payload = self._download_to_temp(args)
            self._state.stage = "validate"
            self._state.evidence.transport["final_scheme"] = urlsplit(
                self._state.effective_url or url
            ).scheme
            if not self._config.policy.final_allowed(
                url, self._state.effective_url or url
            ):
                self._state.decision, self._state.reason = (
                    "block",
                    "final_origin_not_allowed",
                )
                code = self.EXIT_SSL_BLOCKED
                return code
            not_modified = self._state.metadata["http_code"] == 304
            if not_modified:
                self._check_destination(r.destination, self._state.snapshot)
                if r.destination and Path(r.destination).is_file():
                    # Scan an immutable staged copy, never the live destination.
                    shutil.copyfile(r.destination, payload)
                elif self._state.expected or self._config.require_sha256:
                    self._state.evidence.integrity = "missing_required"
                    self._state.decision, self._state.reason = (
                        "block",
                        "retained_artifact_missing",
                    )
                    code = self.EXIT_INTEGRITY
                    return code
            result, rejection = self._collect_evidence(payload)
            if rejection is not None:
                code = rejection
                return code
            if result.status in {"unavailable", "error"}:
                self._state.error = "scan_failure"
                self._state.reason = "scan_failure_policy"
                print(
                    safe_text(
                        f"WARNING: curlguard scan {result.status}: {result.error}"
                    ),
                    file=sys.stderr,
                )
                if self._config.scan_failure_mode == "block":
                    self._state.decision = "block"
                    code = self.EXIT_SCAN_FAILURE_BLOCKED
                    return code
                self._state.decision = "allow"
            elif not result.clean:
                suppressed = self._config.policy.suppressed(
                    url, self._state.effective_url or url, self._state.facts["sha256"]
                )
                decision = evaluate_findings(result, self._config, suppressed)
                self._state.decision, self._state.reason = (
                    decision.action,
                    decision.reason,
                )
                if self._state.decision == "prompt":
                    self._state.decision, _ = self._resolve_flagged_action(
                        scan_result=result,
                        url=redact_url(url),
                        ssl_warn=self._state.bypass,
                    )
                    self._state.reason = "interactive_review"
                elif self._state.decision == "allow":
                    print(
                        f"curlguard: flagged content allowed: {self._state.reason}",
                        file=sys.stderr,
                    )
                if self._state.decision == "block":
                    code = self.EXIT_BLOCKED
                    return code
                if self._state.decision == "quarantine":
                    self._state.stage = "quarantine"
                    q = self._quarantine_file(
                        payload,
                        url=url,
                        rules_triggered=self._state.rules,
                        file_facts=self._state.facts,
                    )
                    self._state.quarantined = str(q)
                    print(
                        safe_text(f"curlguard: suspicious content quarantined at {q}"),
                        file=sys.stderr,
                    )
                    code = self.EXIT_QUARANTINED
                    return code
            else:
                self._state.reason = "scan_no_matches"
            if not_modified:
                self._state.reason = "not_modified_revalidated"
                self._check_destination(r.destination, self._state.snapshot)
                self._commit_etag()
                self._emit_writeout()
                code = 0
                return code
            self._state.stage = "commit"
            # Preflight both outputs before changing either. ETag failure must never
            # make an unchanged payload appear successfully refreshed.
            self._check_destination(r.destination, self._state.snapshot)
            self._check_destination(
                r.values.get("etag-save"), self._state.etag_snapshot
            )
            target, metadata = self._commit_outputs(payload)
            self._emit_writeout()
            self._print_delivery_summary(
                delivery_target=target,
                metadata=metadata,
                scan_result=self._state.status,
                decision_reason=self._state.reason,
                user_decision=self._state.decision,
            )
            code = 0
            return code
        except subprocess.CalledProcessError as exc:
            self._state.error, self._state.reason, self._state.status = (
                "curl_failure",
                "curl_failure",
                "error",
            )
            if exc.stderr:
                sys.stderr.buffer.write(exc.stderr)
            code = exc.returncode
            try:
                self._emit_writeout()
            except BrokenPipeError:
                # Preserve the original transfer failure; suppress shutdown flushing.
                self._silence_broken_pipe()
            return code
        except BrokenPipeError:
            self._state.error = "broken_pipe"
            # Avoid a second broken pipe when Python flushes stdout at shutdown.
            self._silence_broken_pipe()
            code = 23
            return code
        except Interrupted as exc:
            self._state.error = "interrupted"
            code = 128 + exc.signum
            return code
        except KeyboardInterrupt:
            self._state.error = "interrupted"
            code = 130
            return code
        except ValueError as exc:
            self._state.error = "configuration"
            print(safe_text(f"curlguard: {exc}"), file=sys.stderr)
            code = self.EXIT_CONFIG
            return code
        except Exception as exc:
            self._state.error = type(exc).__name__
            self._state.status = "error"
            print(
                f"curlguard: {self._state.stage} failed ({type(exc).__name__})",
                file=sys.stderr,
            )
            code = self.EXIT_INTERNAL
            return code
        finally:
            r = self._state.request
            for path in self._state.temporary:
                self._safe_unlink(path)
            self._state.evidence.decision = self._state.decision or (
                "allow" if code == 0 else "block"
            )
            self._state.evidence.reason = self._state.reason
            self._logger.log(
                AuditEvent(
                    timestamp=datetime.now(timezone.utc).isoformat(),
                    url=r.urls[0] if r and len(r.urls) == 1 else "",
                    destination=r.destination if r else None,
                    scan_result=self._state.status,
                    rules_triggered=self._state.rules,
                    user_decision=self._state.decision,
                    decision_reason=self._state.reason,
                    ssl_bypass_detected=self._state.bypass,
                    content_sha256=self._state.facts.get("sha256"),
                    content_size_bytes=self._state.facts.get("size"),
                    quarantine_path=self._state.quarantined,
                    duration_ms=(time.monotonic() - started) * 1000,
                    exit_code=code,
                    stage=self._state.stage,
                    error_category=self._state.error,
                    interception_reason=r.reason if r else None,
                    effective_url=self._state.effective_url or None,
                    ruleset_id=getattr(self._scanner, "ruleset_id", None),
                    edition=self._config.edition,
                    settings=self._config.settings(),
                    evidence=self._state.evidence.public(),
                )
            )

    def _collect_evidence(self, payload):
        """Inspect and scan staged bytes; no output publication happens here."""
        self._state.facts = self._inspect_file(payload)
        if self._state.expected:
            if self._state.facts["sha256"] != self._state.expected:
                print(
                    "curlguard: expected SHA-256 mismatch; delivery blocked",
                    file=sys.stderr,
                )
                self._state.evidence.integrity = "mismatched"
                self._state.decision, self._state.reason = "block", "sha256_mismatch"
                code = self.EXIT_INTEGRITY
                return None, code
            self._state.evidence.integrity = "matched"
        self._state.stage = "scan"
        result = self._scanner.scan_file(payload)
        self._state.status, self._state.rules = result.status, result.rules_triggered
        self._state.evidence.detection = (
            "no_matches" if result.status == "clean" else result.status
        )
        self._state.evidence.findings = getattr(result, "findings", [])
        return result, None

    def _prepare_request(self, request):
        """Resolve pins, transport and cached rules before any payload request."""
        r = request
        url = r.urls[0]
        if self._config.trusted_hosts or self._config.trusted_sha256:
            raise ValueError(
                "legacy trust allowances removed; migrate to scoped policy exceptions"
            )
        self._state.expected = self._config.policy.expected(
            url, self._config.expected_sha256
        )
        if self._config.require_sha256 and not self._state.expected:
            print(
                "curlguard: expected SHA-256 required before downloading",
                file=sys.stderr,
            )
            self._state.evidence.integrity = "missing_required"
            self._state.decision, self._state.reason = (
                "block",
                "missing_required_sha256",
            )
            code = self.EXIT_INTEGRITY
            return code
        ssl = self._ssl_detector.detect(r.options, url)
        self._state.bypass = ssl.is_bypass
        self._state.transport_options, violations = enforce_transport(r, self._config)
        self._state.evidence.transport = {
            "initial_scheme": urlsplit(url).scheme,
            "certificate_verification_requested": "insecure" not in r.flags,
            "minimum_tls_enforced": self._config.min_tls,
            "negotiated_tls": None,
            "findings": violations,
            "diagnostic": ssl.message if ssl.is_bypass else None,
        }
        if ssl.is_bypass:
            print(f"WARNING: {safe_text(ssl.message)}", file=sys.stderr)
        if violations or (ssl.severity == "block" and not self._config.ssl_warn_only):
            self._state.decision, self._state.reason = "block", "transport_policy"
            code = self.EXIT_SSL_BLOCKED
            return code
        if self._config.update_url:
            from curlguard.auto_updater import AutoUpdater

            self._state.stage = "rules"
            feed = AutoUpdater(self._config, self._scanner).load_active()
            if not feed["usable"]:
                print(
                    "curlguard: configured signed rule feed is unavailable or expired; run rules update",
                    file=sys.stderr,
                )
                if self._config.require_fresh_rules:
                    self._state.decision, self._state.reason = (
                        "block",
                        "required_rules_unavailable",
                    )
                    code = self.EXIT_SCAN_FAILURE_BLOCKED
                    return code
        return None

    def _validate_binary(self):
        path = self._config.real_curl_path
        with path.open("rb") as handle:
            prefix = handle.read(4096)
        if b"curlguard" in prefix or path.resolve() == Path(sys.argv[0]).resolve():
            raise ValueError("real curl resolves to a curlguard wrapper")

    def _silence_broken_pipe(self):
        try:
            fd = os.open(os.devnull, os.O_WRONLY)
            try:
                os.dup2(fd, sys.stdout.fileno())
            finally:
                os.close(fd)
        except (OSError, AttributeError):
            pass

    def _metadata_supported(self):
        p = subprocess.run(
            [str(self._config.real_curl_path), "--version"],
            capture_output=True,
            timeout=5,
        )
        match = re.match(rb"curl (\d+)\.(\d+)\.(\d+)", p.stdout)
        return (
            p.returncode == 0
            and match is not None
            and tuple(map(int, match.groups())) >= (7, 70, 0)
        )

    def _temp(self, destination=None):
        fd, name = tempfile.mkstemp(
            prefix=".curlguard-",
            suffix=".download",
            dir=str(Path(destination).absolute().parent) if destination else None,
        )
        os.close(fd)
        path = Path(name)
        self._state.temporary.append(path)
        return path

    def _download_to_temp(self, args):
        r = self._state.request or parse(args)
        self._state.snapshot = fingerprint(r.destination) if r.destination else None
        payload = self._temp(r.destination)
        if "continue-at" in r.values and r.destination and Path(r.destination).exists():
            shutil.copyfile(r.destination, payload)
        self._state.etag_snapshot = (
            fingerprint(r.values["etag-save"]) if "etag-save" in r.values else None
        )
        self._state.etag = (
            self._temp(r.values["etag-save"]) if "etag-save" in r.values else None
        )
        headers = self._temp()
        marker = "\nCURLGUARD-" + uuid.uuid4().hex + "\n"
        fmt = "%{json}" + marker + r.values.get("write-out", "")
        cmd = [
            str(self._config.real_curl_path),
            "--disable",
            *r.options,
            *self._state.transport_options,
            "--output",
            str(payload),
            "--dump-header",
            str(headers),
            "--write-out",
            fmt,
        ]
        if self._state.etag:
            cmd += ["--etag-save", str(self._state.etag)]
        cmd += ["--url", r.urls[0]]
        self._state.stage = "fetch"
        p = run(cmd, stdout=subprocess.PIPE)
        meta, separator, self._state.writeout = (p.stdout or b"").partition(
            marker.encode()
        )
        if p.returncode:
            raise subprocess.CalledProcessError(p.returncode, cmd)
        if not separator:
            raise OSError("curl did not return transfer metadata")
        try:
            self._state.metadata = json.loads(meta)
            if not isinstance(self._state.metadata["http_code"], int) or not isinstance(
                self._state.metadata["url_effective"], str
            ):
                raise ValueError("wrong metadata types")
        except (ValueError, KeyError, TypeError) as exc:
            raise OSError("invalid curl transfer metadata") from exc
        self._state.effective_url = self._state.metadata["url_effective"]
        if self._state.metadata["http_code"] == 206 and "continue-at" not in r.values:
            raise OSError("unexpected partial response")
        if self._state.metadata["http_code"] == 206:
            blocks = headers.read_bytes().replace(b"\r\n", b"\n").split(b"\n\n")
            final = [block for block in blocks if block.startswith(b"HTTP/")][-1]
            fields = dict(
                line.split(b":", 1) for line in final.split(b"\n")[1:] if b":" in line
            )
            content_range = next(
                (v.strip() for k, v in fields.items() if k.lower() == b"content-range"),
                b"",
            )
            match = re.fullmatch(rb"bytes (\d+)-(\d+)/(\d+)", content_range)
            offset = r.values["continue-at"]
            expected = (
                self._state.snapshot[2]
                if offset == "-" and self._state.snapshot
                else int(offset if offset != "-" else "0")
            )
            if not match:
                raise OSError("invalid resume Content-Range")
            first, last, size = map(int, match.groups())
            if first != expected or last + 1 != size or payload.stat().st_size != size:
                raise OSError("inconsistent resume Content-Range")
        return payload

    def _check_destination(self, path, snapshot):
        if path and fingerprint(path) != snapshot:
            raise OSError("destination changed during download")

    def _commit_etag(self):
        if self._state.etag:
            dest = self._state.request.values["etag-save"]
            self._check_destination(dest, self._state.etag_snapshot)
            os.replace(self._state.etag, dest)

    def _commit_outputs(self, payload):
        """Rollback ETag changes if payload delivery fails; never replay stdout."""
        dest = self._state.request.values.get("etag-save")
        backup = None
        changed = None
        if dest and Path(dest).exists():
            backup = self._temp(dest)
            shutil.copy2(dest, backup)
        try:
            self._commit_etag()
            changed = fingerprint(dest) if dest else None
            return self._deliver_file(
                payload, self._state.request.destination, file_facts=self._state.facts
            )
        except BaseException:
            if (
                dest
                and fingerprint(dest) == changed
                and changed != self._state.etag_snapshot
            ):
                if backup:
                    os.replace(backup, dest)
                else:
                    Path(dest).unlink(missing_ok=True)
            raise

    def _deliver_file(self, temp_path, output_file, *, file_facts=None):
        metadata = self._format_file_metadata(
            file_facts or self._inspect_file(temp_path)
        )
        if output_file:
            self._check_destination(output_file, self._state.snapshot)
            if self._state.snapshot:
                os.chmod(temp_path, stat.S_IMODE(self._state.snapshot[-1]) & 0o777)
            os.replace(temp_path, output_file)
            return f"saved to {output_file}", metadata
        with temp_path.open("rb") as handle:
            shutil.copyfileobj(handle, sys.stdout.buffer)
        sys.stdout.buffer.flush()
        return "written to stdout", metadata

    def _emit_writeout(self):
        if self._state.writeout:
            sys.stdout.buffer.write(self._state.writeout)
            sys.stdout.buffer.flush()
            self._state.writeout = b""

    def _print_delivery_summary(
        self, *, delivery_target, metadata, scan_result, decision_reason, user_decision
    ):
        if self._state.request and "--silent" in self._state.request.options:
            return
        if scan_result == "clean":
            description = "scan completed: no rules matched"
        elif scan_result == "flagged":
            description = (
                f"flagged content was allowed via {decision_reason.replace('_', ' ')}"
            )
        else:
            description = f"content was delivered via {decision_reason}"
        if self._state.evidence.integrity == "matched":
            description += "; expected SHA-256 matched"
        print(
            safe_text(f"curlguard: {description}, {delivery_target} ({metadata})."),
            file=sys.stderr,
        )

    def _inspect_file(self, path):
        return hash_file(Path(path))

    def _format_file_metadata(self, facts):
        return f"{facts['size']} bytes, sha256={facts['sha256']}"

    def _quarantine_file(self, temp_path, *, url, rules_triggered, file_facts):
        qdir = self._config.quarantine_dir
        qdir.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd, name = tempfile.mkstemp(
            prefix=f"{int(time.time())}_", suffix=".download", dir=qdir
        )
        qpath = Path(name)
        sidecar = qpath.with_suffix(qpath.suffix + ".json")
        try:
            with os.fdopen(fd, "wb") as out, temp_path.open("rb") as src:
                shutil.copyfileobj(src, out)
            data = {
                "url": redact_url(url),
                "rules_triggered": rules_triggered,
                "sha256": file_facts["sha256"],
                "size_bytes": file_facts["size"],
                "timestamp": datetime.now(timezone.utc).isoformat(),
            }
            fd = os.open(sidecar, os.O_WRONLY | os.O_CREAT | os.O_EXCL, 0o600)
            with os.fdopen(fd, "w") as handle:
                json.dump(data, handle)
            return qpath
        except BaseException:
            self._safe_unlink(qpath)
            self._safe_unlink(sidecar)
            raise

    def _resolve_flagged_action(self, *, scan_result, url, ssl_warn):
        policy = self._config.match_policy
        if policy == "prompt":
            from curlguard.tui import prompt_user

            return prompt_user(scan_result, url, ssl_warn), "interactive review"
        print(
            f"curlguard: suspicious content: {', '.join(scan_result.rules_triggered)}; policy={policy}",
            file=sys.stderr,
        )
        return policy, "configured policy"

    def _call_real_curl(self, args):
        self._state.stage = "passthrough"
        return run([str(self._config.real_curl_path), *args]).returncode

    def _safe_unlink(self, path):
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    # Compatibility helpers for callers inspecting request shapes.
    def _extract_urls(self, args):
        return parse(args, check_config=False).urls

    def _extract_url(self, args):
        urls = self._extract_urls(args)
        return urls[0] if urls else None

    def _extract_output(self, args, url=None):
        return parse(args, check_config=False).destination

    def _should_intercept(self, args, urls):
        return parse(args).reason is None

    def _sanitize_args(self, args):
        r = parse(args, check_config=False)
        return [*r.options, "--url", *r.urls]
