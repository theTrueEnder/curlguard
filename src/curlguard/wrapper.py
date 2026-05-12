"""Binary wrapper dispatcher module for curlguard."""
import hashlib
import json
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urlparse

from curlguard.logger import AuditEvent


class CurlWrapper:
    EXIT_BLOCKED = 10
    EXIT_QUARANTINED = 11
    EXIT_SSL_BLOCKED = 12
    EXIT_SCAN_FAILURE_BLOCKED = 13

    def __init__(self, config, scanner, logger, ssl_detector) -> None:
        self._config = config
        self._scanner = scanner
        self._logger = logger
        self._ssl_detector = ssl_detector

    def dispatch(self, args: list[str]) -> int:
        started = time.perf_counter()
        urls = self._extract_urls(args)
        url = urls[0] if len(urls) == 1 else ""
        destination = self._extract_output(args, url)

        if not self._should_intercept(args, urls):
            exit_code = self._call_real_curl(args)
            self._log_event(
                url=url,
                destination=destination,
                scan_result="skipped",
                rules_triggered=[],
                user_decision=None,
                decision_reason="unsupported request shape",
                ssl_bypass_detected=False,
                content_sha256=None,
                content_size_bytes=None,
                quarantine_path=None,
                duration_ms=self._elapsed_ms(started),
                exit_code=exit_code,
            )
            return exit_code

        ssl_result = self._ssl_detector.detect(args, url)
        if ssl_result.is_bypass:
            print(f"WARNING: {ssl_result.message}", file=sys.stderr)
            if ssl_result.severity == "block" and not self._config.ssl_warn_only:
                self._log_event(
                    url=url,
                    destination=destination,
                    scan_result="skipped",
                    rules_triggered=[],
                    user_decision="block",
                    decision_reason="ssl policy",
                    ssl_bypass_detected=True,
                    content_sha256=None,
                    content_size_bytes=None,
                    quarantine_path=None,
                    duration_ms=self._elapsed_ms(started),
                    exit_code=self.EXIT_SSL_BLOCKED,
                )
                return self.EXIT_SSL_BLOCKED

        temp_path = None
        try:
            temp_path = self._download_to_temp(args)
            file_facts = self._inspect_file(temp_path)
            scan_result = self._scanner.scan_file(temp_path)

            if scan_result.status in {"unavailable", "error"}:
                return self._handle_scan_failure(
                    started=started,
                    temp_path=temp_path,
                    url=url,
                    destination=destination,
                    scan_result=scan_result,
                    ssl_bypass_detected=ssl_result.is_bypass,
                    file_facts=file_facts,
                )

            if not scan_result.clean:
                trust_reason = self._get_trust_reason(url, file_facts["sha256"])
                if trust_reason:
                    delivery_target, metadata = self._deliver_file(
                        temp_path,
                        destination,
                        file_facts=file_facts,
                    )
                    self._print_delivery_summary(
                        delivery_target=delivery_target,
                        metadata=metadata,
                        scan_result="flagged",
                        decision_reason=trust_reason,
                        user_decision="allow",
                    )
                    self._log_event(
                        url=url,
                        destination=destination,
                        scan_result="flagged",
                        rules_triggered=scan_result.rules_triggered,
                        user_decision="allow",
                        decision_reason=trust_reason,
                        ssl_bypass_detected=ssl_result.is_bypass,
                        content_sha256=file_facts["sha256"],
                        content_size_bytes=file_facts["size"],
                        quarantine_path=None,
                        duration_ms=self._elapsed_ms(started),
                        exit_code=0,
                    )
                    return 0

                decision, decision_reason = self._resolve_flagged_action(
                    scan_result=scan_result,
                    url=url,
                    ssl_warn=ssl_result.is_bypass,
                )
                if decision == "block":
                    self._safe_unlink(temp_path)
                    self._log_event(
                        url=url,
                        destination=destination,
                        scan_result="flagged",
                        rules_triggered=scan_result.rules_triggered,
                        user_decision="block",
                        decision_reason=decision_reason,
                        ssl_bypass_detected=ssl_result.is_bypass,
                        content_sha256=file_facts["sha256"],
                        content_size_bytes=file_facts["size"],
                        quarantine_path=None,
                        duration_ms=self._elapsed_ms(started),
                        exit_code=self.EXIT_BLOCKED,
                    )
                    return self.EXIT_BLOCKED
                if decision == "quarantine":
                    quarantine_path = self._quarantine_file(
                        temp_path,
                        url=url,
                        rules_triggered=scan_result.rules_triggered,
                        file_facts=file_facts,
                    )
                    self._print_quarantine_summary(quarantine_path, file_facts, decision_reason)
                    self._log_event(
                        url=url,
                        destination=destination,
                        scan_result="flagged",
                        rules_triggered=scan_result.rules_triggered,
                        user_decision="quarantine",
                        decision_reason=decision_reason,
                        ssl_bypass_detected=ssl_result.is_bypass,
                        content_sha256=file_facts["sha256"],
                        content_size_bytes=file_facts["size"],
                        quarantine_path=str(quarantine_path),
                        duration_ms=self._elapsed_ms(started),
                        exit_code=self.EXIT_QUARANTINED,
                    )
                    return self.EXIT_QUARANTINED

                delivery_target, metadata = self._deliver_file(
                    temp_path,
                    destination,
                    file_facts=file_facts,
                )
                self._print_delivery_summary(
                    delivery_target=delivery_target,
                    metadata=metadata,
                    scan_result="flagged",
                    decision_reason=decision_reason,
                    user_decision="allow",
                )
                self._log_event(
                    url=url,
                    destination=destination,
                    scan_result="flagged",
                    rules_triggered=scan_result.rules_triggered,
                    user_decision="allow",
                    decision_reason=decision_reason,
                    ssl_bypass_detected=ssl_result.is_bypass,
                    content_sha256=file_facts["sha256"],
                    content_size_bytes=file_facts["size"],
                    quarantine_path=None,
                    duration_ms=self._elapsed_ms(started),
                    exit_code=0,
                )
                return 0

            delivery_target, metadata = self._deliver_file(
                temp_path,
                destination,
                file_facts=file_facts,
            )
            self._print_delivery_summary(
                delivery_target=delivery_target,
                metadata=metadata,
                scan_result="clean",
                decision_reason=None,
                user_decision=None,
            )
            self._log_event(
                url=url,
                destination=destination,
                scan_result="clean",
                rules_triggered=[],
                user_decision=None,
                decision_reason="scan clean",
                ssl_bypass_detected=ssl_result.is_bypass,
                content_sha256=file_facts["sha256"],
                content_size_bytes=file_facts["size"],
                quarantine_path=None,
                duration_ms=self._elapsed_ms(started),
                exit_code=0,
            )
            return 0
        except subprocess.CalledProcessError as exc:
            if exc.stderr:
                sys.stderr.buffer.write(exc.stderr)
            self._log_event(
                url=url,
                destination=destination,
                scan_result="error",
                rules_triggered=[],
                user_decision=None,
                decision_reason="real curl failed",
                ssl_bypass_detected=ssl_result.is_bypass,
                content_sha256=None,
                content_size_bytes=None,
                quarantine_path=None,
                duration_ms=self._elapsed_ms(started),
                exit_code=exc.returncode,
            )
            return exc.returncode
        finally:
            if temp_path and temp_path.exists():
                self._safe_unlink(temp_path)

    def _extract_url(self, args: list[str]) -> str | None:
        urls = self._extract_urls(args)
        if not urls:
            return None
        return urls[0]

    def _extract_urls(self, args: list[str]) -> list[str]:
        return [
            arg for arg in args
            if arg.startswith(("http://", "https://", "ftp://", "sftp://"))
        ]

    def _extract_output(self, args: list[str], url: str | None = None) -> str | None:
        for i, arg in enumerate(args):
            if arg in ("-o", "--output"):
                if i + 1 < len(args):
                    return None if args[i + 1] == "-" else args[i + 1]
            elif arg.startswith("-o") and len(arg) > 2:
                value = arg[2:]
                return None if value == "-" else value
            elif arg.startswith("--output="):
                value = arg[9:]
                return None if value == "-" else value
            elif arg in ("-O", "--remote-name") and url:
                return self._remote_name_from_url(url)
        return None

    def _should_intercept(self, args: list[str], urls: list[str]) -> bool:
        if len(urls) != 1:
            return False

        unsupported_flags = {
            "-I",
            "--head",
            "-T",
            "--upload-file",
            "-F",
            "--form",
            "-d",
            "--data",
            "--data-raw",
            "--data-binary",
            "--data-urlencode",
            "--next",
            "-J",
            "--remote-header-name",
        }
        return not any(arg in unsupported_flags for arg in args)

    def _download_to_temp(self, args: list[str]) -> Path:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".download") as handle:
            temp_path = Path(handle.name)

        cmd = [str(self._config.real_curl_path), *self._sanitize_args(args), "--output", str(temp_path)]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if result.returncode != 0:
            self._safe_unlink(temp_path)
            raise subprocess.CalledProcessError(
                result.returncode,
                cmd,
                stderr=result.stderr,
            )
        return temp_path

    def _sanitize_args(self, args: list[str]) -> list[str]:
        sanitized: list[str] = []
        skip_next = False
        for arg in args:
            if skip_next:
                skip_next = False
                continue
            if arg in {"-o", "--output"}:
                skip_next = True
                continue
            if arg.startswith("--output="):
                continue
            if arg.startswith("-o") and arg != "-o":
                continue
            if arg in {"-O", "--remote-name"}:
                continue
            sanitized.append(arg)
        return sanitized

    def _call_real_curl(self, args: list[str]) -> int:
        cmd = [str(self._config.real_curl_path)] + args
        result = subprocess.run(cmd)
        return result.returncode

    def _handle_scan_failure(
        self,
        *,
        started: float,
        temp_path: Path,
        url: str,
        destination: str | None,
        scan_result,
        ssl_bypass_detected: bool,
        file_facts: dict[str, str | int],
    ) -> int:
        warning = (
            f"WARNING: curlguard scan {scan_result.status}: {scan_result.error or 'unknown error'}"
        )
        if self._config.scan_failure_mode == "block":
            print(f"{warning}. Blocking download.", file=sys.stderr)
            self._safe_unlink(temp_path)
            self._log_event(
                url=url,
                destination=destination,
                scan_result=scan_result.status,
                rules_triggered=[],
                user_decision="block",
                decision_reason="scan failure policy",
                ssl_bypass_detected=ssl_bypass_detected,
                content_sha256=file_facts["sha256"],
                content_size_bytes=file_facts["size"],
                quarantine_path=None,
                duration_ms=self._elapsed_ms(started),
                exit_code=self.EXIT_SCAN_FAILURE_BLOCKED,
            )
            return self.EXIT_SCAN_FAILURE_BLOCKED

        print(f"{warning}. Delivering content due to configured warn mode.", file=sys.stderr)
        delivery_target, metadata = self._deliver_file(
            temp_path,
            destination,
            file_facts=file_facts,
        )
        self._print_delivery_summary(
            delivery_target=delivery_target,
            metadata=metadata,
            scan_result=scan_result.status,
            decision_reason="scan failure policy",
            user_decision="allow",
        )
        self._log_event(
            url=url,
            destination=destination,
            scan_result=scan_result.status,
            rules_triggered=[],
            user_decision="allow",
            decision_reason="scan failure policy",
            ssl_bypass_detected=ssl_bypass_detected,
            content_sha256=file_facts["sha256"],
            content_size_bytes=file_facts["size"],
            quarantine_path=None,
            duration_ms=self._elapsed_ms(started),
            exit_code=0,
        )
        return 0

    def _deliver_file(
        self,
        temp_path: Path,
        output_file: str | None,
        *,
        file_facts: dict[str, str | int] | None = None,
    ) -> tuple[str, str]:
        facts = file_facts or self._inspect_file(temp_path)
        metadata = self._format_file_metadata(facts)
        if output_file:
            shutil.move(str(temp_path), output_file)
            return f"saved to {output_file}", metadata

        with temp_path.open("rb") as handle:
            shutil.copyfileobj(handle, sys.stdout.buffer)
        self._safe_unlink(temp_path)
        return "written to stdout", metadata

    def _print_delivery_summary(
        self,
        *,
        delivery_target: str,
        metadata: str,
        scan_result: str,
        decision_reason: str | None,
        user_decision: str | None,
    ) -> None:
        if scan_result == "clean":
            print(
                f"curlguard: download verified, {delivery_target} ({metadata}).",
                file=sys.stderr,
            )
            return
        if scan_result in {"unavailable", "error"} and user_decision == "allow":
            reason_suffix = f" via {decision_reason}" if decision_reason else ""
            print(
                f"curlguard: content was delivered{reason_suffix} and {delivery_target} ({metadata}).",
                file=sys.stderr,
            )
            return
        if user_decision == "allow":
            reason_suffix = f" via {decision_reason}" if decision_reason else ""
            print(
                f"curlguard: flagged content was allowed{reason_suffix} and {delivery_target} ({metadata}).",
                file=sys.stderr,
            )

    def _print_quarantine_summary(
        self,
        quarantine_path: Path,
        file_facts: dict[str, str | int],
        decision_reason: str | None,
    ) -> None:
        metadata = self._format_file_metadata(file_facts)
        reason_suffix = f" via {decision_reason}" if decision_reason else ""
        print(
            f"curlguard: suspicious content quarantined{reason_suffix} at {quarantine_path} ({metadata}).",
            file=sys.stderr,
        )

    def _format_file_metadata(self, file_facts: dict[str, str | int]) -> str:
        return f"{file_facts['size']} bytes, sha256={file_facts['sha256']}"

    def _inspect_file(self, path: Path) -> dict[str, str | int]:
        payload = path.read_bytes()
        return {
            "sha256": hashlib.sha256(payload).hexdigest(),
            "size": len(payload),
        }

    def _quarantine_file(
        self,
        temp_path: Path,
        *,
        url: str,
        rules_triggered: list[str],
        file_facts: dict[str, str | int],
    ) -> Path:
        qdir = self._config.quarantine_dir
        qdir.mkdir(parents=True, exist_ok=True)
        qpath = qdir / f"{int(time.time())}_{temp_path.name}"
        shutil.move(str(temp_path), str(qpath))
        metadata_path = qpath.with_suffix(qpath.suffix + ".json")
        metadata_path.write_text(
            json.dumps(
                {
                    "url": url,
                    "rules_triggered": rules_triggered,
                    "sha256": file_facts["sha256"],
                    "size_bytes": file_facts["size"],
                    "timestamp": datetime.now(timezone.utc).isoformat(),
                },
                indent=2,
            ),
            encoding="utf-8",
        )
        return qpath

    def _log_event(
        self,
        *,
        url: str,
        destination: str | None,
        scan_result: str,
        rules_triggered: list[str],
        user_decision: str | None,
        decision_reason: str | None,
        ssl_bypass_detected: bool,
        content_sha256: str | None,
        content_size_bytes: int | None,
        quarantine_path: str | None,
        duration_ms: float,
        exit_code: int,
    ) -> None:
        self._logger.log(
            AuditEvent(
                timestamp=datetime.now(timezone.utc).isoformat(),
                url=url,
                destination=destination,
                scan_result=scan_result,
                rules_triggered=rules_triggered,
                user_decision=user_decision,
                decision_reason=decision_reason,
                ssl_bypass_detected=ssl_bypass_detected,
                content_sha256=content_sha256,
                content_size_bytes=content_size_bytes,
                quarantine_path=quarantine_path,
                duration_ms=duration_ms,
                exit_code=exit_code,
            )
        )

    def _elapsed_ms(self, started: float) -> float:
        return (time.perf_counter() - started) * 1000

    def _safe_unlink(self, path: Path) -> None:
        try:
            path.unlink(missing_ok=True)
        except OSError:
            pass

    def stream_scan(self, args: list[str]) -> Iterator[bytes]:
        cmd = [str(self._config.real_curl_path)] + args
        proc = subprocess.Popen(cmd, stdout=subprocess.PIPE)
        buffer = bytearray()
        for chunk in iter(lambda: proc.stdout.read(8192), b""):
            buffer.extend(chunk)
            yield chunk

        # Scan accumulated buffer
        if buffer:
            result = self._scanner.scan(bytes(buffer))
            if not result.clean:
                proc.terminate()
                raise ValueError(f"Malware detected: {result.rules_triggered}")

    def _resolve_flagged_action(self, *, scan_result, url: str, ssl_warn: bool) -> tuple[str, str]:
        matched_rules = ", ".join(scan_result.rules_triggered)
        if self._config.match_policy == "prompt":
            print(
                "curlguard: suspicious content detected; opening interactive review prompt.",
                file=sys.stderr,
            )
            print(f"curlguard: matched rules: {matched_rules}", file=sys.stderr)
            from curlguard.tui import prompt_user

            return prompt_user(scan_result, url, ssl_warn), "interactive review"

        if self._config.match_policy == "quarantine":
            print(
                f"curlguard: suspicious content detected; quarantining due to configured policy. Matched rules: {matched_rules}",
                file=sys.stderr,
            )
            return "quarantine", "configured policy"

        if self._config.match_policy == "block":
            print(
                f"curlguard: suspicious content detected; blocking due to configured policy. Matched rules: {matched_rules}",
                file=sys.stderr,
            )
            return "block", "configured policy"

        print(
            f"curlguard: suspicious content detected; delivering due to configured policy. Matched rules: {matched_rules}",
            file=sys.stderr,
        )
        return "allow", "configured policy"

    def _get_trust_reason(self, url: str, checksum: str) -> str | None:
        host = urlparse(url).hostname.lower() if urlparse(url).hostname else ""
        if checksum in self._config.trusted_sha256:
            return "trusted checksum"
        if host and self._is_trusted_host(host):
            return "trusted host"
        return None

    def _is_trusted_host(self, host: str) -> bool:
        return any(
            host == trusted_host or host.endswith(f".{trusted_host}")
            for trusted_host in self._config.trusted_hosts
        )

    def _remote_name_from_url(self, url: str) -> str | None:
        parsed = urlparse(url)
        filename = Path(parsed.path).name
        return filename or None
