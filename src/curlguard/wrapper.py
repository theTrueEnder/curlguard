"""Binary wrapper dispatcher module for curlguard."""

import hashlib
import os
import shutil
import subprocess
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path

from curlguard.curl_args import parse_curl_args
from curlguard.logger import AuditEvent


class CurlWrapper:
    def __init__(self, config, scanner, logger, ssl_detector) -> None:
        self._config = config
        self._scanner = scanner
        self._logger = logger
        self._ssl_detector = ssl_detector

    def will_intercept(self, args: list[str]) -> bool:
        return (
            parse_curl_args(args).intercept
            and not self._should_passthrough_for_context()
        )

    def dispatch(self, args: list[str]) -> int:
        started = time.perf_counter()
        invocation = parse_curl_args(args)
        url = invocation.urls[0] if len(invocation.urls) == 1 else ""
        destination = invocation.output

        if not self.will_intercept(args):
            exit_code = self._call_real_curl(args)
            self._log_event(
                url=url,
                destination=destination,
                scan_result="skipped",
                rules_triggered=[],
                user_decision=None,
                ssl_bypass_detected=False,
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
                    ssl_bypass_detected=True,
                    duration_ms=self._elapsed_ms(started),
                    exit_code=1,
                )
                return 1

        temp_path = None
        try:
            temp_path = self._download_to_temp(args)
            scan_result = self._scanner.scan_file(temp_path)

            if scan_result.status in {"unavailable", "error"}:
                return self._handle_scan_failure(
                    started=started,
                    temp_path=temp_path,
                    url=url,
                    destination=destination,
                    scan_result=scan_result,
                    ssl_bypass_detected=ssl_result.is_bypass,
                )

            if not scan_result.clean:
                print(
                    "curlguard: suspicious content detected; opening interactive review prompt.",
                    file=sys.stderr,
                )
                print(
                    f"curlguard: matched rules: {', '.join(scan_result.rules_triggered)}",
                    file=sys.stderr,
                )
                from curlguard.review import prompt_user

                decision = prompt_user(
                    scan_result,
                    url,
                    ssl_warn=ssl_result.is_bypass,
                    interface=self._config.review_interface,
                )
                if decision == "block":
                    self._safe_unlink(temp_path)
                    self._log_event(
                        url=url,
                        destination=destination,
                        scan_result="flagged",
                        rules_triggered=scan_result.rules_triggered,
                        user_decision="block",
                        ssl_bypass_detected=ssl_result.is_bypass,
                        duration_ms=self._elapsed_ms(started),
                        exit_code=1,
                    )
                    return 1
                if decision == "quarantine":
                    self._quarantine_file(temp_path)
                    self._log_event(
                        url=url,
                        destination=destination,
                        scan_result="flagged",
                        rules_triggered=scan_result.rules_triggered,
                        user_decision="quarantine",
                        ssl_bypass_detected=ssl_result.is_bypass,
                        duration_ms=self._elapsed_ms(started),
                        exit_code=1,
                    )
                    return 1

                delivery_target, metadata = self._deliver_file(temp_path, destination)
                self._print_delivery_summary(
                    delivery_target=delivery_target,
                    metadata=metadata,
                    scan_result="flagged",
                    user_decision="allow",
                )
                self._log_event(
                    url=url,
                    destination=destination,
                    scan_result="flagged",
                    rules_triggered=scan_result.rules_triggered,
                    user_decision="allow",
                    ssl_bypass_detected=ssl_result.is_bypass,
                    duration_ms=self._elapsed_ms(started),
                    exit_code=0,
                )
                return 0

            delivery_target, metadata = self._deliver_file(temp_path, destination)
            self._print_delivery_summary(
                delivery_target=delivery_target,
                metadata=metadata,
                scan_result="clean",
                user_decision=None,
            )
            self._log_event(
                url=url,
                destination=destination,
                scan_result="clean",
                rules_triggered=[],
                user_decision=None,
                ssl_bypass_detected=ssl_result.is_bypass,
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
                ssl_bypass_detected=ssl_result.is_bypass,
                duration_ms=self._elapsed_ms(started),
                exit_code=exc.returncode,
            )
            return exc.returncode
        except OSError as exc:
            exit_code = 127 if isinstance(exc, FileNotFoundError) else 1
            print(
                f"curlguard: unable to complete guarded download: {exc}",
                file=sys.stderr,
            )
            self._log_event(
                url=url,
                destination=destination,
                scan_result="error",
                rules_triggered=[],
                user_decision="block",
                ssl_bypass_detected=ssl_result.is_bypass,
                duration_ms=self._elapsed_ms(started),
                exit_code=exit_code,
            )
            return exit_code
        finally:
            if temp_path and temp_path.exists():
                self._safe_unlink(temp_path)

    def _extract_url(self, args: list[str]) -> str | None:
        urls = self._extract_urls(args)
        if not urls:
            return None
        return urls[0]

    def _extract_urls(self, args: list[str]) -> list[str]:
        return list(parse_curl_args(args).urls)

    def _is_url(self, arg: str) -> bool:
        return arg.lower().startswith(("http://", "https://"))

    def _extract_output(self, args: list[str], url: str | None = None) -> str | None:
        return parse_curl_args(args).output

    def _normalize_output(self, output: str) -> str | None:
        if output == "-":
            return None
        return output

    def _should_intercept(self, args: list[str], urls: list[str]) -> bool:
        return self.will_intercept(args)

    def _should_passthrough_for_context(self) -> bool:
        if self._config.force_intercept or not self._config.context_aware_bypass:
            return False
        if os.environ.get("CURLGUARD_SHIM_ACTIVE") != "1":
            return False
        return self._has_passthrough_ancestor()

    def _is_interactive_session(self) -> bool:
        return self._stream_isatty(sys.stdin) or self._stream_isatty(sys.stderr)

    def _stream_isatty(self, stream) -> bool:
        try:
            return stream.isatty()
        except Exception:
            return False

    def _has_passthrough_ancestor(self) -> bool:
        targets = tuple(
            name.lower() for name in self._config.passthrough_process_names if name
        )
        if not targets:
            return False

        seen: set[int] = set()
        pid = os.getppid()
        while pid > 1 and pid not in seen:
            seen.add(pid)
            names = self._read_process_names(pid)
            if any(self._matches_passthrough_process(name, targets) for name in names):
                return True
            pid = self._read_parent_pid(pid)
        return False

    def _read_process_names(self, pid: int) -> set[str]:
        proc_dir = Path("/proc") / str(pid)
        names: set[str] = set()

        try:
            cmdline = (proc_dir / "cmdline").read_bytes().split(b"\0")
        except OSError:
            cmdline = []
        for raw_part in cmdline[:1]:
            if not raw_part:
                continue
            decoded = raw_part.decode("utf-8", errors="ignore")
            if decoded:
                names.add(Path(decoded).name.lower())

        try:
            comm = (proc_dir / "comm").read_text(encoding="utf-8").strip().lower()
        except OSError:
            comm = ""
        if comm:
            names.add(comm)

        try:
            exe_name = Path(os.readlink(proc_dir / "exe")).name.lower()
        except OSError:
            exe_name = ""
        if exe_name:
            names.add(exe_name)

        return names

    def _read_parent_pid(self, pid: int) -> int:
        status_path = Path("/proc") / str(pid) / "status"
        try:
            for line in status_path.read_text(encoding="utf-8").splitlines():
                if line.startswith("PPid:"):
                    return int(line.split(":", 1)[1].strip())
        except (OSError, ValueError):
            return 0
        return 0

    def _matches_passthrough_process(self, name: str, targets: tuple[str, ...]) -> bool:
        return any(
            name == target or name.startswith(f"{target}-") for target in targets
        )

    def _download_to_temp(self, args: list[str]) -> Path:
        with tempfile.NamedTemporaryFile(delete=False, suffix=".download") as handle:
            temp_path = Path(handle.name)

        invocation = parse_curl_args(args)
        if not invocation.intercept:
            self._safe_unlink(temp_path)
            raise ValueError(f"unsupported guarded request: {invocation.reason}")

        cmd = [
            str(self._config.real_curl_path),
            *invocation.download_args,
            "--max-filesize",
            str(self._config.max_download_bytes),
            "--output",
            str(temp_path),
        ]
        result = subprocess.run(cmd, stdout=subprocess.DEVNULL, stderr=subprocess.PIPE)
        if result.returncode != 0:
            self._safe_unlink(temp_path)
            raise subprocess.CalledProcessError(
                result.returncode,
                cmd,
                stderr=result.stderr,
            )
        if temp_path.stat().st_size > self._config.max_download_bytes:
            self._safe_unlink(temp_path)
            raise OSError("download exceeded CURLGUARD_MAX_DOWNLOAD_BYTES")
        return temp_path

    def _sanitize_args(self, args: list[str]) -> list[str]:
        invocation = parse_curl_args(args)
        return list(invocation.download_args) if invocation.intercept else list(args)

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
    ) -> int:
        warning = f"WARNING: curlguard scan {scan_result.status}: {scan_result.error or 'unknown error'}"
        if self._config.scan_failure_mode == "block":
            print(f"{warning}. Blocking download.", file=sys.stderr)
            self._safe_unlink(temp_path)
            self._log_event(
                url=url,
                destination=destination,
                scan_result=scan_result.status,
                rules_triggered=[],
                user_decision="block",
                ssl_bypass_detected=ssl_bypass_detected,
                duration_ms=self._elapsed_ms(started),
                exit_code=1,
            )
            return 1

        print(
            f"{warning}. Delivering content due to configured warn mode.",
            file=sys.stderr,
        )
        delivery_target, metadata = self._deliver_file(temp_path, destination)
        self._print_delivery_summary(
            delivery_target=delivery_target,
            metadata=metadata,
            scan_result=scan_result.status,
            user_decision="allow",
        )
        self._log_event(
            url=url,
            destination=destination,
            scan_result=scan_result.status,
            rules_triggered=[],
            user_decision="allow",
            ssl_bypass_detected=ssl_bypass_detected,
            duration_ms=self._elapsed_ms(started),
            exit_code=0,
        )
        return 0

    def _deliver_file(
        self, temp_path: Path, output_file: str | None
    ) -> tuple[str, str]:
        metadata = self._format_file_metadata(temp_path)
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
        user_decision: str | None,
    ) -> None:
        if scan_result == "clean":
            print(
                f"curlguard: download verified, {delivery_target} ({metadata}).",
                file=sys.stderr,
            )
            return
        if user_decision == "allow":
            print(
                f"curlguard: flagged content was allowed by user decision and {delivery_target} ({metadata}).",
                file=sys.stderr,
            )

    def _format_file_metadata(self, path: Path) -> str:
        digest = hashlib.sha256()
        size = 0
        with path.open("rb") as handle:
            while chunk := handle.read(1024 * 1024):
                size += len(chunk)
                digest.update(chunk)
        checksum = digest.hexdigest()
        return f"{size} bytes, sha256={checksum}"

    def _quarantine_file(self, temp_path: Path) -> Path:
        qdir = self._config.quarantine_dir
        qdir.mkdir(parents=True, exist_ok=True)
        qpath = qdir / f"{int(time.time())}_{temp_path.name}"
        shutil.move(str(temp_path), str(qpath))
        return qpath

    def _log_event(
        self,
        *,
        url: str,
        destination: str | None,
        scan_result: str,
        rules_triggered: list[str],
        user_decision: str | None,
        ssl_bypass_detected: bool,
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
                ssl_bypass_detected=ssl_bypass_detected,
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
