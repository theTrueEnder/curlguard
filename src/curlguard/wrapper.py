"""Binary wrapper dispatcher module for curlguard."""
import hashlib
import shutil
import subprocess
import sys
import tempfile
import time
from collections.abc import Iterator
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import unquote, urlparse

from curlguard.logger import AuditEvent


class CurlWrapper:
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

        if len(urls) > 1:
            print(
                "curlguard: multiple URLs in one curl command are not supported; "
                "run one URL per command so each response can be scanned",
                file=sys.stderr,
            )
            self._log_event(
                url=url,
                destination=destination,
                scan_result="skipped",
                rules_triggered=[],
                user_decision=None,
                ssl_bypass_detected=False,
                duration_ms=self._elapsed_ms(started),
                exit_code=2,
            )
            return 2

        if not self._should_intercept(args, urls):
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
                from curlguard.tui import prompt_user

                decision = prompt_user(scan_result, url, ssl_result.is_bypass)
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
        finally:
            if temp_path and temp_path.exists():
                self._safe_unlink(temp_path)

    def _extract_url(self, args: list[str]) -> str | None:
        urls = self._extract_urls(args)
        if not urls:
            return None
        return urls[0]

    def _extract_urls(self, args: list[str]) -> list[str]:
        urls: list[str] = []
        take_next_as_url = False
        for arg in args:
            if take_next_as_url:
                if self._is_url(arg):
                    urls.append(arg)
                take_next_as_url = False
                continue
            if arg == "--url":
                take_next_as_url = True
                continue
            if arg.startswith("--url="):
                maybe_url = arg[6:]
                if self._is_url(maybe_url):
                    urls.append(maybe_url)
                continue
            if self._is_url(arg):
                urls.append(arg)
        return urls

    def _is_url(self, arg: str) -> bool:
        return arg.startswith(("http://", "https://", "ftp://", "sftp://"))

    def _extract_output(self, args: list[str], url: str | None = None) -> str | None:
        for i, arg in enumerate(args):
            if arg in ("-o", "--output"):
                if i + 1 < len(args):
                    return self._normalize_output(args[i + 1])
            elif arg.startswith("-o") and len(arg) > 2:
                return self._normalize_output(arg[2:])
            elif arg.startswith("--output="):
                return self._normalize_output(arg[9:])
        if url and self._uses_remote_name(args):
            return self._remote_name_from_url(url)
        return None

    def _normalize_output(self, output: str) -> str | None:
        if output == "-":
            return None
        return output

    def _uses_remote_name(self, args: list[str]) -> bool:
        for arg in args:
            if arg in ("-O", "--remote-name"):
                return True
            if arg.startswith("--remote-name="):
                return True
            if arg.startswith("-") and not arg.startswith("--") and not arg.startswith("-o"):
                if "O" in arg[1:]:
                    return True
        return False

    def _remote_name_from_url(self, url: str) -> str | None:
        path = unquote(urlparse(url).path)
        name = Path(path).name
        return name or None

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

        cmd = [
            str(self._config.real_curl_path),
            *self._sanitize_args(args),
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
            if arg.startswith("--remote-name="):
                continue
            if arg.startswith("-") and not arg.startswith("--") and not arg.startswith("-o"):
                stripped_arg = "-" + "".join(ch for ch in arg[1:] if ch not in "OJ")
                if stripped_arg != "-":
                    sanitized.append(stripped_arg)
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
                ssl_bypass_detected=ssl_bypass_detected,
                duration_ms=self._elapsed_ms(started),
                exit_code=1,
            )
            return 1

        print(f"{warning}. Delivering content due to configured warn mode.", file=sys.stderr)
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

    def _deliver_file(self, temp_path: Path, output_file: str | None) -> tuple[str, str]:
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
        payload = path.read_bytes()
        checksum = hashlib.sha256(payload).hexdigest()
        size = len(payload)
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
