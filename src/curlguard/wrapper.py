"""Binary wrapper dispatcher module for curlguard."""
import subprocess
import sys
from pathlib import Path
from typing import Iterator, Optional
import tempfile
import shutil
import os


class CurlWrapper:
    def __init__(self, config, scanner, logger, ssl_detector) -> None:
        self._config = config
        self._scanner = scanner
        self._logger = logger
        self._ssl_detector = ssl_detector

    def dispatch(self, args: list[str]) -> int:
        # Find URL and output destination
        url = self._extract_url(args)
        if not url:
            # No URL found, just pass through to real curl
            return self._call_real_curl(args)

        output_file = self._extract_output(args)

        # Check SSL bypass
        ssl_result = self._ssl_detector.detect(args, url)
        if ssl_result.is_bypass:
            print(f"WARNING: {ssl_result.message}", file=sys.stderr)

        # Download to temp
        temp_path, actual_url = self._download_to_temp(args, url)

        # Scan
        scan_result = self._scanner.scan_file(temp_path)

        # Handle based on scan result and user decision
        if not scan_result.clean:
            print(f"MALWARE DETECTED: {scan_result.rules_triggered}", file=sys.stderr)
            from curlguard.tui import prompt_user
            decision = prompt_user(scan_result, url, ssl_result.is_bypass)
            if decision == "block":
                os.remove(temp_path)
                return 1
            elif decision == "quarantine":
                qdir = self._config.quarantine_dir
                qdir.mkdir(parents=True, exist_ok=True)
                import time
                qpath = qdir / f"{int(time.time())}_{Path(temp_path).name}"
                shutil.move(str(temp_path), str(qpath))
                return 1
            else:
                pass  # allow - continue to deliver file

        # Clean - move to destination if specified
        if output_file:
            shutil.move(str(temp_path), output_file)
        else:
            # Print to stdout
            with open(temp_path, "rb") as f:
                shutil.copyfileobj(f, sys.stdout.buffer)
            os.remove(temp_path)

        return 0

    def _extract_url(self, args: list[str]) -> Optional[str]:
        for arg in args:
            if arg.startswith(("http://", "https://", "ftp://", "sftp://")):
                return arg
        return None

    def _extract_output(self, args: list[str]) -> Optional[str]:
        for i, arg in enumerate(args):
            if arg in ("-o", "--output"):
                if i + 1 < len(args):
                    return args[i + 1]
            elif arg.startswith("-o") and len(arg) > 2:
                return arg[2:]
            elif arg.startswith("--output="):
                return arg[9:]
        return None

    def _download_to_temp(self, args: list[str], url: str) -> tuple[Path, str]:
        # Build real curl args
        real_args = [str(self._config.real_curl_path), "-o", "{temp}"] + args
        temp = Path(tempfile.mktemp(suffix=".download"))

        cmd = [str(self._config.real_curl_path), "-L"]
        for arg in args:
            if arg.startswith("-o") and len(arg) > 2:
                cmd.extend(["-o", temp])
            elif arg == "-o" or arg == "--output":
                continue  # skip, we handle output
            else:
                cmd.append(arg)

        result = subprocess.run(cmd, capture_output=True)
        return temp, url

    def _call_real_curl(self, args: list[str]) -> int:
        cmd = [str(self._config.real_curl_path)] + args
        result = subprocess.run(cmd)
        return result.returncode

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