"""SSL bypass detection module for curlguard."""

from dataclasses import dataclass
from typing import Literal


@dataclass
class SslBypassResult:
    is_bypass: bool
    bypass_type: str | None  # "flag" | "mixed" | "ssl-version" | None
    severity: Literal["warning", "block"]
    message: str


class SslBypassDetector:
    INSECURE_FLAGS = {"--insecure", "--proxy-insecure", "-k"}
    INSECURE_SSL_FLAGS = {"--sslv3", "--tlsv1.0", "--tlsv1.1"}

    def detect(self, args: list[str], url: str) -> SslBypassResult:
        # Check for insecure flags
        for i, arg in enumerate(args):
            option = arg.split("=", 1)[0]
            if option in self.INSECURE_FLAGS or self._short_flag_present(arg, "k"):
                return SslBypassResult(
                    is_bypass=True,
                    bypass_type="flag",
                    severity="warning",
                    message="SSL bypass flag detected: --insecure disables certificate verification",
                )
            if option in self.INSECURE_SSL_FLAGS:
                return SslBypassResult(
                    is_bypass=True,
                    bypass_type="ssl-version",
                    severity="block",
                    message=f"Downgraded SSL/TLS version flag detected: {arg}",
                )
            if option == "--tls-max":
                # Check next arg for version < 1.2
                raw_version = arg.partition("=")[2]
                if not raw_version and i + 1 < len(args):
                    raw_version = args[i + 1]
                if raw_version:
                    try:
                        version = float(raw_version)
                        if version < 1.2:
                            return SslBypassResult(
                                is_bypass=True,
                                bypass_type="ssl-version",
                                severity="block",
                                message=f"TLS version too low: {version}",
                            )
                    except ValueError:
                        pass

        # Check for http:// URL (mixed content)
        if url.startswith("http://"):
            return SslBypassResult(
                is_bypass=True,
                bypass_type="mixed",
                severity="warning",
                message="Insecure URL scheme: http:// provides no encryption",
            )

        return SslBypassResult(
            is_bypass=False,
            bypass_type=None,
            severity="warning",
            message="",
        )

    def _short_flag_present(self, arg: str, target: str) -> bool:
        if not arg.startswith("-") or arg.startswith("--"):
            return False
        value_flags = {"A", "d", "D", "e", "F", "H", "K", "m", "o", "T", "u", "w", "x"}
        for flag in arg[1:]:
            if flag == target:
                return True
            if flag in value_flags:
                return False
        return False
