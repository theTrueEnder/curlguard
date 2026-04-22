"""SSL bypass detection module for curlguard."""
from dataclasses import dataclass
from typing import Literal, Optional


@dataclass
class SslBypassResult:
    is_bypass: bool
    bypass_type: Optional[str]  # "flag" | "mixed" | "ssl-version" | None
    severity: Literal["warning", "block"]
    message: str


class SslBypassDetector:
    INSECURE_FLAGS = {"--insecure", "-k", "--k"}
    INSECURE_SSL_FLAGS = {"--sslv3", "--tlsv1.0", "--tlsv1.1"}

    def detect(self, args: list[str], url: str) -> SslBypassResult:
        # Check for insecure flags
        for i, arg in enumerate(args):
            if arg in self.INSECURE_FLAGS:
                return SslBypassResult(
                    is_bypass=True,
                    bypass_type="flag",
                    severity="warning",
                    message="SSL bypass flag detected: --insecure disables certificate verification",
                )
            if arg in self.INSECURE_SSL_FLAGS:
                return SslBypassResult(
                    is_bypass=True,
                    bypass_type="ssl-version",
                    severity="block",
                    message=f"Downgraded SSL/TLS version flag detected: {arg}",
                )
            if arg == "--tls-max":
                # Check next arg for version < 1.2
                if i + 1 < len(args):
                    try:
                        version = float(args[i + 1])
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