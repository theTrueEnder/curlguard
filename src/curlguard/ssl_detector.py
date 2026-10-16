"""Transport diagnostics using the same option parser as the download planner."""

from dataclasses import dataclass
from typing import Literal

from curlguard.arguments import parse


@dataclass
class SslBypassResult:
    is_bypass: bool
    bypass_type: str | None
    severity: Literal["warning", "block"]
    message: str


class SslBypassDetector:
    def detect(self, args: list[str], url: str) -> SslBypassResult:
        request = parse([*args, url], check_config=False)
        weak = request.flags & {"sslv3", "tlsv1.0", "tlsv1.1"}
        try:
            low_max = float(request.values.get("tls-max", "1.3")) < 1.2
        except ValueError:
            low_max = False
        if weak or low_max:
            return SslBypassResult(
                True,
                "ssl-version",
                "block",
                "TLS version too low: SSLv3/TLS below 1.2 requested",
            )
        if "insecure" in request.flags:
            return SslBypassResult(
                True,
                "flag",
                "warning",
                "SSL bypass flag detected: --insecure disables certificate verification",
            )
        if url.startswith("http://"):
            return SslBypassResult(
                True,
                "mixed",
                "warning",
                "Insecure URL scheme: http:// provides no encryption",
            )
        return SslBypassResult(False, None, "warning", "")
