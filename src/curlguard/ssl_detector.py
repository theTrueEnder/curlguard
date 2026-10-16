"""Transport diagnostics using the same option parser as the download planner."""

from dataclasses import dataclass
from typing import Literal
from urllib.parse import urlsplit

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
        weak = request.flags & {"sslv3"}
        try:
            low_max = float(request.values.get("tls-max", "1.3")) < 1.2
        except ValueError:
            low_max = False
        if weak or low_max:
            return SslBypassResult(
                True,
                "ssl-version",
                "block",
                "SSLv3 requested or TLS maximum below 1.2",
            )
        if request.flags & {"tlsv1.0", "tlsv1.1"}:
            return SslBypassResult(
                True,
                "minimum-version",
                "warning",
                "TLS minimum permits versions below 1.2; negotiated version is unknown",
            )
        if "insecure" in request.flags:
            return SslBypassResult(
                True,
                "flag",
                "warning",
                "SSL bypass flag detected: --insecure disables certificate verification",
            )
        if urlsplit(url).scheme == "http":
            return SslBypassResult(
                True,
                "mixed",
                "warning",
                "Insecure URL scheme: http:// provides no encryption",
            )
        return SslBypassResult(False, None, "warning", "")


def enforce_transport(request, config):
    """Return enforced curl options and pre-network policy violations."""
    violations = []
    if config.require_https and urlsplit(request.urls[0]).scheme != "https":
        violations.append("https_required")
    if config.verify_certificates and "insecure" in request.flags:
        violations.append("certificate_verification_required")
    options = []
    if config.min_tls:
        if "sslv3" in request.flags:
            violations.append("tls_minimum_conflict")
        maximum = request.values.get("tls-max")
        if maximum is not None:
            try:
                if maximum != "default" and float(maximum) < float(config.min_tls):
                    violations.append("tls_maximum_conflict")
            except ValueError:
                violations.append("invalid_tls_maximum")
        requested = [
            v for v in ("1.0", "1.1", "1.2", "1.3") if "tlsv" + v in request.flags
        ]
        minimum = max([config.min_tls, *requested], key=float)
        options.append("--tlsv" + minimum)
    if config.require_https:
        options += ["--proto", "=https"]
    if config.redirect_protocols:
        options += ["--proto-redir", "=" + ",".join(config.redirect_protocols)]
    return options, violations
