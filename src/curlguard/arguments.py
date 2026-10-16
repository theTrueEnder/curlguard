"""Conservative curl feature registry: unrecognized semantics are never rewritten."""

import os
import re
from dataclasses import dataclass, field
from pathlib import Path
from urllib.parse import urlsplit

# Canonical spellings, separated by arity. Only modeled GET options belong here.
FLAGS = {
    "f": "fail",
    "s": "silent",
    "S": "show-error",
    "L": "location",
    "k": "insecure",
    "g": "globoff",
    "q": "disable",
    "4": "ipv4",
    "6": "ipv6",
}
VALUES = {
    "o": "output",
    "C": "continue-at",
    "z": "time-cond",
    "w": "write-out",
    "H": "header",
    "A": "user-agent",
    "u": "user",
    "x": "proxy",
    "b": "cookie",
    "m": "max-time",
    "e": "referer",
}
LONG_FLAGS = set(FLAGS.values()) | {
    "compressed",
    "http1.1",
    "http2",
    "no-progress-meter",
    "retry-connrefused",
    "retry-all-errors",
    "sslv3",
    "tlsv1.0",
    "tlsv1.1",
    "tlsv1.2",
    "tlsv1.3",
}
LONG_VALUES = set(VALUES.values()) | {
    "url",
    "connect-timeout",
    "retry",
    "retry-delay",
    "retry-max-time",
    "max-redirs",
    "cacert",
    "capath",
    "resolve",
    "connect-to",
    "noproxy",
    "proxy-user",
    "tls-max",
    "limit-rate",
    "etag-compare",
    "etag-save",
    "proto",
    "proto-redir",
}
WRITEOUT = {
    "http_code",
    "response_code",
    "time_total",
    "time_namelookup",
    "time_connect",
    "time_appconnect",
    "time_pretransfer",
    "time_starttransfer",
    "time_redirect",
    "num_redirects",
    "size_download",
    "size_header",
    "speed_download",
    "ssl_verify_result",
    "http_version",
    "remote_ip",
    "remote_port",
    "local_ip",
    "local_port",
}


@dataclass
class Request:
    urls: list[str] = field(default_factory=list)
    options: list[str] = field(default_factory=list)
    values: dict[str, str] = field(default_factory=dict)
    flags: set[str] = field(default_factory=set)
    destination: str | None = None
    remote_name: bool = False
    reason: str | None = None


def config_paths() -> list[Path]:
    paths = []
    if os.environ.get("CURL_HOME"):
        paths.append(Path(os.environ["CURL_HOME"]) / ".curlrc")
    if os.environ.get("XDG_CONFIG_HOME"):
        paths.append(Path(os.environ["XDG_CONFIG_HOME"]) / "curlrc")
    paths.append(Path.home() / ".curlrc")
    return paths


def parse(args: list[str], *, check_config: bool = True) -> Request:
    r = Request()
    disabled = bool(args and (args[0] == "--disable" or args[0].startswith("-q")))
    if check_config and not disabled and any(p.exists() for p in config_paths()):
        r.reason = "active implicit curl config"
        return r
    i = 0
    end = False
    output_seen = False
    while i < len(args):
        arg = args[i]
        i += 1
        if arg == "--" and not end:
            end = True
            continue
        if end or not arg.startswith("-") or arg == "-":
            r.urls.append(arg)
            continue
        tokens = []
        if arg.startswith("--"):
            name, sep, value = arg[2:].partition("=")
            if name == "remote-name" and not sep:
                tokens.append((name, None))
            elif name in LONG_FLAGS and not sep:
                tokens.append((name, None))
            elif name in LONG_VALUES:
                if not sep:
                    if i == len(args):
                        r.reason = f"missing argument: --{name}"
                        return r
                    value = args[i]
                    i += 1
                tokens.append((name, value))
            else:
                r.reason = f"unsupported option: --{name}"
                return r
        else:
            cluster = arg[1:]
            while cluster:
                c, cluster = cluster[0], cluster[1:]
                if c in FLAGS or c == "O":
                    tokens.append((FLAGS.get(c, "remote-name"), None))
                elif c in VALUES:
                    if cluster:
                        value, cluster = cluster, ""
                    elif i < len(args):
                        value = args[i]
                        i += 1
                    else:
                        r.reason = f"missing argument: -{c}"
                        return r
                    tokens.append((VALUES[c], value))
                else:
                    r.reason = f"unsupported option: -{c}"
                    return r
        for name, value in tokens:
            if name == "url":
                r.urls.append(value)
            elif name == "output":
                if value == "":
                    r.reason = "empty output filename"
                if not output_seen:
                    r.destination = None if value == "-" else value
                    r.remote_name = False
                output_seen = True
            elif name == "remote-name":
                if not output_seen:
                    r.remote_name = True
                output_seen = True
            elif name != "disable":
                if name == "header" and (
                    value.startswith("@") or re.match(r"(?i)range\s*:", value.lstrip())
                ):
                    r.reason = "unmodeled range or external header source"
                if value is None:
                    r.flags.add(name)
                if value is not None:
                    r.values[name] = value
                if name not in {"write-out", "etag-save"}:
                    r.options.append("--" + name)
                    if value is not None:
                        r.options.append(value)
    if len(r.urls) != 1:
        r.reason = "requires exactly one URL"
        return r
    try:
        url = urlsplit(r.urls[0])
    except ValueError:
        r.reason = "malformed URL"
        return r
    if url.scheme not in {"http", "https"} or not url.hostname:
        r.reason = "unsupported URL scheme or missing host"
    elif "--globoff" not in r.options and re.search(r"[{}\[\]]", url.path + url.query):
        r.reason = "URL globbing"
    if r.remote_name:
        r.destination = Path(url.path).name or None
        if not r.destination:
            r.reason = "remote URL has no filename"
    fmt = r.values.get("write-out", "")
    # Reject external formats, output switches, header expansion, and unknown variables.
    variables = re.findall(r"%\{([^}]+)\}", fmt.replace("%%", ""))
    remainder = re.sub(r"%\{[^}]+\}|%%", "", fmt)
    if (
        fmt.startswith("@")
        or any(v not in WRITEOUT for v in variables)
        or "%" in remainder
    ):
        r.reason = "unsupported write-out format"
    if "continue-at" in r.values:
        offset = r.values["continue-at"]
        if not r.destination or (offset != "-" and not offset.isdecimal()):
            r.reason = "resume requires a regular output file and nonnegative offset"
        if "compressed" in r.flags:
            r.reason = "compressed resume is unsupported"
    paths = [p for p in [r.destination, r.values.get("etag-save")] if p]
    for path in paths:
        p = Path(path)
        if p.is_symlink() or (p.exists() and not p.is_file()):
            r.reason = "nonregular output destination"
        elif p.exists():
            info = p.stat()
            if (
                info.st_nlink != 1
                or info.st_uid != os.geteuid()
                or not os.access(p, os.W_OK)
            ):
                r.reason = (
                    "output ownership, permissions, or hardlinks require native curl"
                )
    if (
        r.destination
        and r.values.get("etag-save")
        and Path(r.destination).absolute() == Path(r.values["etag-save"]).absolute()
    ):
        r.reason = "payload and ETag destinations overlap"
    return r
