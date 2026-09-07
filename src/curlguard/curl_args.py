"""Conservative parsing for the curl subset curlguard can safely intercept."""

from dataclasses import dataclass
from pathlib import Path
from urllib.parse import unquote, urlparse

SUPPORTED_LONG_FLAGS = {
    "--compressed",
    "--fail",
    "--fail-with-body",
    "--insecure",
    "--location",
    "--location-trusted",
    "--show-error",
    "--silent",
    "--sslv3",
    "--tlsv1.0",
    "--tlsv1.1",
}
SUPPORTED_LONG_VALUES = {
    "--connect-timeout",
    "--header",
    "--max-filesize",
    "--max-time",
    "--proxy",
    "--proxy-user",
    "--referer",
    "--retry",
    "--retry-delay",
    "--retry-max-time",
    "--tls-max",
    "--user",
    "--user-agent",
}
OUTPUT_LONG_VALUES = {"--output"}
REMOTE_NAME_FLAGS = {"--remote-name"}
URL_LONG_VALUES = {"--url"}

SUPPORTED_SHORT_FLAGS = {"f", "k", "L", "q", "s", "S", "v"}
SUPPORTED_SHORT_VALUES = {"A", "e", "H", "m", "u", "x"}
UNSUPPORTED_SHORT = {
    "C",
    "d",
    "D",
    "F",
    "G",
    "h",
    "I",
    "J",
    "K",
    "r",
    "R",
    "T",
    "V",
    "w",
}


@dataclass(frozen=True)
class CurlInvocation:
    intercept: bool
    urls: tuple[str, ...]
    output: str | None
    download_args: tuple[str, ...]
    reason: str


def parse_curl_args(args: list[str]) -> CurlInvocation:
    urls: list[str] = []
    download_args: list[str] = []
    output: str | None = None
    remote_name = False
    output_mode_seen = False
    index = 0

    while index < len(args):
        arg = args[index]
        if arg == "--":
            trailing = args[index + 1 :]
            if len(trailing) != 1 or not _is_download_url(trailing[0]):
                return _passthrough(
                    urls, output, args, "unsupported positional arguments"
                )
            urls.append(trailing[0])
            download_args.extend(["--", trailing[0]])
            break

        if arg.startswith("--"):
            name, separator, attached = arg.partition("=")
            if name in SUPPORTED_LONG_FLAGS:
                if separator:
                    return _passthrough(urls, output, args, f"invalid value for {name}")
                download_args.append(arg)
            elif name in REMOTE_NAME_FLAGS:
                if separator:
                    return _passthrough(urls, output, args, f"invalid value for {name}")
                if output_mode_seen:
                    return _passthrough(urls, output, args, "multiple output modes")
                remote_name = True
                output_mode_seen = True
            elif name in OUTPUT_LONG_VALUES | URL_LONG_VALUES | SUPPORTED_LONG_VALUES:
                if separator:
                    value = attached
                else:
                    index += 1
                    if index >= len(args):
                        return _passthrough(
                            urls, output, args, f"missing value for {name}"
                        )
                    value = args[index]

                if name in OUTPUT_LONG_VALUES:
                    if output_mode_seen:
                        return _passthrough(urls, output, args, "multiple output modes")
                    output = _normalize_output(value)
                    output_mode_seen = True
                else:
                    download_args.extend([name, value])
                    if name in URL_LONG_VALUES and _is_download_url(value):
                        urls.append(value)
            else:
                return _passthrough(urls, output, args, f"unsupported option {name}")
            index += 1
            continue

        if arg.startswith("-") and arg != "-":
            parsed = _parse_short_cluster(arg, args, index)
            if parsed is None:
                return _passthrough(
                    urls, output, args, f"unsupported option cluster {arg}"
                )
            rebuilt, consumed_next, cluster_output, cluster_remote = parsed
            if rebuilt:
                download_args.extend(rebuilt)
            if cluster_output is not _NO_OUTPUT:
                if output_mode_seen or cluster_remote:
                    return _passthrough(urls, output, args, "multiple output modes")
                output = _normalize_output(cluster_output)
                output_mode_seen = True
            elif cluster_remote:
                if output_mode_seen:
                    return _passthrough(urls, output, args, "multiple output modes")
                output_mode_seen = True
            remote_name = remote_name or cluster_remote
            index += 2 if consumed_next else 1
            continue

        if _is_download_url(arg):
            urls.append(arg)
            download_args.append(arg)
            index += 1
            continue

        return _passthrough(urls, output, args, f"unsupported argument {arg}")

    if len(urls) != 1:
        return _passthrough(
            urls, output, args, "curlguard requires exactly one HTTP(S) URL"
        )
    if remote_name:
        output = _remote_name_from_url(urls[0])
        if output is None:
            return _passthrough(urls, output, args, "remote filename is unavailable")
    return CurlInvocation(True, tuple(urls), output, tuple(download_args), "supported")


_NO_OUTPUT = object()


def _parse_short_cluster(
    arg: str, args: list[str], index: int
) -> tuple[list[str], bool, str | object, bool] | None:
    cluster = arg[1:]
    kept_flags: list[str] = []
    consumed_next = False
    output: str | object = _NO_OUTPUT
    remote_name = False
    position = 0

    while position < len(cluster):
        flag = cluster[position]
        if flag in UNSUPPORTED_SHORT:
            return None
        if flag in SUPPORTED_SHORT_FLAGS:
            kept_flags.append(flag)
            position += 1
            continue
        if flag == "O":
            remote_name = True
            position += 1
            continue
        if flag == "o" or flag in SUPPORTED_SHORT_VALUES:
            attached = cluster[position + 1 :]
            if attached:
                value = attached
            else:
                if index + 1 >= len(args):
                    return None
                value = args[index + 1]
                consumed_next = True
            if flag == "o":
                output = value
            else:
                kept_flags.append(flag)
                kept = "-" + "".join(kept_flags)
                return [kept, value], consumed_next, output, remote_name
            break
        return None

    rebuilt = ["-" + "".join(kept_flags)] if kept_flags else []
    return rebuilt, consumed_next, output, remote_name


def _passthrough(
    urls: list[str], output: str | None, args: list[str], reason: str
) -> CurlInvocation:
    return CurlInvocation(False, tuple(urls), output, tuple(args), reason)


def _is_download_url(value: str) -> bool:
    return value.lower().startswith(("http://", "https://"))


def _normalize_output(output: str) -> str | None:
    return None if output == "-" else output


def _remote_name_from_url(url: str) -> str | None:
    name = Path(unquote(urlparse(url).path)).name
    return name or None
