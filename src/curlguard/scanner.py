"""Bounded file scanning and transactional rule replacement."""

import hashlib
import json
import subprocess
import sys
import tempfile
import time
from dataclasses import dataclass, field
from importlib.resources import files
from pathlib import Path
from typing import Literal

from curlguard.evidence import SEVERITIES, Finding, safe_text


@dataclass
class ScanResult:
    clean: bool
    matches: list
    rules_triggered: list
    scan_time_ms: float
    status: Literal["clean", "flagged", "unavailable", "error"] = "clean"
    error: str | None = None
    findings: list[Finding] = field(default_factory=list)


class YaraScanner:
    def __init__(self, rules_paths=None, *, timeout=10, max_bytes=268435456):
        self._rules_paths = [Path(p) for p in (rules_paths or [])]
        self.timeout, self.max_bytes = timeout, max_bytes
        self._rules = None
        self._rules_count = 0
        self._yara_available = False
        self._load_error = None
        self.ruleset_id = None
        self._remote_source = None
        self.reload_rules()

    def rule_files(self):
        files = set()
        for path in self._rules_paths:
            if path.is_dir():
                files.update(p.resolve() for p in path.glob("*.yar"))
            elif path.suffix == ".yar":
                files.add(path.resolve())
        return sorted(files)

    def compile_candidate(self, replacement=None, target=None):
        import yara

        sources = {
            "builtin": files("curlguard.rules")
            .joinpath("foundation.yar")
            .read_text(encoding="utf-8")
        }
        for path in self.rule_files():
            if target is not None and path.resolve() == Path(target).resolve():
                continue
            sources[str(path)] = path.read_text(encoding="utf-8")
        if self._remote_source is not None:
            sources["remote"] = self._remote_source
        if replacement is not None:
            sources["remote"] = Path(replacement).read_text(encoding="utf-8")
        with tempfile.TemporaryDirectory(prefix="curlguard-compile-") as directory:
            source = Path(directory) / "sources.json"
            compiled = Path(directory) / "compiled.yarc"
            source.write_text(json.dumps(sources), encoding="utf-8")
            try:
                subprocess.run(
                    [
                        sys.executable,
                        "-I",
                        str(Path(__file__).with_name("compile_worker.py")),
                        str(source),
                        str(compiled),
                    ],
                    check=True,
                    capture_output=True,
                    timeout=30,
                )
            except subprocess.CalledProcessError as exc:
                raise ValueError("candidate rule compilation failed") from exc
            rules = yara.load(str(compiled))
        identity = hashlib.sha256(
            "".join(k + sources[k] for k in sorted(sources)).encode()
        ).hexdigest()
        return rules, len(sources), identity

    def set_remote(self, source, candidate=None):
        previous = self._remote_source
        self._remote_source = source
        try:
            self.activate(candidate or self.compile_candidate())
        except BaseException:
            self._remote_source = previous
            raise

    def activate(self, candidate):
        self._rules, self._rules_count, self.ruleset_id = candidate
        self._load_error = None
        self._yara_available = True

    def reload_rules(self):
        try:
            self.activate(self.compile_candidate())
        except ImportError:
            self._yara_available = False
            self._load_error = "yara-python is not installed"
        except Exception as exc:
            self._yara_available = True
            self._load_error = str(exc)
            # Retain the last known-good compiled ruleset.

    def _scan(self, *, data=None, path=None):
        started = time.perf_counter()

        def result(status, error=None, matches=()):
            return ScanResult(
                status == "clean",
                [str(m) for m in matches],
                [m.rule for m in matches],
                (time.perf_counter() - started) * 1000,
                status,
                error,
                [self._finding(m) for m in matches],
            )

        if not self._yara_available or self._rules is None:
            return result(
                "unavailable", self._load_error or "no YARA rules could be loaded"
            )
        try:
            size = Path(path).stat().st_size if path is not None else len(data)
            if size > self.max_bytes:
                return result("error", "payload exceeds CURLGUARD_MAX_SCAN_BYTES")
            kwargs = {"filepath": str(path)} if path is not None else {"data": data}
            matches = self._rules.match(timeout=self.timeout, **kwargs)
            return result("flagged" if matches else "clean", matches=matches)
        except Exception as exc:
            return result("error", f"scan failed: {exc}")

    def _finding(self, match):
        meta = match.meta
        severity = meta.get("severity", "high")
        confidence = meta.get("confidence", "unknown")
        category = meta.get("category", "indicator")
        locations, excerpts = [], []
        for string in match.strings:
            for instance in string.instances[:4]:
                if len(locations) >= 8:
                    break
                locations.append(
                    {
                        "identifier": safe_text(string.identifier)[:128],
                        "offset": instance.offset,
                    }
                )
                excerpts.append(
                    safe_text(
                        instance.matched_data[:96].decode("utf-8", errors="replace")
                    )
                )
        return Finding(
            safe_text(match.rule),
            safe_text(match.namespace),
            safe_text(meta.get("description", "Unclassified rule match"))[:512],
            severity
            if isinstance(severity, str) and severity in SEVERITIES
            else "high",
            confidence if confidence in ("low", "medium", "high") else "unknown",
            category if category in ("behavior", "indicator") else "indicator",
            self.ruleset_id,
            locations,
            excerpts,
        )

    def scan(self, data: bytes) -> ScanResult:
        return self._scan(data=data)

    def scan_file(self, path) -> ScanResult:
        return self._scan(path=path)

    def get_rules_count(self):
        return self._rules_count
