"""Bounded file scanning and transactional rule replacement."""

import hashlib
import time
from dataclasses import dataclass
from pathlib import Path
from typing import Literal


@dataclass
class ScanResult:
    clean: bool
    matches: list
    rules_triggered: list
    scan_time_ms: float
    status: Literal["clean", "flagged", "unavailable", "error"] = "clean"
    error: str | None = None


class YaraScanner:
    def __init__(self, rules_paths=None, *, timeout=10, max_bytes=268435456):
        self._rules_paths = [Path(p) for p in (rules_paths or [])]
        self.timeout, self.max_bytes = timeout, max_bytes
        self._rules = None
        self._rules_count = 0
        self._yara_available = False
        self._load_error = None
        self.ruleset_id = None
        self.reload_rules()

    def rule_files(self):
        builtin = Path(__file__).parent / "rules" / "foundation.yar"
        files = {builtin.resolve()}
        for path in self._rules_paths:
            if path.is_dir():
                files.update(p.resolve() for p in path.glob("*.yar"))
            elif path.suffix == ".yar":
                files.add(path.resolve())
        return sorted(files)

    def compile_candidate(self, replacement=None, target=None):
        import yara

        sources = {}
        for path in self.rule_files():
            if target is not None and path.resolve() == Path(target).resolve():
                continue
            sources[str(path)] = path.read_text(encoding="utf-8")
        if replacement is not None:
            sources[str(target)] = Path(replacement).read_text(encoding="utf-8")
        # No source may include arbitrary local files. Remote includes are disabled too.
        rules = yara.compile(sources=sources, includes=False)
        identity = hashlib.sha256(
            "".join(k + sources[k] for k in sorted(sources)).encode()
        ).hexdigest()
        return rules, len(sources), identity

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

    def scan(self, data: bytes) -> ScanResult:
        return self._scan(data=data)

    def scan_file(self, path) -> ScanResult:
        return self._scan(path=path)

    def get_rules_count(self):
        return self._rules_count
