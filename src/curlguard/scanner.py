"""YARA scanner module for curlguard."""

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
    def __init__(
        self,
        rules_paths: list[str | Path] | None = None,
        scan_timeout_seconds: int = 10,
    ) -> None:
        self._rules_paths = [Path(p) for p in (rules_paths or [])]
        self._rules: list[object] = []
        self._rules_count = 0
        self._yara_available = False
        self._load_error: str | None = None
        self._scan_timeout_seconds = scan_timeout_seconds
        self._load_rules()

    def _load_rules(self) -> None:
        self._rules = []
        self._rules_count = 0
        self._load_error = None
        try:
            import yara

            self._yara = yara
            self._yara_available = True

            builtin = Path(__file__).parent / "rules" / "foundation.yar"
            rule_files = [builtin] if builtin.is_file() else []
            for path in self._rules_paths:
                if path.is_dir():
                    rule_files.extend(sorted(path.glob("*.yar")))
                elif path.is_file() and path.suffix == ".yar":
                    rule_files.append(path)

            rule_files = self._deduplicate_rule_files(rule_files)

            if not rule_files:
                return

            self._compile_rules(rule_files)
        except ImportError:
            # yara not installed - fall back to no scanning
            self._yara_available = False
            self._load_error = "yara-python is not installed"
        except Exception as exc:
            self._yara_available = True
            self._load_error = str(exc)

    def _deduplicate_rule_files(self, rule_files: list[Path]) -> list[Path]:
        unique: list[Path] = []
        fingerprints: set[str] = set()
        for rule_file in dict.fromkeys(path.resolve() for path in rule_files):
            try:
                fingerprint = hashlib.sha256(rule_file.read_bytes()).hexdigest()
            except OSError:
                fingerprint = f"path:{rule_file}"
            if fingerprint not in fingerprints:
                fingerprints.add(fingerprint)
                unique.append(rule_file)
        return unique

    def _compile_rules(self, rule_files: list[Path]) -> None:
        import yara

        errors = []
        for rule_file in rule_files:
            try:
                self._rules.append(yara.compile(filepath=str(rule_file)))
            except Exception as exc:
                errors.append(f"{rule_file}: {exc}")
        self._rules_count = len(self._rules)
        if errors:
            self._load_error = "; ".join(errors)

    def scan(self, data: bytes) -> ScanResult:
        start = time.perf_counter()
        if not self._yara_available:
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(
                clean=True,
                matches=[],
                rules_triggered=[],
                scan_time_ms=elapsed,
                status="unavailable",
                error=self._load_error or "yara-python is not installed",
            )

        if not self._rules:
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(
                clean=True,
                matches=[],
                rules_triggered=[],
                scan_time_ms=elapsed,
                status="unavailable",
                error=self._load_error or "no YARA rules could be loaded",
            )

        try:
            matches = []
            for rules in self._rules:
                matches.extend(
                    rules.match(data=data, timeout=self._scan_timeout_seconds)
                )
            matches = self._deduplicate_matches(matches)
            elapsed = (time.perf_counter() - start) * 1000
            rules_triggered = [m.rule for m in matches]
            return ScanResult(
                clean=len(matches) == 0,
                matches=[str(m) for m in matches],
                rules_triggered=rules_triggered,
                scan_time_ms=elapsed,
                status="flagged" if matches else "clean",
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(
                clean=True,
                matches=[],
                rules_triggered=[],
                scan_time_ms=elapsed,
                status="error",
                error=str(exc),
            )

    def scan_file(self, path: str | Path) -> ScanResult:
        path = Path(path)
        start = time.perf_counter()
        if not self._yara_available or not self._rules:
            return self.scan(b"")

        try:
            matches = []
            for rules in self._rules:
                matches.extend(
                    rules.match(filepath=str(path), timeout=self._scan_timeout_seconds)
                )
            matches = self._deduplicate_matches(matches)
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(
                clean=not matches,
                matches=[str(match) for match in matches],
                rules_triggered=[match.rule for match in matches],
                scan_time_ms=elapsed,
                status="flagged" if matches else "clean",
            )
        except Exception as exc:
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(
                clean=True,
                matches=[],
                rules_triggered=[],
                scan_time_ms=elapsed,
                status="error",
                error=str(exc),
            )

    def reload_rules(self) -> None:
        self._load_rules()

    def _deduplicate_matches(self, matches: list) -> list:
        return list({match.rule: match for match in matches}.values())

    def get_rules_count(self) -> int:
        return self._rules_count
