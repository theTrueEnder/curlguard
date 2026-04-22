"""YARA scanner module for curlguard."""
from dataclasses import dataclass
from pathlib import Path
from typing import Iterator
import time


@dataclass
class ScanResult:
    clean: bool
    matches: list
    rules_triggered: list
    scan_time_ms: float


class YaraScanner:
    def __init__(self, rules_paths: list[str | Path] | None = None) -> None:
        self._rules_paths = [Path(p) for p in (rules_paths or [])]
        self._rules = None
        self._rules_count = 0
        self._yara_available = False
        self._load_rules()

    def _load_rules(self) -> None:
        try:
            import yara

            self._yara = yara
            self._yara_available = True

            if not self._rules_paths:
                # Use built-in foundation rules
                builtin = Path(__file__).parent / "rules" / "foundation.yar"
                if builtin.exists():
                    self._rules_paths = [builtin]

            rule_files = []
            for path in self._rules_paths:
                if path.is_dir():
                    rule_files.extend(path.glob("*.yar"))
                elif path.suffix == ".yar":
                    rule_files.append(path)

            if not rule_files:
                return

            # Compile with duplicate handling
            self._compile_rules(rule_files)
        except ImportError:
            # yara not installed - fall back to no scanning
            self._yara_available = False

    def _compile_rules(self, rule_files: list[Path]) -> None:
        import yara

        # Merge all rule files and compile
        self._rules = yara.compile(
            sources={
                str(rf): rf.read_text()
                for rf in rule_files
            }
        )
        self._rules_count = len(rule_files)

    def scan(self, data: bytes) -> ScanResult:
        start = time.perf_counter()
        if not self._yara_available or self._rules is None:
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(clean=True, matches=[], rules_triggered=[], scan_time_ms=elapsed)

        try:
            matches = self._rules.match(data=data)
            elapsed = (time.perf_counter() - start) * 1000
            rules_triggered = [m.rule for m in matches]
            return ScanResult(
                clean=len(matches) == 0,
                matches=[str(m) for m in matches],
                rules_triggered=rules_triggered,
                scan_time_ms=elapsed,
            )
        except Exception:
            elapsed = (time.perf_counter() - start) * 1000
            return ScanResult(clean=True, matches=[], rules_triggered=[], scan_time_ms=elapsed)

    def scan_file(self, path: str | Path) -> ScanResult:
        path = Path(path)
        return self.scan(path.read_bytes())

    def reload_rules(self) -> None:
        self._load_rules()

    def get_rules_count(self) -> int:
        return self._rules_count