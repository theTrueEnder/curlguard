"""YARA scanner module for curlguard."""
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
    def __init__(self, rules_paths: list[str | Path] | None = None) -> None:
        self._rules_paths = [Path(p) for p in (rules_paths or [])]
        self._rules = None
        self._rules_count = 0
        self._yara_available = False
        self._load_error: str | None = None
        self._load_rules()

    def _load_rules(self) -> None:
        self._rules = None
        self._rules_count = 0
        self._load_error = None
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
            self._load_error = "yara-python is not installed"
        except Exception as exc:
            self._yara_available = True
            self._load_error = str(exc)

    def _compile_rules(self, rule_files: list[Path]) -> None:
        import yara

        # Merge all rule files and compile
        self._rules = yara.compile(
            sources={
                str(rf): rf.read_text(encoding="utf-8")
                for rf in rule_files
            }
        )
        self._rules_count = len(rule_files)

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

        if self._rules is None:
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
            matches = self._rules.match(data=data)
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
        return self.scan(path.read_bytes())

    def reload_rules(self) -> None:
        self._load_rules()

    def get_rules_count(self) -> int:
        return self._rules_count
