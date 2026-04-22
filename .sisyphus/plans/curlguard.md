# curlguard — Secure Curl Wrapper with YARA Scanning

## TL;DR

> **Quick Summary**: A shell-agnostic binary wrapper around curl that intercepts all downloads, scans file contents with YARA rules, and shows an interactive TUI prompt when malware is detected — protecting Linux users from supply chain attacks via `curl ... | bash`.
>
> **Deliverables**:
> - `curlguard` Python binary wrapper placed in PATH before `/usr/bin/curl`
> - YARA scanner engine with built-in rules + user-managed rules directory + daily auto-update
> - Terminal TUI (Python textualize) prompt on detection: Block / Quarantine / Allow
> - SSL bypass detection (flags `--insecure`, http→https redirects as warnings)
> - Full audit logging to `~/.curlguard/audit.log` (per-user) or `/var/log/curlguard/audit.log` (system-wide)
> - Per-user and system-wide installation scripts
>
> **Estimated Effort**: Large
> **Parallel Execution**: YES — 3 waves
> **Critical Path**: T1 (project scaffold) → T2 (core scanner) → T3 (wrapper binary) → T4 (TUI prompt) → T8 (integration test with real malware sample)

---

## Context

### Original Request
A tool that aliases over curl and scans the contents of files being pulled so Linux users can be protected from installation hijacking attacks (e.g., `curl ... | bash` downloading malware).

### Interview Summary

**Key Discussions**:
- Detection response: Interactive TUI prompt (user decides Block/Quarantine/Allow per incident)
- Scanner engine: YARA rules from 3 sources — built-in rules shipped with tool, user-managed local `.yar` files, daily auto-update from trusted source
- Shell compatibility: Shell-agnostic via binary wrapper in PATH (works in bash/zsh/fish/any shell)
- Installation scope: Both per-user (`~/.local/bin/curlguard`) and system-wide (`/usr/local/bin/curlguard`)
- SSL bypass detection: Yes — flag and warn when `--insecure` is used or http→https redirect detected
- Audit logging: Full audit log of every download (timestamp, URL, destination, scan result, user decision)
- TUI framework: Python + textualize (Charm's TUI library)
- Language: Python (recommended for easier YARA bindings)
- Project name: `curlguard`
- Rule update frequency: On first run each day (reasonable balance between freshness and speed)
- Test strategy: Unit + integration tests (pytest) + a public true positive example for user demo

**Research Findings**:
- YARA has excellent Python bindings (`yara-python`/`yaracr`/`yarap`); YARA 4.x is current stable
- Textualize (textual) is the modern standard for Python TUIs — maintained, doc-rich, declarative
- Binary wrapper approach: place `curlguard` executable in PATH before `/usr/bin/curl`, `curlguard` calls real `/usr/bin/curl.real` (renamed original)
- SSL bypass patterns: `--insecure`, `-k`, `--sslv3`, `--tlsv1.0`, mixed http/https URLs
- Auto-update: rules from Elastic Security or VirusTotal (requires API key) or open ruleset like `bartblaze/YARA-rules`

---

## Work Objectives

### Core Objective
Intercept all curl downloads, scan file contents with YARA rules, alert user via TUI on detection, block/quarantine/allow based on user decision, and maintain full audit trail.

### Concrete Deliverables
- `curlguard` — Python binary wrapper that intercepts curl invocations
- `curlguard-real` — Renamed original `/usr/bin/curl` (preserved for actual downloads)
- Built-in YARA rule set (foundation rules shipped with tool)
- User rules directory: `~/.curlguard/rules/` (per-user) or `/etc/curlguard/rules.d/` (system-wide)
- Daily auto-update of YARA rules from open ruleset
- TUI prompt (textualize) with Block / Quarantine / Allow options
- SSL bypass detection and warning
- Audit log: `~/.curlguard/audit.log` or `/var/log/curlguard/audit.log`
- Per-user installer: `install-peruser.sh`
- System-wide installer: `install-systemwide.sh` (requires sudo)
- Unit + integration tests with pytest
- Example true positive: a known malicious script (e.g., a caught-in-the-wild malware sample from Malware Bazaar) that users can test against

### Definition of Done
- [ ] `curl https://example.com/malware.sh | bash` is intercepted by curlguard and scanned
- [ ] Clean files pass through without interruption
- [ ] Files matching YARA rules trigger TUI prompt with verdict choices
- [ ] `curl --insecure https://example.com/file.sh` triggers SSL bypass warning
- [ ] Audit log entry written for every curl invocation
- [ ] Installation works for both per-user and system-wide modes
- [ ] pytest unit and integration tests pass

### Must Have
- YARA scanning with multiple rule sources
- Interactive TUI prompt on detection
- Shell-agnostic (works with bash, zsh, fish, sh)
- SSL bypass detection
- Full audit logging
- Working installers for both scopes

### Must NOT Have
- Modification of actual curl behavior — curlguard only wraps/intercepts, doesn't change curl's output
- Rootkit-level kernel manipulation — binary wrapper only
- Network-level interception (mitmproxy) — not in scope
- Windows/macOS support — Linux only for v1

---

## Verification Strategy

### Test Decision
- **Infrastructure exists**: NO — pytest will be set up as part of this project
- **Automated tests**: YES — TDD approach: RED (failing test) → GREEN (minimal impl) → REFACTOR
- **Framework**: pytest + pytest-asyncio + unittest.mock for YARA and curl mocking
- **If TDD**: Each task follows RED (failing test) → GREEN (minimal impl) → REFACTOR

### QA Policy
Every task MUST include agent-executed QA scenarios. Evidence saved to `.sisyphus/evidence/task-{N}-{scenario-slug}.{ext}`.

- **CLI tool**: Use `Bash` (tmux/interactive_bash) to run curlguard, assert output, check exit codes
- **TUI**: Use `Bash` with script/expect to test TUI behavior
- **Integration**: Use `Bash` to run real curlguard over real files, assert detection behavior

---

## Execution Strategy

### Parallel Execution Waves

```
Wave 1 (Start Immediately — scaffolding + foundation):
├── T1: Project scaffold + pyproject.toml + dependencies
├── T2: Core YARA scanner module (rules loading, matching, built-in rules)
├── T3: Config loader (paths, settings, env var overrides)
├── T4: Audit logger module (JSON log format, rotation)
├── T5: SSL bypass detector (flag parsing, URL inspection)
└── T6: Binary wrapper dispatcher (PATH resolution, pass-through, subprocess)

Wave 2 (After Wave 1 — core functionality, MAX PARALLEL):
├── T7: TUI prompt with textualize (Block/Quarantine/Allow dialog)
├── T8: Real curl binary manager (rename original, call with correct args)
├── T9: User rules directory watcher + loader
├── T10: Auto-update engine (daily check, fetch, reload YARA)
└── T11: Per-user installer (install-peruser.sh)

Wave 3 (After Wave 2 — integration + polish):
├── T12: System-wide installer (install-systemwide.sh, sudo required)
├── T13: Integration tests (pytest, real curlguard + real YARA rules)
├── T14: Example true positive test (download known malware sample, verify detection)
└── T15: README + usage documentation

Wave FINAL (After ALL tasks — 4 parallel reviews, then user okay):
├── T16: Plan compliance audit (oracle)
├── T17: Code quality review (unspecified-high)
├── T18: Real manual QA (unspecified-high)
└── T19: Scope fidelity check (deep)
-> Present results -> Get explicit user okay
```

### Dependency Matrix

| Task | Can Start | Blocks |
|------|-----------|--------|
| T2 (YARA scanner) | After T1 | T7, T10 |
| T3 (config loader) | After T1 | T6, T8 |
| T4 (audit logger) | After T1 | T6, T7, T8 |
| T5 (SSL bypass) | After T1 | T6, T8 |
| T6 (binary wrapper) | After T2, T3, T4, T5 | T7, T8, T11 |
| T7 (TUI prompt) | After T2, T4, T6 | T11 |
| T8 (real curl manager) | After T3, T4, T5, T6 | T11 |
| T9 (user rules watcher) | After T2 | T11 |
| T10 (auto-update engine) | After T2 | T11 |
| T11 (per-user installer) | After T6, T7, T8, T9, T10 | T12, T13 |
| T12 (system-wide installer) | After T11 | T13 |
| T13 (integration tests) | After T11, T12 | T14 |
| T14 (true positive test) | After T13 | T15 |
| T15 (README) | After T14 | FINAL |

### Agent Dispatch Summary

- **Wave 1**: `6 tasks` — all `quick` category (scaffolding + foundational modules)
- **Wave 2**: `5 tasks` — T7 `visual-engineering` (TUI), T8 `unspecified-high`, T9-T10 `quick`, T11 `unspecified-high`
- **Wave 3**: `4 tasks` — T12 `unspecified-high`, T13-T14 `unspecified-high`, T15 `writing`
- **FINAL**: `4 tasks` — T16 `oracle`, T17-T18 `unspecified-high`, T19 `deep`

---

## TODOs

- [x] 1. **Project scaffold + pyproject.toml + dependencies**

  **What to do**:
  - Create `src/curlguard/__init__.py` — package init with version
  - Create `pyproject.toml` with: project name, version, Python >=3.10, dependencies (yara-python, textual, requests, httpx), scripts entry point (`curlguard = curlguard.cli:main`), build system (setuptools)
  - Create `src/curlguard/cli.py` — argparse entry point that routes to `dispatch()`
  - Create `src/curlguard/__main__.py` — `python -m curlguard` entry
  - Create `src/` layout: `scanner.py`, `config.py`, `logger.py`, `ssl_detector.py`, `wrapper.py`, `tui.py`, `curl_manager.py`, `rules_watcher.py`, `auto_updater.py`
  - Create `tests/__init__.py`, `tests/test_scanner.py`, `tests/test_config.py`, `tests/test_logger.py`, `tests/test_ssl_detector.py`, `tests/test_wrapper.py`
  - Create `examples/` directory for true positive test sample
  - Create `rules/` directory with `rules/example.yar` — a simple built-in YARA rule for testing
  - Initialize git repo, create `.gitignore` (exclude `__pycache__`, `.pytest_cache`, `*.pyc`)
  - Add `scripts/install-peruser.sh` and `scripts/install-systemwide.sh` stubs

  **Must NOT do**:
  - Don't implement any logic in these files yet — just scaffolding and imports
  - Don't add real YARA rules yet — just a placeholder `.yar` file

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: [`git-master`] — for proper .gitignore setup
  - **Skills Evaluated but Omitted**:
    - `playwright`: Not relevant — CLI tool, no browser UI

  **Parallelization**:
  - **Can Run In Parallel**: YES
  - **Parallel Group**: Wave 1 (with Tasks 2, 3, 4, 5, 6)
  - **Blocks**: Tasks 2-6 depend on project structure existing
  - **Blocked By**: None (can start immediately)

  **References**:

  **Pattern References** (existing code to follow):
  - Python project layout: `src/{pkg}/__init__.py`, `pyproject.toml`, `tests/` — follow modern Python packaging (PEP 518/517)

  **API/Type References** (contracts to implement against):
  - `pyproject.toml` structure: must include `[project]`, `[project.scripts]`, `[build-system]`, `[tool.pytest.ini_options]`

  **External References** (libraries and frameworks):
  - Python textualize docs: `https://textual.textualize.io/` — TUI framework for the prompt
  - YARA documentation: `https://yara.readthedocs.io/` — rule format and Python bindings
  - `yara-python` pip: `https://pypi.org/project/yara-python/` — Python YARA bindings

  **WHY Each Reference Matters**:
  - textualize: The TUI prompt (Task 7) will use `textual.app.App` and `textual.widgets` — study the reactive widget pattern
  - YARA: Rules are `.yar` files with `rule Name { strings: ... condition: ... }` syntax
  - pyproject.toml: Modern Python packaging standard — scripts entry point makes `curlguard` CLI available after pip install

  **Acceptance Criteria**:

  - [ ] `python -m curlguard --help` runs without ImportError
  - [ ] `pyproject.toml` passes `pip install -e .` without error
  - [ ] `curlguard --help` works after editable install
  - [ ] `ls src/curlguard/` shows all 9 module files (scanner.py, config.py, etc.)
  - [ ] `ls tests/` shows at least `test_scanner.py`, `test_config.py`, `test_logger.py`
  - [ ] `ls rules/` shows `example.yar`
  - [ ] `git init` + `.gitignore` created

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: CLI entry point works after editable install
    Tool: Bash
    Preconditions: Clean environment, Python 3.10+, pip available
    Steps:
      1. pip install -e . (in project root)
      2. python -m curlguard --version
      3. curlguard --help
    Expected Result: Both commands print help/version without ImportError
    Failure Indicators: ModuleNotFoundError, ImportError, "not found" in output
    Evidence: .sisyphus/evidence/task-1-cli-help.txt

  Scenario: Project structure is correct
    Tool: Bash
    Preconditions: Project scaffold created
    Steps:
      1. ls src/curlguard/ — verify all module files exist
      2. ls tests/ — verify test files exist
      3. cat pyproject.toml — verify [project.scripts] has curlguard entry
    Expected Result: All expected files present, pyproject.toml has correct entry point
    Failure Indicators: Missing files, malformed pyproject.toml
    Evidence: .sisyphus/evidence/task-1-structure.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-1-cli-help.txt`
  - [ ] `.sisyphus/evidence/task-1-structure.txt`

  **Commit**: YES
  - Message: `init(skeleton): project scaffold and dependencies`
  - Files: `pyproject.toml`, `src/curlguard/`, `tests/`, `rules/`, `scripts/`, `.gitignore`
  - Pre-commit: `python -m pytest tests/ -q` (should collect 0 tests initially)

---

- [x] 2. **Core YARA scanner module**

  **What to do**:
  - Implement `src/curlguard/scanner.py` — `YaraScanner` class with:
    - `__init__(rules_paths: list[str])` — load all `.yar` files from given paths
    - `scan(data: bytes) -> ScanResult` — run YARA match, return matched rules
    - `scan_file(path: str) -> ScanResult` — read file, call `scan()`
    - `reload_rules()` — hot-reload rules (for auto-updater integration)
    - Built-in rules embedded as string (foundation rules: base64-encoded shell payloads, suspicious curl flags, known malware patterns)
  - Implement `src/curlguard/scanner.py` — `ScanResult` dataclass: `clean: bool`, `matches: list[str]`, `rules_triggered: list[str]`, `scan_time_ms: float`
  - Add `src/curlguard/rules/__init__.py` — package for built-in rules
  - Add `src/curlguard/rules/foundation.yar` — 5-10 YARA rules covering common malicious patterns:
    - `base64_encoded_shell` — detects base64-encoded reverse shells or exec payloads
    - `suspicious_curl_flags` — detects `curl ... | bash` patterns in scripts
    - `obfuscated_download` — detects wget/curl downloading to eval
    - `known_malware_header` — catches common malware file signatures (EICAR-like)
    - `network_ioc` — suspicious URLs/IPs in downloaded content
  - Write comprehensive pytest tests: mock YARA, test clean file, test matched rule, test reload

  **Must NOT do**:
  - Don't connect to network — all local operation
  - Don't implement auto-updater logic — just the scanner interface

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: None
  - **Skills Evaluated but Omitted**:
    - `playwright`: Not relevant

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 1)
  - **Parallel Group**: Wave 1 (with Tasks 1, 3, 4, 5, 6)
  - **Blocks**: T7 (TUI), T10 (auto-updater)
  - **Blocked By**: T1 (needs project structure)

  **References**:

  **Pattern References** (existing code to follow):
  - YARA Python binding pattern: `yara.compile()`, `yaras.Rules.match()`
  - Clean separation: scanner is pure function, no I/O side effects except rule loading

  **API/Type References** (contracts to implement against):
  - `ScanResult` dataclass fields: `clean: bool`, `matches: list[str]`, `rules_triggered: list[str]`, `scan_time_ms: float`
  - `YaraScanner` methods: `__init__`, `scan`, `scan_file`, `reload_rules`

  **Test References** (testing patterns to follow):
  - Mock YARA with `unittest.mock.MagicMock` to avoid needing yara-python installed for tests
  - Use `pytest.mark.parametrize` for multiple rule test cases

  **External References** (libraries and frameworks):
  - YARA rule format: `https://yara.readthedocs.io/en/stable/writingrules.html`
  - Example YARA rules from `https://github.com/elastic/protections-artifacts/tree/main/yara/rules`

  **WHY Each Reference Matters**:
  - Elastic rules: Production-quality YARA rules to model our foundation rules on

  **Acceptance Criteria**:

  - [ ] `YaraScanner(['rules/']).scan(b'safe content')` returns `ScanResult(clean=True, ...)`
  - [ ] `YaraScanner(['rules/']).scan(b'...base64...')` returns `ScanResult(clean=False, ...)` with matched rule
  - [ ] `scanner.reload_rules()` re-reads rules from disk without re-initializing
  - [ ] pytest tests pass with mocked YARA
  - [ ] Foundation rules match at least 3 known malicious patterns

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Clean content passes scanner without matches
    Tool: Bash
    Preconditions: YaraScanner initialized with built-in rules
    Steps:
      1. python -c "from curlguard.scanner import YaraScanner; s = YaraScanner(['rules/']); r = s.scan(b'#!/bin/bash\necho hello'); print(r.clean)"
    Expected Result: Output is "True"
    Failure Indicators: clean=False when scanning benign content
    Evidence: .sisyphus/evidence/task-2-clean-pass.txt

  Scenario: Malicious base64-encoded payload triggers detection
    Tool: Bash
    Preconditions: YaraScanner initialized with built-in rules
    Steps:
      1. python -c "from curlguard.scanner import YaraScanner; s = YaraScanner(['rules/']); r = s.scan(b'...'); print(r.clean)" where ... is a known malicious payload
    Expected Result: clean=False, rules_triggered contains 'base64_encoded_shell'
    Failure Indicators: No detection of known malicious pattern
    Evidence: .sisyphus/evidence/task-2-malware-detect.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-2-clean-pass.txt`
  - [ ] `.sisyphus/evidence/task-2-malware-detect.txt`

  **Commit**: YES (grouped with Wave 1)
  - Message: `init(skeleton): project scaffold and foundation modules` (already committed in T1)
  - Files: `src/curlguard/scanner.py`, `src/curlguard/rules/foundation.yar`, `tests/test_scanner.py`
  - Pre-commit: `python -m pytest tests/test_scanner.py -v`

---

- [x] 3. **Config loader (paths, settings, env var overrides)**

  **What to do**:
  - Implement `src/curlguard/config.py` — `CurlGuardConfig` dataclass with fields:
    - `mode: Literal["per-user", "system-wide"]`
    - `log_path: Path` — audit log location
    - `rules_dirs: list[Path]` — directories to scan for `.yar` files
    - `quarantine_dir: Path` — where flagged files go
    - `real_curl_path: Path` — path to original curl binary (e.g., `/usr/bin/curl.real`)
    - `update_url: str | None` — URL to fetch updated rules from
    - `update_interval_hours: int` — how often to check for updates (default 24)
    - `ssl_warn_only: bool` — if True, SSL bypasses are warnings not blocks
  - Implement `load_config()` — detect mode from install location, check env vars (`CURLGUARD_LOG`, `CURLGUARD_RULES`, etc.), return `CurlGuardConfig`
  - Support env var overrides: `CURLGUARD_MODE`, `CURLGUARD_LOG_PATH`, `CURLGUARD_RULES_DIR`, `CURLGUARD_QUARANTINE`, `CURLGUARD_UPDATE_URL`
  - Write pytest tests: default values, env var override, per-user vs system-wide detection

  **Must NOT do**:
  - Don't create directories or files — just compute paths
  - Don't load YARA rules — just define where they should be

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 1)
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 4, 5, 6)
  - **Blocks**: T6 (binary wrapper), T8 (real curl manager)
  - **Blocked By**: T1 (needs project structure)

  **References**:

  **API/Type References** (contracts to implement against):
  - `CurlGuardConfig` fields and their types
  - Env var naming convention: `CURLGUARD_*` prefix

  **External References** (libraries and frameworks):
  - Python pathlib for path handling (no os.path usage)
  - `dataclasses` for immutability

  **Acceptance Criteria**:

  - [ ] `load_config()` returns config with correct per-user defaults when installed in `~/.local/bin`
  - [ ] `load_config()` returns config with correct system-wide defaults when installed in `/usr/local/bin`
  - [ ] `CURLGUARD_LOG_PATH=/tmp/test.log` env var overrides `log_path`
  - [ ] All env vars in `CURLGUARD_*` are recognized and override defaults
  - [ ] pytest tests pass

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Config detects per-user mode from install path
    Tool: Bash
    Preconditions: curlguard binary installed in ~/.local/bin/
    Steps:
      1. CURLGUARD_MODE=per-user python -c "from curlguard.config import load_config; c = load_config(); print(c.mode)"
    Expected Result: "per-user"
    Failure Indicators: Wrong mode detected
    Evidence: .sisyphus/evidence/task-3-peruser-config.txt

  Scenario: Env var overrides log path
    Tool: Bash
    Preconditions: Any mode
    Steps:
      1. CURLGUARD_LOG_PATH=/tmp/override.log python -c "from curlguard.config import load_config; c = load_config(); print(c.log_path)"
    Expected Result: "/tmp/override.log"
    Failure Indicators: Env var ignored, default path returned
    Evidence: .sisyphus/evidence/task-3-env-override.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-3-peruser-config.txt`
  - [ ] `.sisyphus/evidence/task-3-env-override.txt`

  **Commit**: YES (grouped with Wave 1)
  - Message: `init(skeleton): project scaffold and foundation modules`
  - Files: `src/curlguard/config.py`, `tests/test_config.py`

---

- [x] 4. **Audit logger module (JSON log format, rotation)**

  **What to do**:
  - Implement `src/curlguard/logger.py` — `AuditLogger` class:
    - `__init__(log_path: Path)` — open log file for append, create parent dirs
    - `log(event: AuditEvent)` — write JSON line to log file
    - `close()` — flush and close
    - Context manager protocol (`__enter__`, `__exit__`)
  - Implement `AuditEvent` dataclass: `timestamp: str` (ISO 8601), `url: str`, `destination: str | None`, `scan_result: str` ("clean" | "flagged" | "error"), `rules_triggered: list[str]`, `user_decision: str | None` ("block" | "quarantine" | "allow" | None), `ssl_bypass_detected: bool`, `duration_ms: float`, `exit_code: int`
  - Log rotation: if log file > 10MB, rotate to `.1`, `.2`, etc. (keep 5 files)
  - Thread-safe: use `threading.Lock` around file writes
  - Write pytest tests: JSON format correctness, rotation trigger, thread safety

  **Must NOT do**:
  - Don't actually make network requests — purely log events
  - Don't modify or delete downloaded files

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 1)
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 3, 5, 6)
  - **Blocks**: T6 (binary wrapper), T7 (TUI), T8 (real curl manager)
  - **Blocked By**: T1 (needs project structure)

  **References**:

  **API/Type References** (contracts to implement against):
  - `AuditEvent` dataclass fields
  - `AuditLogger` methods: `log`, `close`, context manager protocol

  **External References** (libraries and frameworks):
  - Python `logging.handlers.RotatingFileHandler` pattern for rotation logic
  - ISO 8601 timestamp format via `datetime.utcnow().isoformat()`

  **Acceptance Criteria**:

  - [ ] `AuditLogger(log_path).log(event)` writes valid JSON line to file
  - [ ] Log file is created with parent directories if they don't exist
  - [ ] Rotation happens when file > 10MB (test by writing large entry)
  - [ ] Multiple concurrent `log()` calls don't corrupt log file
  - [ ] JSON parseable with `jq` or Python json module
  - [ ] pytest tests pass

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Audit log writes valid JSON for clean download
    Tool: Bash
    Preconditions: temp directory for log
    Steps:
      1. python -c "from curlguard.logger import AuditLogger, AuditEvent; from pathlib import Path; import tempfile; from datetime import datetime; p = Path(tempfile.mkdtemp()) / 'audit.log'; l = AuditLogger(p); l.log(AuditEvent(timestamp=datetime.utcnow().isoformat(), url='https://example.com/file.sh', destination='/tmp/file.sh', scan_result='clean', rules_triggered=[], user_decision=None, ssl_bypass_detected=False, duration_ms=150.0, exit_code=0)); l.close(); print(open(p).read())"
    Expected Result: Valid JSON object with all expected fields on single line
    Failure Indicators: Invalid JSON, missing fields, multi-line entry
    Evidence: .sisyphus/evidence/task-4-json-log.txt

  Scenario: Log rotation triggers at 10MB threshold
    Tool: Bash
    Preconditions: temp directory
    Steps:
      1. python script that writes AuditEvent entries until rotation triggers
      2. ls temp_dir/ — check for rotated file (e.g., audit.log.1)
    Expected Result: Rotated file exists with original content
    Failure Indicators: No rotation, or rotation at wrong size
    Evidence: .sisyphus/evidence/task-4-rotation.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-4-json-log.txt`
  - [ ] `.sisyphus/evidence/task-4-rotation.txt`

  **Commit**: YES (grouped with Wave 1)
  - Message: `init(skeleton): project scaffold and foundation modules`
  - Files: `src/curlguard/logger.py`, `tests/test_logger.py`

---

- [x] 5. **SSL bypass detector (flag parsing, URL inspection)**

  **What to do**:
  - Implement `src/curlguard/ssl_detector.py` — `SslBypassDetector` class:
    - `detect(args: list[str], url: str) -> SslBypassResult` — parse curl args, inspect URL
    - Detect these insecure patterns:
      - `--insecure`, `-k`, `-k` flags in curl args
      - `--sslv3`, `--tlsv1.0`, `--tlsv1.1` (downgraded TLS versions)
      - URL scheme `http://` when host typically uses `https://` (configurable list)
      - Redirect from https → http detected via Location header (handled in curl_manager)
  - Implement `SslBypassResult` dataclass: `is_bypass: bool`, `bypass_type: str | None` (flag/mixed/ssl-version), `severity: Literal["warning", "block"]`, `message: str`
  - Default severity: `warning` unless config has `ssl_warn_only=False` → then `block`
  - Write pytest tests: detect --insecure, detect -k, clean (no bypass), http→https mixed

  **Must NOT do**:
  - Don't actually execute curl — just parse args and URL
  - Don't implement the redirect detection itself (that happens in curl_manager when curl returns 301/302)

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 1)
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 3, 4, 6)
  - **Blocks**: T6 (binary wrapper), T8 (real curl manager)
  - **Blocked By**: T1 (needs project structure)

  **References**:

  **API/Type References** (contracts to implement against):
  - `SslBypassResult` dataclass fields
  - `SslBypassDetector.detect()` signature

  **External References** (libraries and frameworks):
  - curl flag reference: `https://curl.se/docs/manpage.html` — specifically `--insecure`, `-k`, `--tlsv1.0`

  **Acceptance Criteria**:

  - [ ] `detect(['curl', '-k', 'https://example.com/file.sh'], 'https://example.com/file.sh').is_bypass == True`
  - [ ] `detect(['curl', '--insecure', 'https://example.com/file.sh'], 'https://example.com/file.sh').is_bypass == True`
  - [ ] `detect(['curl', 'https://example.com/file.sh'], 'https://example.com/file.sh').is_bypass == False`
  - [ ] pytest tests pass

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Detect --insecure flag as SSL bypass
    Tool: Bash
    Preconditions: SslBypassDetector initialized
    Steps:
      1. python -c "from curlguard.ssl_detector import SslBypassDetector; d = SslBypassDetector(); r = d.detect(['--insecure', 'https://example.com/file.sh'], 'https://example.com/file.sh'); print(r.is_bypass, r.bypass_type)"
    Expected Result: "True flag"
    Failure Indicators: is_bypass=False or bypass_type wrong
    Evidence: .sisyphus/evidence/task-5-insecure-flag.txt

  Scenario: Clean request has no bypass detected
    Tool: Bash
    Preconditions: SslBypassDetector initialized
    Steps:
      1. python -c "from curlguard.ssl_detector import SslBypassDetector; d = SslBypassDetector(); r = d.detect(['https://example.com/file.sh'], 'https://example.com/file.sh'); print(r.is_bypass)"
    Expected Result: "False"
    Failure Indicators: False positive — is_bypass=True for clean request
    Evidence: .sisyphus/evidence/task-5-clean.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-5-insecure-flag.txt`
  - [ ] `.sisyphus/evidence/task-5-clean.txt`

  **Commit**: YES (grouped with Wave 1)
  - Message: `init(skeleton): project scaffold and foundation modules`
  - Files: `src/curlguard/ssl_detector.py`, `tests/test_ssl_detector.py`

---

- [x] 6. **Binary wrapper dispatcher (PATH resolution, pass-through, subprocess)**

  **What to do**:
  - Implement `src/curlguard/wrapper.py` — `CurlWrapper` class:
    - `__init__(config: CurlGuardConfig)` — store config, locate real curl
    - `dispatch(args: list[str]) -> int` — main entry point:
      1. Parse args: detect `-o`, `--output`, redirect to file vs stdout
      2. If output to file: download to temp location first, scan, then move/reveal
      3. If stdout (piping): download to temp, scan, if clean stream to stdout, if blocked abort
      4. Handle SSL bypass detection
      5. Write audit log entry
    - `download_to_temp(args: list[str]) -> tuple[Path, str]` — call real curl with `-o` temp file, return temp path and URL
    - `stream_scan(args: list[str]) -> Iterator[bytes]` — download in chunks, scan incrementally (for piped output)
  - Parse curl args: `-o`, `--output`, `-O`, `--remote-name`, URL positional argument, `-L` (follow redirects)
  - Handle follow redirects (`-L`): pass through to real curl, detect https→http redirect
  - Write pytest tests: mock real curl call, test temp file handling, test audit log call

  **Must NOT do**:
  - Don't actually invoke real curl during tests — mock it
  - Don't modify curl arguments — parse and pass through exactly

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 1)
  - **Parallel Group**: Wave 1 (with Tasks 1, 2, 3, 4, 5)
  - **Blocks**: T7 (TUI), T8 (real curl manager), T11 (installer)
  - **Blocked By**: T1 (needs project structure), T2-T5 (dependencies)

  **References**:

  **API/Type References** (contracts to implement against):
  - `CurlWrapper.dispatch()` — returns exit code int
  - `download_to_temp()` — returns (Path, url)
  - `stream_scan()` — yields bytes

  **External References** (libraries and frameworks):
  - `subprocess.run()` for calling real curl
  - Python `tempfile` module for temp file creation
  - curl argument parsing: position of URL, `-o` / `--output` flags

  **Acceptance Criteria**:

  - [ ] `CurlWrapper(config).dispatch(['-o', '/tmp/out.sh', 'https://example.com/file.sh'])` calls real curl with same args
  - [ ] `dispatch()` calls `AuditLogger.log()` for every invocation
  - [ ] `dispatch()` calls `SslBypassDetector.detect()` before downloading
  - [ ] pytest tests pass with mocked subprocess and logger

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Wrapper passes correct args to real curl
    Tool: Bash
    Preconditions: curlguard installed, real curl at /usr/bin/curl.real
    Steps:
      1. curlguard -o /tmp/test_out.sh https://example.com/file.sh
      2. cat /tmp/test_out.sh (verify content matches)
      3. ls -la /tmp/test_out.sh (verify file exists)
    Expected Result: File downloaded correctly via real curl.real
    Failure Indicators: Wrong file content, real curl not called, path issues
    Evidence: .sisyphus/evidence/task-6-wrapper-pass.png

  Scenario: Audit log written for every curl invocation
    Tool: Bash
    Preconditions: curlguard installed, audit log at expected location
    Steps:
      1. curlguard -o /tmp/test.sh https://example.com/file.sh
      2. tail -1 /path/to/audit.log | python -c "import sys,json; d=json.load(sys.stdin); print(d['url'], d['scan_result'])"
    Expected Result: URL and scan_result in log entry
    Failure Indicators: No log entry, missing fields
    Evidence: .sisyphus/evidence/task-6-audit-log.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-6-wrapper-pass.png`
  - [ ] `.sisyphus/evidence/task-6-audit-log.txt`

  **Commit**: YES (grouped with Wave 1)
  - Message: `init(skeleton): project scaffold and foundation modules`
  - Files: `src/curlguard/wrapper.py`, `tests/test_wrapper.py`

---

- [x] 7. **TUI prompt with textualize (Block/Quarantine/Allow dialog)**

  **What to do**:
  - Implement `src/curlguard/tui.py` — `CurlGuardTUI` class extending `textual.app.App`:
    - Display: filename, URL, matched rules (with severity color), scan time
    - Three action buttons: `[B]lock` (red), `[Q]uarantine` (yellow), `[A]llow` (green)
    - Keyboard shortcuts: B, Q, A keys for fast response
    - Show SSL bypass warning banner if applicable
    - Progress indicator while scanning
  - Implement `prompt_user(scan_result: ScanResult, url: str, ssl_warn: bool) -> str` — non-blocking TUI that returns user's choice
  - TUI runs in its own subprocess so the wrapper can wait for the result
  - Use `textual.widgets.Static`, `textual.widgets.Button`, `textual.layout.Container`
  - Write pytest tests: use `textual.pilot.Pilot` to test TUI interactions without display

  **Must NOT do**:
  - Don't make blocking calls — TUI runs as subprocess, communicates via return code or file descriptor
  - Don't implement any scanning logic in the TUI — just display and prompt

  **Recommended Agent Profile**:
  - **Category**: `visual-engineering`
  - **Skills**: None
  - **Skills Evaluated but Omitted**:
    - `playwright`: Not relevant — terminal UI not browser

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 2)
  - **Parallel Group**: Wave 2 (with Tasks 8, 9, 10, 11)
  - **Blocks**: T11 (installer)
  - **Blocked By**: T2 (scanner), T4 (logger), T6 (wrapper)

  **References**:

  **Pattern References** (existing code to follow):
  - Textualize App pattern: `class MyApp(textual.app.App):` with `compose()` method returning widgets
  - Button press handling with `on_button_pressed()` handler
  - Keyboard shortcuts with `textual.binding`

  **Test References** (testing patterns to follow):
  - `textual.pilot.Pilot` for headless TUI testing: `async with app.run_test() as pilot:`

  **External References** (libraries and frameworks):
  - Textualize docs: `https://textual.textualize.io/` — "Getting Started" and "Widgets" sections
  - Textualize examples: `https://github.com/Textualize/textual/tree/main/examples`

  **WHY Each Reference Matters**:
  - The App pattern with compose() and on_* handlers is the canonical textualize structure
  - Pilot testing allows simulating button clicks and keypresses without a display

  **Acceptance Criteria**:

  - [ ] TUI displays: matched rules, URL, filename, action buttons
  - [ ] Pressing B key returns "block"
  - [ ] Pressing Q key returns "quarantine"
  - [ ] Pressing A key returns "allow"
  - [ ] Clicking button returns correct action
  - [ ] SSL bypass warning banner visible when ssl_warn=True
  - [ ] pytest textual tests pass in headless mode

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: TUI renders with matched rule detected
    Tool: Bash
    Preconditions: TUI code implemented, textual installed
    Steps:
      1. python -c "from curlguard.tui import CurlGuardTUI; app = CurlGuardTUI(); print('TUI imported OK')"
    Expected Result: No import errors
    Failure Indicators: ImportError, missing widgets
    Evidence: .sisyphus/evidence/task-7-tui-import.txt

  Scenario: Button press returns correct action
    Tool: Bash (headless)
    Preconditions: TUI app running in test mode
    Steps:
      1. python script using textual.pilot.Pilot to press B button
      2. capture returned action
    Expected Result: Return value is "block"
    Failure Indicators: Wrong return value, no response
    Evidence: .sisyphus/evidence/task-7-button-press.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-7-tui-import.txt`
  - [ ] `.sisyphus/evidence/task-7-button-press.txt`

  **Commit**: YES (grouped with Wave 2)
  - Message: `feat(core): YARA scanner, TUI, curl manager, updater, installer`
  - Files: `src/curlguard/tui.py`

---

- [x] 8. **Real curl binary manager (rename original, call with correct args)**

  **What to do**:
  - Implement `src/curlguard/curl_manager.py` — `CurlManager` class:
    - `install()` — rename `/usr/bin/curl` to `/usr/bin/curl.real`, create wrapper script at `/usr/bin/curl` that calls `curlguard`
    - `uninstall()` — restore `/usr/bin/curl.real` to `/usr/bin/curl`
    - `is_installed() -> bool` — check if curl.real exists and curl is the wrapper
    - `call_real_curl(args: list[str], env: dict[str, str]) -> subprocess.CompletedProcess` — invoke real curl with args
  - Handle case where `curl.real` already exists (idempotent — don't re-wrap)
  - Ensure wrapper script is executable: `#!/bin/sh` dispatch to `curlguard`
  - Per-user install: same logic but operates on `~/.local/bin/curl` and `~/.local/bin/curl.real`
  - Write pytest tests: mock filesystem operations, test install/uninstall idempotency

  **Must NOT do**:
  - Don't overwrite existing `curl.real` if it already exists (it was already the real curl)
  - Don't fail if curl.real is already present — just verify and continue

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 2)
  - **Parallel Group**: Wave 2 (with Tasks 7, 9, 10, 11)
  - **Blocks**: T11 (installer)
  - **Blocked By**: T3 (config), T4 (logger), T5 (SSL detector), T6 (wrapper)

  **References**:

  **External References** (libraries and frameworks):
  - Shell wrapper script pattern: `#!/bin/sh\nexec curlguard "$@"`
  - `/bin/sh` is POSIX sh — works in all shells (bash, zsh, fish, dash)

  **Acceptance Criteria**:

  - [ ] `CurlManager.install()` renames /usr/bin/curl to /usr/bin/curl.real and creates wrapper
  - [ ] `curl` command after install calls `curlguard` (which calls `curl.real`)
  - [ ] `CurlManager.uninstall()` restores original state
  - [ ] `is_installed()` returns correct boolean
  - [ ] Per-user install works in `~/.local/bin/`
  - [ ] pytest tests pass

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Install creates curl.real and curl wrapper
    Tool: Bash
    Preconditions: Running as user with write access to /usr/local/bin or ~/.local/bin
    Steps:
      1. python -c "from curlguard.curl_manager import CurlManager; CurlManager('per-user').install()"
      2. ls ~/.local/bin/curl ~/.local/bin/curl.real
    Expected Result: Both files exist, curl is executable script calling curlguard
    Failure Indicators: Missing files, wrong content
    Evidence: .sisyphus/evidence/task-8-install.txt

  Scenario: Uninstall restores original curl
    Tool: Bash
    Preconditions: curlguard installed in per-user mode
    Steps:
      1. python -c "from curlguard.curl_manager import CurlManager; CurlManager('per-user').uninstall()"
      2. ls ~/.local/bin/curl.real (should not exist, or curl.real is now curl)
    Expected Result: curl.real gone, curl restored to original
    Failure Indicators: Original not restored
    Evidence: .sisyphus/evidence/task-8-uninstall.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-8-install.txt`
  - [ ] `.sisyphus/evidence/task-8-uninstall.txt`

  **Commit**: YES (grouped with Wave 2)
  - Message: `feat(core): YARA scanner, TUI, curl manager, updater, installer`
  - Files: `src/curlguard/curl_manager.py`

---

- [x] 9. **User rules directory watcher + loader**

  **What to do**:
  - Implement `src/curlguard/rules_watcher.py` — `RulesWatcher` class:
    - `__init__(rules_dirs: list[Path])` — scan given directories for `.yar` files
    - `load_all() -> dict[Path, yara.Rules]` — load all rules from all dirs
    - `watch() -> list[Path]` — return list of `.yar` files that are newer than last load (for hot reload)
    - `auto_reload(callback: Callable)` — watch filesystem for changes, call callback on change (uses ` watchdog` or polling)
  - Merge rules from: built-in rules (`src/curlguard/rules/`), user rules dirs (config), auto-updater rules
  - YARA compilation: compile all rules together, handle duplicate rule names (suffix with `_1`, `_2`)
  - Write pytest tests: mock filesystem, test merging, test hot reload trigger

  **Must NOT do**:
  - Don't download anything — just watch local filesystem
  - Don't require watchdog if not installed — implement simple polling fallback

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 2)
  - **Parallel Group**: Wave 2 (with Tasks 7, 8, 10, 11)
  - **Blocks**: T11 (installer)
  - **Blocked By**: T2 (scanner)

  **References**:

  **External References** (libraries and frameworks):
  - `watchdog` library for filesystem monitoring (optional dependency)
  - Python `stat` module for file modification time checking

  **Acceptance Criteria**:

  - [ ] `load_all()` returns compiled YARA rules from all directories
  - [ ] New `.yar` file added to rules dir is detected by `watch()`
  - [ ] `auto_reload()` calls callback when rules change
  - [ ] pytest tests pass

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Load rules from multiple directories
    Tool: Bash
    Preconditions: rules dirs with .yar files
    Steps:
      1. python -c "from curlguard.rules_watcher import RulesWatcher; rw = RulesWatcher(['rules/']); rules = rw.load_all(); print('loaded')"
    Expected Result: "loaded" printed, no YARA compilation errors
    Failure Indicators: YARA compile error, missing rules
    Evidence: .sisyphus/evidence/task-9-load-all.txt

  Scenario: Hot reload detects new rules
    Tool: Bash
    Preconditions: RulesWatcher watching a directory
    Steps:
      1. touch rules/new_test.yar
      2. python -c "from curlguard.rules_watcher import RulesWatcher; rw = RulesWatcher(['rules/']); changed = rw.watch(); print(changed)"
    Expected Result: Path to new_test.yar in changed list
    Failure Indicators: New file not detected
    Evidence: .sisyphus/evidence/task-9-watch.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-9-load-all.txt`
  - [ ] `.sisyphus/evidence/task-9-watch.txt`

  **Commit**: YES (grouped with Wave 2)
  - Message: `feat(core): YARA scanner, TUI, curl manager, updater, installer`
  - Files: `src/curlguard/rules_watcher.py`

---

- [x] 10. **Auto-update engine (daily check, fetch, reload YARA)**

  **What to do**:
  - Implement `src/curlguard/auto_updater.py` — `AutoUpdater` class:
    - `__init__(config: CurlGuardConfig, scanner: YaraScanner)` — store config and scanner reference
    - `check_and_update()` — check if update needed (based on `update_interval_hours`), fetch new rules, hot-reload scanner
    - `should_update() -> bool` — check last update timestamp from `~/.curlguard/.last_update` or `/var/lib/curlguard/.last_update`
    - `fetch_rules(url: str) -> list[Path]` — download `.yar` files to rules cache dir, return downloaded paths
    - `update_timestamp()` — write current time to last update marker file
  - Update source: default `https://github.com/elastic/protections-artifacts/raw/main/yara/rules/evilscape.YARA` (or similar open ruleset) — configurable via `CURLGUARD_UPDATE_URL`
  - On update failure: log warning, continue with existing rules (don't block downloads)
  - Write pytest tests: mock HTTP responses, test update skip (not due), test update trigger (due), test reload call

  **Must NOT do**:
  - Don't update if `update_url` is None (updates disabled)
  - Don't fail the scan if update fails — fallback to existing rules

  **Recommended Agent Profile**:
  - **Category**: `quick`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 2)
  - **Parallel Group**: Wave 2 (with Tasks 7, 8, 9, 11)
  - **Blocks**: T11 (installer)
  - **Blocked By**: T2 (scanner)

  **References**:

  **External References** (libraries and frameworks):
  - `requests` library for HTTP fetching
  - GitHub raw content URL pattern: `https://github.com/{user}/{repo}/raw/{branch}/{path}`

  **Acceptance Criteria**:

  - [ ] `should_update()` returns True when 24+ hours have passed since last update
  - [ ] `should_update()` returns False when <24 hours have passed
  - [ ] `check_and_update()` skips update if not due
  - [ ] `check_and_update()` downloads and reloads rules when due
  - [ ] pytest tests pass with mocked HTTP

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Update skipped when not due
    Tool: Bash
    Preconditions: Recent update timestamp file exists
    Steps:
      1. touch /tmp/.last_update (set to now)
      2. python -c "from curlguard.auto_updater import AutoUpdater; au = AutoUpdater(config_with_recent_update); print(au.should_update())"
    Expected Result: "False"
    Failure Indicators: should_update=True when it should be False
    Evidence: .sisyphus/evidence/task-10-skip-update.txt

  Scenario: Update triggered when 24h+ elapsed
    Tool: Bash
    Preconditions: Old update timestamp (48h ago)
    Steps:
      1. python -c "from curlguard.auto_updater import AutoUpdater; print(AutoUpdater(config_with_old_update).should_update())"
    Expected Result: "True"
    Failure Indicators: False positive
    Evidence: .sisyphus/evidence/task-10-trigger-update.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-10-skip-update.txt`
  - [ ] `.sisyphus/evidence/task-10-trigger-update.txt`

  **Commit**: YES (grouped with Wave 2)
  - Message: `feat(core): YARA scanner, TUI, curl manager, updater, installer`
  - Files: `src/curlguard/auto_updater.py`

---

- [x] 11. **Per-user installer (install-peruser.sh)**

  **What to do**:
  - Implement `scripts/install-peruser.sh`:
    - Check Python 3.10+ available
    - `pip install -e .` (editable install from project dir)
    - Run `CurlManager('per-user').install()` via Python
    - Create `~/.curlguard/` directory structure: `rules/`, `quarantine/`
    - Copy built-in rules to `~/.curlguard/rules/`
    - Print success message with next steps
  - Add to shell rc files: for bash (`~/.bashrc`), zsh (`~/.zshrc`), fish (`~/.config/fish/config.fish`) — add `export PATH="$HOME/.local/bin:$PATH"` if not already present
  - For fish: also add `set -gx CURLGUARD_MODE per-user` to env
  - Print verification instructions: `curl --version` should show curlguard in path
  - Write pytest or bash test: run installer script, verify `~/.local/bin/curl` exists and `~/.local/bin/curl.real` exists

  **Must NOT do**:
  - Don't use sudo — per-user install must not require root
  - Don't modify system /usr/bin/curl — only per-user paths

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 2)
  - **Parallel Group**: Wave 2 (with Tasks 7, 8, 9, 10)
  - **Blocks**: T12 (system-wide installer), T13 (integration tests)
  - **Blocked By**: T6, T7, T8, T9, T10

  **References**:

  **External References** (libraries and frameworks):
  - Shell RC file pattern: append to file if line not already present
  - Fish config: `set -gx VARIABLE value` syntax

  **Acceptance Criteria**:

  - [ ] `bash scripts/install-peruser.sh` completes without sudo
  - [ ] `~/.local/bin/curl` exists and is executable wrapper script
  - [ ] `~/.local/bin/curl.real` is the original curl binary
  - [ ] `~/.curlguard/rules/` contains copied built-in rules
  - [ ] PATH updated in shell rc file
  - [ ] `curl --version` in new shell shows curlguard in path

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Per-user install creates correct directory structure
    Tool: Bash
    Preconditions: Running in clean home directory environment
    Steps:
      1. bash scripts/install-peruser.sh
      2. ls ~/.local/bin/curl ~/.local/bin/curl.real
      3. ls ~/.curlguard/rules/
    Expected Result: All expected files and directories exist
    Failure Indicators: Missing files, wrong permissions
    Evidence: .sisyphus/evidence/task-11-peruser-install.txt

  Scenario: curl command now routes through curlguard
    Tool: Bash
    Preconditions: Per-user install completed, new shell with updated PATH
    Steps:
      1. export PATH="$HOME/.local/bin:$PATH"
      2. which curl
    Expected Result: Path is ~/.local/bin/curl
    Failure Indicators: /usr/bin/curl still being picked up
    Evidence: .sisyphus/evidence/task-11-path-verify.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-11-peruser-install.txt`
  - [ ] `.sisyphus/evidence/task-11-path-verify.txt`

  **Commit**: YES (grouped with Wave 2)
  - Message: `feat(core): YARA scanner, TUI, curl manager, updater, installer`
  - Files: `scripts/install-peruser.sh`

---

- [x] 12. **System-wide installer (install-systemwide.sh, sudo required)**

  **What to do**:
  - Implement `scripts/install-systemwide.sh`:
    - Check running as root (or sudo)
    - `pip install .` (system install — makes `curlguard` CLI globally available)
    - Run `CurlManager('system-wide').install()` via Python
    - Create `/var/lib/curlguard/` directory structure: `rules/`, `quarantine/`, `.last_update`
    - Create `/var/log/curlguard/` for audit logs
    - Copy built-in rules to `/var/lib/curlguard/rules/`
    - Print success message with security note (audit log at `/var/log/curlguard/`)
  - Add `CURLGUARD_MODE=system-wide` to `/etc/environment` or `/etc/profile.d/curlguard.sh`
  - Only modify `/usr/bin/curl` — no user directories
  - Write pytest or bash test: run with sudo, verify system paths

  **Must NOT do**:
  - Don't run without sudo when needed
  - Don't proceed if already installed in per-user mode (detect and warn)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 3 — after T11)
  - **Parallel Group**: Wave 3 (with Tasks 13, 14, 15)
  - **Blocks**: T13 (integration tests)
  - **Blocked By**: T11

  **References**:

  **External References** (libraries and frameworks):
  - `/etc/profile.d/` pattern for setting environment variables system-wide
  - `/var/log/` directory conventions for system services

  **Acceptance Criteria**:

  - [ ] `sudo bash scripts/install-systemwide.sh` completes successfully
  - [ ] `/usr/bin/curl` is the wrapper, `/usr/bin/curl.real` is the original
  - [ ] `/var/lib/curlguard/rules/` contains built-in rules
  - [ ] `/var/log/curlguard/` directory exists for audit logs
  - [ ] `curl --version` shows curlguard in system PATH

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: System-wide install creates correct structure
    Tool: Bash
    Preconditions: Running with sudo
    Steps:
      1. sudo bash scripts/install-systemwide.sh
      2. ls /usr/bin/curl /usr/bin/curl.real
      3. ls /var/lib/curlguard/rules/
    Expected Result: All expected files and directories exist
    Failure Indicators: Missing files, wrong ownership
    Evidence: .sisyphus/evidence/task-12-systemwide-install.txt

  Scenario: Curl routes through curlguard system-wide
    Tool: Bash
    Preconditions: System-wide install completed
    Steps:
      1. which curl
    Expected Result: "/usr/bin/curl"
    Failure Indicators: curl not found or still original
    Evidence: .sisyphus/evidence/task-12-systemwide-curl-path.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-12-systemwide-install.txt`
  - [ ] `.sisyphus/evidence/task-12-systemwide-curl-path.txt`

  **Commit**: YES (grouped with Wave 3)
  - Message: `feat(installer): system-wide install script`
  - Files: `scripts/install-systemwide.sh`

---

- [x] 13. **Integration tests (pytest, real curlguard + real YARA rules)**

  **What to do**:
  - Implement `tests/test_integration.py`:
    - Test full dispatch: `curl https://example.com/file.sh` → curlguard → real curl → scan → output
    - Test: clean file passes through with exit 0
    - Test: known malicious file triggers TUI prompt (mock TUI to return decision)
    - Test: `--insecure` flag triggers SSL bypass warning but doesn't block (warning mode)
    - Test: audit log entry written with correct fields
    - Test: non-existent URL returns curl's 404 exit code
    - Test: redirect following (`-L`) works correctly
  - Use `pytest-mock` to mock the TUI subprocess (return "allow" automatically for testing)
  - Use real YARA scanner with real rules
  - Use real `curl.real` subprocess call
  - Add `tests/conftest.py` with fixtures: `temp_config`, `mock_tui_response`

  **Must NOT do**:
  - Don't actually pipe to bash during tests — scan only, don't execute
  - Don't use network URLs that might go stale — use localhost with Python http.server

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 3)
  - **Parallel Group**: Wave 3 (with Tasks 12, 14, 15)
  - **Blocks**: T14 (true positive test)
  - **Blocked By**: T11, T12

  **References**:

  **Test References** (testing patterns to follow):
  - `pytest-mock` for mocking subprocess and TUI responses
  - `pytest.fixture` for reusable test fixtures
  - `pytest.mark.integration` decorator to distinguish from unit tests

  **External References** (libraries and frameworks):
  - `python -m http.server` for serving test files locally
  - `pytest-mock` pypi: `https://pypi.org/project/pytest-mock/`

  **Acceptance Criteria**:

  - [ ] `pytest tests/test_integration.py -v` passes
  - [ ] Clean file test: exit code 0, no TUI prompt
  - [ ] Flagged file test: TUI called, audit log written
  - [ ] SSL bypass test: warning in output, download proceeds
  - [ ] 404 test: correct curl exit code propagated

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: Integration test - clean file passes through
    Tool: Bash
    Preconditions: curlguard installed (can be per-user or system), pytest installed
    Steps:
      1. python -m pytest tests/test_integration.py::test_clean_file_passes -v
    Expected Result: PASSED
    Failure Indicators: Test FAILED or error
    Evidence: .sisyphus/evidence/task-13-clean-pass.txt

  Scenario: Integration test - flagged file triggers prompt
    Tool: Bash
    Preconditions: curlguard installed, TUI mocked
    Steps:
      1. python -m pytest tests/test_integration.py::test_flagged_file_prompts -v
    Expected Result: PASSED
    Failure Indicators: Test FAILED or TUI not called
    Evidence: .sisyphus/evidence/task-13-flagged-prompt.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-13-clean-pass.txt`
  - [ ] `.sisyphus/evidence/task-13-flagged-prompt.txt`

  **Commit**: YES (grouped with Wave 3)
  - Message: `feat(tests): integration tests`
  - Files: `tests/test_integration.py`, `tests/conftest.py`

---

- [x] 14. **Example true positive test (download known malware sample, verify detection)**

  **What to do**:
  - Download a known malware sample from Malware Bazaar (or similar open malware repository) that matches our YARA rules
  - Save to `examples/known_malware/` with: sample, expected YARA rule match, metadata (MD5, SHA256, source URL)
  - Verify curlguard detects it with TUI prompt
  - Provide test instructions in `examples/README.md` so user can try it themselves:
    ```bash
    # After installing curlguard:
    cd examples/known_malware
    ./test_detection.sh  # runs curlguard on sample, should show TUI prompt
    ```
  - The sample should be a real, non-sandboxed malware file — e.g., a caught-in-the-wild cryptominer, backdoor, or rootkit that has been publicly shared on Malware Bazaar with permission
  - Include clear warnings in the README: "This is REAL malware. Do not execute. Do not pipe to bash."

  **Must NOT do**:
  - Don't execute the malware — only scan it
  - Don't use an empty or fake "malware" file — must be a real sample
  - Don't include ransomware or destructive malware — stick to non-destructive malware (cryptominer, coinhive-style script, infostealer)

  **Recommended Agent Profile**:
  - **Category**: `unspecified-high`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 3)
  - **Parallel Group**: Wave 3 (with Tasks 12, 13, 15)
  - **Blocks**: T15 (README)
  - **Blocked By**: T13

  **References**:

  **External References** (libraries and frameworks):
  - Malware Bazaar: `https://bazaar.abuse.ch/` — open malware repository, samples can be downloaded without account for many types
  - Example: `https://bazaar.abuse.ch/sample/{hash}/` for direct downloads

  **Acceptance Criteria**:

  - [ ] `examples/known_malware/` contains a real malware sample
  - [ ] `curlguard examples/known_malware/sample.sh` triggers TUI prompt
  - [ ] YARA rule match is confirmed in TUI output
  - [ ] `examples/README.md` has clear instructions and safety warnings

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: True positive malware sample triggers detection
    Tool: Bash
    Preconditions: curlguard installed, malware sample in examples/
    Steps:
      1. curlguard -o /tmp/malware_test examples/known_malware/sample.sh 2>&1
      2. echo "Exit code: $?"
    Expected Result: Non-zero exit code, TUI prompt shown (if interactive), or blocked if non-interactive
    Failure Indicators: Clean pass on known malware
    Evidence: .sisyphus/evidence/task-14-true-positive.txt

  Scenario: README has safety warnings
    Tool: Bash
    Preconditions: examples/README.md exists
    Steps:
      1. grep -i "malware\|warning\|do not execute" examples/README.md
    Expected Result: Warning text present
    Failure Indicators: No warnings found
    Evidence: .sisyphus/evidence/task-14-readme-warnings.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-14-true-positive.txt`
  - [ ] `.sisyphus/evidence/task-14-readme-warnings.txt`

  **Commit**: YES (grouped with Wave 3)
  - Message: `feat(tests): true positive example`
  - Files: `examples/known_malware/`, `examples/README.md`

---

- [x] 15. **README + usage documentation**

  **What to do**:
  - Write `README.md`:
    - Project tagline and threat model explanation
    - Quick start: installation (per-user and system-wide)
    - How curlguard works (architecture diagram in text)
    - YARA rules: how to add custom rules, how auto-update works
    - TUI prompt: what each button does (Block/Quarantine/Allow)
    - Audit log: where it lives, what it logs, how to read it
    - SSL bypass detection: what gets flagged
    - Configuration: all `CURLGUARD_*` env vars
    - Troubleshooting: common issues (PATH conflicts, TTY issues)
    - Contributing: how to add YARA rules, how to submit rules upstream
  - Add `CONTRIBUTING.md` with: YARA rule submission guidelines, code style (black, isort), test requirements
  - Add `SECURITY.md` with: responsible disclosure policy, contact info

  **Must NOT do**:
  - Don't include installation instructions that require sudo without noting it
  - Don't show examples that pipe malware to bash without warnings

  **Recommended Agent Profile**:
  - **Category**: `writing`
  - **Skills**: None

  **Parallelization**:
  - **Can Run In Parallel**: YES (Wave 3)
  - **Parallel Group**: Wave 3 (with Tasks 12, 13, 14)
  - **Blocks**: FINAL
  - **Blocked By**: T14

  **References**:

  **External References** (libraries and frameworks):
  - README best practices: clear sections with code blocks, badges
  - Security.md template: `https://github.com/丁香园/.github/blob/master/SECURITY.md` — example security policy

  **Acceptance Criteria**:

  - [ ] README has all sections listed above
  - [ ] Installation instructions work for both per-user and system-wide
  - [ ] Code blocks are tested/accurate
  - [ ] Security warnings prominent on any example involving malware

  **QA Scenarios (MANDATORY)**:

  ```
  Scenario: README covers all major sections
    Tool: Bash
    Preconditions: README.md exists
    Steps:
      1. grep -E "^## " README.md
    Expected Result: All expected sections present (Installation, How It Works, etc.)
    Failure Indicators: Missing sections
    Evidence: .sisyphus/evidence/task-15-readme-sections.txt

  Scenario: Installation instructions are copy-pasteable
    Tool: Bash
    Preconditions: README.md has install section
    Steps:
      1. grep -A5 "Per-user install" README.md
    Expected Result: Complete bash commands that work when copy-pasted
    Failure Indicators: Incomplete commands, missing steps
    Evidence: .sisyphus/evidence/task-15-install-instructions.txt
  ```

  **Evidence to Capture:**
  - [ ] `.sisyphus/evidence/task-15-readme-sections.txt`
  - [ ] `.sisyphus/evidence/task-15-install-instructions.txt`

  **Commit**: YES (grouped with Wave 3)
  - Message: `feat(docs): README and documentation`
  - Files: `README.md`, `CONTRIBUTING.md`, `SECURITY.md`

---

## Final Verification Wave

> 4 review agents run in PARALLEL. ALL must APPROVE. Present consolidated results to user and get explicit "okay" before completing.

- [ ] F1. **Plan Compliance Audit** — `oracle`
  Read the plan end-to-end. For each "Must Have": verify implementation exists (read file, curl endpoint, run command). For each "Must NOT Have": search codebase for forbidden patterns — reject with file:line if found. Check evidence files exist in .sisyphus/evidence/. Compare deliverables against plan.
  Output: `Must Have [N/N] | Must NOT Have [N/N] | Tasks [N/N] | VERDICT: APPROVE/REJECT`

- [ ] F2. **Code Quality Review** — `unspecified-high`
  Run `python -m py_compile` on all .py files + linter (`ruff` or `flake8`) + `python -m pytest tests/`. Review all changed files for: `as any`/`@ts-ignore`, empty catches, `console.log` in prod, commented-out code, unused imports. Check AI slop: excessive comments, over-abstraction, generic names (data/result/item/temp).
  Output: `Build [PASS/FAIL] | Lint [PASS/FAIL] | Tests [N pass/N fail] | Files [N clean/N issues] | VERDICT`

- [ ] F3. **Real Manual QA** — `unspecified-high`
  Start from clean state (uninstalled curlguard). Execute EVERY QA scenario from EVERY task — follow exact steps, capture evidence. Test cross-task integration (features working together, not isolation). Test edge cases: empty state, invalid input, rapid actions. Save to `.sisyphus/evidence/final-qa/`.
  Output: `Scenarios [N/N pass] | Integration [N/N] | Edge Cases [N tested] | VERDICT`

- [ ] F4. **Scope Fidelity Check** — `deep`
  For each task: read "What to do", read actual diff (git log/diff). Verify 1:1 — everything in spec was built (no missing), nothing beyond spec was built (no creep). Check "Must NOT do" compliance. Detect cross-task contamination: Task N touching Task M's files. Flag unaccounted changes.
  Output: `Tasks [N/N compliant] | Contamination [CLEAN/N issues] | Unaccounted [CLEAN/N files] | VERDICT`

---

## Commit Strategy

- **Wave 1**: `init(skeleton): project scaffold and foundation modules` — pyproject.toml, src/curlguard/ (all Wave 1 modules)
- **Wave 2**: `feat(core): YARA scanner, TUI, curl manager, updater, installer` — src/curlguard/ (Wave 2 modules)
- **Wave 3**: `feat(tests): integration tests, true positive example, docs` — tests/, examples/, README.md

---

## Success Criteria

### Verification Commands
```bash
# Help command works
curlguard --help

# Clean file passes through (no output interruption)
curlguard -o /dev/null https://raw.githubusercontent.com/torvalds/linux/master/README
echo "Exit: $?"  # Should be 0

# Malicious file triggers TUI (in non-interactive mode, should block or prompt)
# YARA rule matches on base64-encoded payload pattern
curlguard -o /tmp/test.sh examples/known_malware/sample.sh
echo "Exit: $?"  # Should be non-zero or prompt shown

# SSL bypass flag triggers warning
curlguard -k https://example.com/file.sh 2>&1 | grep -i "warning"
```

### Final Checklist
- [ ] All "Must Have" present
- [ ] All "Must NOT Have" absent
- [ ] All tests pass

