# Working on curlguard

curlguard is a Linux-first curl wrapper. Use Linux or WSL for verification:
the code and tests rely on POSIX locks, signals, permissions, and real curl.

- `src/curlguard/arguments.py` classifies requests; `wrapper.py` stages,
  scans, and delivers supported downloads; `process.py` handles cancellation.
- Scanning/rules live in `scanner.py`, `rules/`, `auto_updater.py`, and
  `rules_watcher.py`. Installation lives in `curl_manager.py` and `scripts/`.
- Preserve pre-delivery scanning, existing destinations on failure, and
  original curl arguments for unsupported requests. Keep skipped/unavailable
  scanning distinct from clean results. Detailed policies and limitations:
  [docs/update-reliability.md](docs/update-reliability.md).
- Never execute the malware samples or pinned installer fixtures. Scan them
  as data. Installation/migration checks must use isolated paths; live system
  installation and package repair are not part of ordinary verification.

Setup, test routing, and failure diagnostics are in
[docs/development.md](docs/development.md). With the Linux dev environment active:

```bash
ruff check src tests scripts/validate-wsl-updates.py
ruff format --check src tests scripts/validate-wsl-updates.py
python -m pytest
```

For production or shared test/configuration changes, run focused tests first,
then all three checks above (the same checks as CI). For isolated test changes,
run the affected tests; expand to the full suite when shared fixtures change.
Documentation-only changes need link/command checks, not a full suite rerun.
