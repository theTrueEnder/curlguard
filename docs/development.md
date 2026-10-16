# Development and verification

Use Linux or WSL, Python 3.10+, curl 7.70+, OpenSSL, and real YARA.
Native Windows is not the verification target: POSIX locks, process groups,
and filesystem semantics are part of the behavior under test. CI's supported
version matrix is defined in [ci.yml](../.github/workflows/ci.yml).

From the repository root on Linux/WSL (Debian/Ubuntu prerequisites):

```bash
# Installs system prerequisites; only needed when preparing the environment.
sudo apt-get install python3-venv build-essential libyara-dev curl openssl
python3 -m venv .venv
source .venv/bin/activate
python -m pip install -e '.[dev]'
python -c 'import yara; print(yara.__version__)'
```

If a Windows virtual environment already occupies `.venv`, use a separate Linux
path such as `/tmp/curlguard-dev-env` for both creation and activation.

## Choose tests by changed behavior

Run `python -m pytest` followed by the relevant paths below. These are starting
points, not mutually exclusive suites; select multiple rows for shared changes.

| Changed area | Focused tests under `tests/` |
|---|---|
| Curl argument classification | `test_arguments.py`, `test_downloads.py` |
| Download staging, delivery, cancellation, process handling | `test_downloads.py`, `test_resilience.py`, `test_integration.py` |
| Scanner or bundled YARA rules | `test_scanner.py`, `test_resilience.py`, `test_integration.py` |
| Remote rule updates | `test_auto_updater.py`, `test_resilience.py` |
| Configuration, logging, quarantine, installation | `test_config.py`, `test_logger.py`, `test_resilience.py`, `test_integration.py` |
| CLI, prompts, TLS option detection | `test_cli.py`, `test_tui.py`, `test_ssl_detector.py`, `test_integration.py` |

For example: `python -m pytest tests/test_arguments.py tests/test_downloads.py`.
The full verification commands are:

```bash
ruff check src tests scripts/validate-wsl-updates.py scripts/install-runtime.py
ruff format --check src tests scripts/validate-wsl-updates.py scripts/install-runtime.py
python -m pytest
```

Pytest defaults to compact progress, short failure tracebacks, and a summary of
non-passing results. Captured failure output and warnings remain visible.
To inspect a failure, rerun its node ID, for example:
`python -m pytest -vv --tb=long tests/test_arguments.py::test_url_like_values_are_not_urls`.
`python -m pytest --lf -vv --tb=long` reruns cached failures; it runs the full suite
if there are no cached failures. A passing diagnostic rerun does not erase the
original failure; investigate possible flakiness.

The mandatory tests use local HTTP/HTTPS servers, mocked remote updates, and
isolated install paths. `tests/fixtures/installers/manifest.json` pins installer
snapshots by URL and hash; tests scan those files without executing them.
Do not run examples that pipe payloads to a shell as verification.
Optional WSL/APT validation is separate from the suite and accesses network
repositories; see [update-reliability.md](update-reliability.md#validation).

## Search scope

Start with `rg` in `src/curlguard` and the relevant tests. Installer fixtures
remain searchable for rule work. The historical `.sisyphus/plans/curlguard.md`
is already excluded by ripgrep's default hidden-file behavior; read it explicitly
only for historical context. Use `rg --hidden` when intentionally searching hidden
project files, such as CI configuration.

## Distribution and redesign verification

`tests/test_distribution.py` builds wheel and sdist in an isolated source copy;
`python -m build` builds the wheel from that sdist. Installed-artifact checks import
from a separate installation outside the checkout with source injection disabled.
The development extra includes `build`. Mandatory tests do not download artifacts
or execute fixtures. Installer-failure tests use isolated paths and injected
subprocess failures; real installation smoke checks must use a temporary HOME,
a private prefix and an isolated distro-curl layout, never live system paths.

`test_policy.py` tests pre-publication hashes, scoped exceptions and transport;
`test_findings.py` tests inert corpus findings and real compiler worker cleanup;
`test_auto_updater.py` signs with ephemeral keys and mocks only update HTTP.
Existing differential curl tests explicitly select compatibility settings; separate
edition-default tests verify the branch's actual shipped strictness and overrides.

Shared fixes flow from `codex/general-users` into `codex/security-users`. The latter
changes only the shipped edition/default module and its README audience statement
unless an explicitly gated security-only feature is added. Keep runtime imports
pointing at the tested worktree or installed artifact when reusing development
interpreters. See the [redesign plan](plans/security-redesign.md) and
[follow-on use cases](plans/underserved-use-cases.md).
