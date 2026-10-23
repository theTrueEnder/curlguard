# Mitigation validation — October 23, 2026

Installer recovery and edition integration are complete locally. Remote release
integration remains pending. This report supplements the historical
[October 16 redesign validation](redesign-validation.md); it does not replace its
dated results or imply that hosted CI has run on unpublished commits.

## Tested source commits

| Edition | Source commit | Full pytest result | Lint and formatting |
|---|---|---|---|
| General | `d484afe1184921e9058f2baab92a63aa8fdb2751` | 259 passed, no skips, 128.30 s | Passed |
| Security | `21993a8710413fcf85ab533b4505e3e8d3e8648e` | 259 passed, no skips, 131.95 s | Passed |

The security source commit merges general's recovery implementation and shared
investigation/reproducible-fetch workflows. Its strict defaults remain intact.
The parity gate passed for these refs: only `src/curlguard/edition.py` and the
README edition-audience paragraph differ. Subsequent documentation commits do not
change the tested implementation.

Verification used WSL Ubuntu, Python 3.12.3, curl 8.5.0, YARA 4.5.4, Ruff 0.17.1,
and the real offline Cosign v3.1.3 verifier. Focused installation/parity tests
preceded the general full suite; 96 focused installation, policy, workflow,
investigation, and transfer-budget tests preceded the security full suite. Tests
used each worktree's `src` explicitly, rather than another branch's editable
installation. Installed-artifact tests imported their separate installed package.

Commands, run independently in each worktree:

```bash
ruff check src tests scripts/validate-wsl-updates.py scripts/install-runtime.py scripts/check-edition-parity.py
ruff format --check src tests scripts/validate-wsl-updates.py scripts/install-runtime.py scripts/check-edition-parity.py
PYTHONPATH=src CURLGUARD_TEST_COSIGN=/tmp/curlguard-cosign-v3.1.3 python -m pytest
```

The existing Ubuntu 22.04/Python 3.10 and Ubuntu 24.04/Python 3.12 hosted matrix
remains configured. That hosted matrix has not been run for these local candidates;
the new manual workflow-dispatch parity job is also awaiting remote rollout.

## Installer failure and recovery

Publication now prepares originals and replacements before touching either live
wrapper. A durable transaction survives interrupted publication; install,
uninstall, and recovery share a lock. Restoration renames prepared originals and
does not allocate rollback backups after failure. The parent conservatively
retains a validated candidate after any uncertain publication attempt.

Automated coverage includes first/second publication failure, simulated ENOSPC
after preparation, failed rollback rename, preparation failure, process death,
lock contention/release, repeated recovery, and committed-transaction cleanup.
Unsafe permissions, symlinks, changed backups, and concurrent wrapper edits cause
refusal. An unresolved transaction blocks install and uninstall. Public per-user
recovery succeeds despite invalid download-policy settings and an isolated distro
root used during installer health checking.

Actual offline built-wheel checks also ran in private temporary layouts for both
editions:

- Per-user installation and upgrade succeeded, preserving the earlier runtime.
  A third installation injected second-wrapper publication failure and rollback
  rename failure into the installed manager. The installer returned failure and
  retained its candidate Python, old runtime, journal, and backup. Candidate
  doctor succeeded; the absolute `-I -m curlguard.cli recover-install` command
  restored both old wrappers. Repeating recovery was safe, and uninstall removed
  both wrappers.
- Root-owned system-layout installation, upgrade, doctor, and uninstall succeeded
  under `/tmp`. The helper and inputs were staged into root-owned storage before
  installation. Ownership reports were safe, isolated, and package-in-runtime.
  The copied distro curl remained byte-identical.
- Wheel and sdist tests verified bundled resources and installed imports outside
  the checkout. The sdist produced a wheel. Installer shell syntax checks passed.

The smoke harness initially encountered two setup errors: a copied curl missing
its executable bit and direct doctor using the wrong mode. Corrected isolated
setups passed. The per-user recovery test then exposed the irrelevant distro-root
binding, which was fixed in `d484afe` and included in both final full-suite runs.

No malware sample or pinned installer fixture was executed. No live wrapper,
system package, or global Python installation was modified. A surviving wrapper
can use a retained runtime while recovery is pending; replacement of the pair is
recoverable, not a claim of two-file power-loss atomicity.

## Local artifacts and recovery records

These are disposable WSL paths on the validation machine, not published releases:

| Evidence | Location |
|---|---|
| General distribution, SHA256SUMS, failure log and smoke result | `/tmp/curlguard-mitigation-smoke-qz4cpmbo` |
| Security distribution, SHA256SUMS, failure log and smoke result | `/tmp/curlguard-mitigation-smoke-acc2tfak` |
| General root-owned system-layout result | `/tmp/curlguard-system-mitigation-luq4q1lc` |
| Security root-owned system-layout result | `/tmp/curlguard-system-mitigation-pnvzvaee` |

Edition-specific directories prevent identical wheel filenames from being
confused. Wheel SHA-256 values:

```text
general  60e22dda99c41e5f4d0cc7bd98dac2cdb70bd0077302c7a8859c2655b3b429be
security 9178f19a69c09b85f89a550c50621b4cf5e8a915bb23c4e03267ab7ecdf4820e
```

A verified full-history recovery bundle and pre-integration ref listing are saved
locally under `.git/mitigation-recovery-2026-10-23/`. The bundle is `before.bundle`;
`refs-before.txt` records the saved local refs, and `remote-before.txt` records the
remote default and maintained-branch heads. Inspect with `git bundle verify` and
restore a saved ref into a new branch with `git fetch PATH_TO_BUNDLE
refs/heads/NAME:refs/heads/RECOVERY_NAME`, using the exact recorded names. Do not
overwrite current work to inspect historical commits.

## Release gates still open

The remote default was checked before integration: `master` at
`941beb3ba5c40b3f6b0d829493b6813439da68f1`; remote general was `804ae94`, and
security had no remote branch. No remote refs or settings were changed in this
implementation step. `master`, `update`, and the lightweight branch retain their
original local heads.

The [mitigation plan](plans/mitigation-and-release.md) requires separately
authorized rollout. Before declaring release integration complete:

1. Recheck remote heads for concurrent changes, then publish both maintained
   branches without force pushes.
2. Obtain green hosted matrix results on the exact published candidates and run
   the parity gate. Configure required checks and branch protections.
3. Make `codex/general-users` the default if that recommendation is accepted;
   retain `master` and the other legacy branches.
4. Verify fresh default and explicit security clones, installed edition identity,
   and published documentation. Restore the recorded default setting if rollout
   fails, without rewriting history.

Items 1 and 2 of the mitigation plan are complete locally. Item 3 is prepared,
with its remote rollout and fresh-clone acceptance checks still open.
