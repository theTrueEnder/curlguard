# Mitigation plan: installer recovery, edition parity, and release integration

Status: installer recovery and local edition integration complete; remote rollout
pending. See [October 23 validation](../validation-2026-10-23-mitigation.md) for
tested commits, results, artifacts, and remaining release gates.

This plan addresses the three gaps identified in the repository evaluation. It
supplements the [security redesign](security-redesign.md) and
[underserved use cases](underserved-use-cases.md) plans. It does not authorize a
live installation, package publishing, branch deletion, or remote configuration
change.

## Baseline and completion order

The evaluated general branch was `804ae94`, and the security branch was
`fee9b25`. General passed 242 tests; security passed 199 tests. Both passed lint
and formatting checks under Linux. These results establish the starting point;
they do not validate the mitigations below.

The three remaining gaps are:

1. A failed wrapper upgrade can leave a wrapper pointing to a deleted candidate
   runtime when publication and rollback both fail.
2. The security edition lacks the shared workflows added in general commit
   `804ae94`, including investigation and reproducible fetch capabilities.
3. The remote default remains the older `master` implementation, the security
   branch is local-only, and current release validation needs a separate report.

Complete installer recovery first, merge shared work into security second, and
perform release integration last. Preserve concurrent changes and all existing
branches throughout.

## 1. Make failed installation recoverable — P0

### Required invariant

Never remove a runtime that a published wrapper might reference. A failed
upgrade must either restore the previous wrapper pair or retain the runtimes,
backups, and recovery information needed to repair it. Report failure honestly
when the filesystem prevents restoration; do not promise atomic replacement of
two independent paths across process interruption or power loss.

### Implementation

Change `src/curlguard/curl_manager.py` and `scripts/install-runtime.py` together:

- Serialize installation, uninstall, and recovery with the same POSIX lock.
- Before changing either live wrapper, prepare both replacement wrappers and
  on-disk backups of all existing wrappers on the target filesystem. Preserve
  required permissions and flush the prepared files and transaction directory.
- Persist a private, versioned transaction record before publication. Record the
  mode, candidate runtime, prior existence, and old/new wrapper fingerprints.
  Derive allowed target paths from the installation mode; never let journal
  contents select arbitrary files to overwrite.
- Restore by renaming already prepared backups. The rollback path must not
  allocate a new temporary backup after the failure has occurred.
- Record publication outcomes explicitly: not attempted, completed, restored, or
  recovery required. Before invoking wrapper publication, the parent installer
  must enter the publication-attempted state. On failure or uncertain subprocess
  outcome after that point, retain the candidate runtime conservatively.
- Remove a failed candidate only when publication never started or its lack of
  live references is established. Keep previous working runtimes.
- Retain transaction data until publication or restoration is confirmed. Recovery
  must inspect actual wrapper fingerprints rather than depend on a final journal
  update succeeding during disk exhaustion.
- Refuse to overwrite a wrapper changed by another actor. Preserve existing
  unrelated-file, symlink, ownership, and explicit legacy-migration protections.

Add an idempotent `recover-install TRANSACTION` command, dispatched before normal
policy loading or scanner initialization. On incomplete recovery, print its
absolute invocation using the retained runtime's Python with `-I`; it must work
without relying on either potentially broken PATH wrapper. Validate transaction
ownership, permissions, expected roots, and fingerprints. Never execute journal
content. Restore old wrappers by default; for a fresh installation, remove only
wrappers demonstrably created by that transaction.

Recovery returns success only after restoration is verified. Use existing
configuration/internal-error conventions for invalid records or incomplete
recovery. A failed installer still returns failure even when rollback succeeds.
Block subsequent installation or uninstall while an unresolved transaction
requires attention. Document recovery and retained-runtime cleanup; do not add
automatic deletion based solely on runtime age.

### Verification and acceptance

Extend `tests/test_distribution.py` with failures at both wrapper publications,
allocation failure after preparation, rollback rename failure, and interruption
after the first publication. Cover fresh installs and upgrades, repeated
recovery, concurrent operations, and refusal of unknown edits or unsafe records.
Inject filesystem failures in isolated paths; no live system installation is
required.

Update the current failed-candidate test: pre-publication failures can discard the
candidate; publication failures must favor retaining a possibly referenced
runtime. Preserve the existing successful-rollback test.

- [x] The reproduced dangling-wrapper case is a regression test.
- [x] Every surviving managed wrapper references an existing validated runtime,
      including when restoration cannot finish.
- [x] Recovery needs no newly allocated backup and is safe to repeat.
- [x] Previous destinations, unrelated files, and `/usr/bin/curl` remain intact.
- [x] Isolated built-wheel install, upgrade, failed upgrade, recovery, and
      uninstall checks pass; unresolved recovery never reports success.

## 2. Restore shared functionality across editions — P1

Implement the common recovery fix on `codex/general-users`, then merge general
into `codex/security-users`. Include the shared capabilities from `804ae94`.
Preserve the security edition's identity, required hashes, strict transport,
unsupported-request blocking, and required-scan behavior. Resolve conflicts by
maintaining one transfer/scanner implementation and explicit edition defaults.

Audit the resulting tree differences. Start the permitted-difference list with
`src/curlguard/edition.py` and audience-specific README text; require an explicit
explanation for any additional security-only capability. Do not exempt common
workflows from security policy merely to make inherited tests pass.

Add a release-readiness parity check comparing the two candidate refs against
that list. Shared changes should have paired integration work and validation.
Do not make an ordinary general-branch PR depend on security already containing
that PR's unmerged commit; enforce synchronization at promotion time.

- [x] Security exposes all intended shared investigation and reproducible-fetch
      workflows with its own resolved policy.
- [x] Strict defaults and explicit relaxations, including disabling mandatory
      hashes, are tested on both editions.
- [x] Tree differences are limited to reviewed edition-specific content.
- [x] Focused tests and all mandatory checks pass independently on both refs.

Use separate worktrees or isolated archives/environments. Verify imports come
from the edition under test. Run the repository's complete lint, formatting, and
pytest checks on Linux/WSL, including `scripts/install-runtime.py` in lint and
formatting checks. Run the real offline Cosign cases and report skips explicitly.
Retain the existing supported Python/Ubuntu CI matrix.

## 3. Complete release integration and current evidence — P1

### Recommended release decision

Make `codex/general-users` the remote default and publish
`codex/security-users` as the maintained strict edition. Preserve `master` as a
legacy branch, including its unique history. Preserve `update` and the original
lightweight branch as well. Do not merge legacy automation bypasses into the
shared engine without a separate policy review.

This is the recommended rollout choice, not an action performed by this plan.
Actual pushing, branch protection, and default-branch changes require a separately
authorized rollout.

### Preparation and rollout gates

1. Add a new dated validation report keyed to the exact candidate commits for
   both editions. Record runtime versions, test counts/skips, real verifier
   coverage, distribution checks, and installer fault-injection outcomes. Keep
   the October 16 report as historical evidence and link to the new report.
2. Build and validate wheel and sdist artifacts independently for both editions.
   Store them in edition-specific directories with SHA-256 manifests to avoid
   confusing artifacts with identical filenames. Check packaged edition identity,
   resources, doctor output, and installed imports outside the checkout.
3. Record the existing remote default and branch heads before rollout. Check for
   concurrent remote changes. Publish both maintained branches normally, without
   force pushes, once authorized.
4. Require hosted CI to pass for both exact published candidates, including the
   supported runtime matrix and the parity gate. Configure appropriate required
   checks and protection against force pushes before switching the default.
5. Switch the default to general only after both editions are available and
   validated. Verify a fresh default clone selects general and an explicit
   security clone ships strict defaults. Check README edition guidance,
   installation examples, migration links, and validation references.

If rollout fails, retain both histories and artifacts, restore the recorded
default setting if necessary, and direct users to the last validated refs.
Repair forward or use ordinary revert commits; do not rewrite published history.
No PyPI upload or live machine installation is needed for these gates.

- [ ] Both maintained editions are remotely available with passing hosted CI.
- [ ] Default-branch behavior matches the agreed audience and documentation.
- [x] Current validation evidence identifies exact refs and remaining limitations.
- [x] Historical and concurrent work remains recoverable and unchanged.

## Closure criteria

Close item 1 only when failure and recovery tests establish the runtime-retention
invariant. Close item 2 only when both editions pass the common acceptance suite
and the reviewed parity gate. Close item 3 only after the authorized remote
rollout and fresh-clone checks succeed. Until then, distinguish code completion
from rollout pending; green tests on one local branch do not close all three.
