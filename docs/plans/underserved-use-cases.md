# Underserved use cases: follow-on implementation plan

Implementation status: local scan, quarantine JSON investigation/rescan/export,
versioned fetch reports/locks with offline Cosign, independent transfer budgets,
and fetch-only manifests are implemented. See
[interfaces, schemas and verification](../investigation-and-ci.md) and the
[administrator design and boundary evidence](../organizational-enforcement.md).
Organizational enforcement remains a design with rollout gates; no privileged
enforcement is deployed. The original scope and acceptance criteria follow.

These items are follow-on work, not features claimed by the current redesign.
Shared prerequisites delivered by that batch are staged publication, structured
evidence, hash validation, exact artifact policies, signed rule generations and
installed-runtime health checks. See [security-redesign.md](security-redesign.md).

## 1. Existing-file inspection

- **Interface:** `curlguard scan PATH [--json]`, with one regular-file input and no
  network access. Reuse scanner findings and content-policy evaluation; do not
  import transport checks into a local-file operation.
- **Behavior:** report evidence and stable outcomes for no matches, findings,
  oversized/unreadable input and unavailable scanning. Never modify or execute
  the input. Detect changes during inspection before reporting a content hash.
- **Acceptance:** inert regular files cover each outcome; byte contents, ownership
  and permissions remain unchanged; JSON carries its schema and ruleset identity.
- **Exclusions:** recursive directories, archive expansion, automatic remediation.

## 2. Quarantine investigation

- **Interfaces:** add machine-readable inspect, rescan and deliberate export to
  the existing quarantine commands. Keep historic sidecars readable.
- **Behavior:** rescan using the selected current ruleset, retain original capture
  metadata, and append the new result with its ruleset identity. Verify the stored
  digest and report changes. Export only to a new regular destination after
  revalidation; never execute payloads or implicitly overwrite files.
- **Acceptance:** legacy records, tampered/missing payloads, ambiguous IDs,
  stale findings, destination races and export policy failures are tested.
- **Exclusions:** automatic release, execution and destructive retention policies.

## 3. CI and container workflows

- **Interfaces:** versioned JSON fetch reports and artifact lockfiles containing
  source identity, resolved artifact hash and verification requirements. Keep
  stdout payload bytes separate from machine-readable reports.
- **Behavior:** deterministic noninteractive decisions. Add publisher verification
  using a maintained Sigstore verifier, exact issuer/identity policy and offline
  verification bundles. Signature evidence remains independent of malware findings.
- **Acceptance:** local CI/container examples succeed from pinned inputs; changed
  bytes, wrong identities, invalid bundles and incomplete offline verification
  block before publication. No fixture is executed.
- **Prerequisites:** select and pin a supported verifier/version during that work,
  define report/lockfile schemas, and establish trust-update policy.
- **Exclusions:** executing installers, automatically trusting newly seen signers.

## 4. Large or hostile transfers

- **Interface:** independent limits for staged bytes and total elapsed transfer
  time, configurable separately from scan-size and scan-time limits.
- **Behavior:** supervise the actual staged output. Account for unknown lengths,
  retries, resumed prefixes and decompression. Do not rely solely on curl options
  whose enforcement differs across supported versions. Set an explicit measured
  overshoot bound and reap the transfer process when a budget is exhausted.
- **Acceptance:** endless/chunked streams, misleading lengths, slow trickles,
  decompression expansion and exhausted disk tests terminate within those bounds
  and preserve existing outputs/ETags.
- **Exclusions:** streaming execution and archive extraction.

## 5. Installer bootstrapping

- **Interface:** a manifest-driven workflow for fetching separately declared,
  pinned bootstrap and secondary artifacts without executing them.
- **Behavior:** document that approving one bootstrap script does not approve its
  future downloads. Show independent verification for declared artifacts and mark
  undeclared secondary downloads as outside coverage.
- **Acceptance:** runnable fetch-only examples use local inert fixtures, verify
  each artifact, reject changes and accurately show remaining coverage boundaries.
- **Exclusions:** tracing arbitrary scripts, claiming transitive protection,
  sandbox execution. Any execution feature requires a separate threat-model review.

## 6. Organizational enforcement design

- **Deliverable:** an administrator-deployment and threat-model design covering
  administrator-owned policy, centrally collected audit and an enforcement
  mechanism independent of user PATH/environment settings.
- **Behavior:** enumerate bypasses through absolute curl, other HTTP clients,
  containers, user namespaces and writable local configuration. Treat local JSONL
  audit as best-effort evidence until an independent collector acknowledges it.
- **Acceptance:** demonstrate bypass boundaries and independently enforced controls
  in isolated environments before making organization-wide enforcement claims.
- **Exclusions:** describing either current branch as mandatory organizational
  protection or deploying privileged enforcement during this batch.

## Delivery order

Implement 1–2 first, then 3, 4, 5 and the design in 6. Each item is a separate
reviewable change with Linux/WSL focused tests followed by the full repository
checks when shared code changes. Publisher signatures, archive extraction,
process sandboxing and organizational enforcement are not part of the current
security-redesign batch.
