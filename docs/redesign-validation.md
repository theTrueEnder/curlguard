# Security redesign validation

Validation uses WSL Ubuntu, real curl and YARA, local HTTP/HTTPS fixtures and
isolated build/runtime paths. Sample payloads and pinned installer fixtures are
scanned only as data. No live wrapper installation, package repair, ref deletion
or publishing is performed.

Final per-branch results are recorded after the complete runs. The implemented
checks include installed wheel/sdist behavior, signed feeds with ephemeral keys,
resource-limited compiler cleanup, strict transport, artifact pinning, conditional
revalidation, candidate runtime failure and wrapper-pair rollback.
