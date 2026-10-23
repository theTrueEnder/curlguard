"""Read-only local inspection against a private, bounded snapshot."""

import hashlib
import os
import stat
import tempfile
from contextlib import contextmanager
from pathlib import Path

from curlguard.evidence import Evidence
from curlguard.policy import evaluate_findings


def identity(s):
    return (s.st_dev, s.st_ino, s.st_size, s.st_mtime_ns, s.st_ctime_ns, s.st_mode)


class InspectionError(OSError):
    def __init__(self, outcome):
        self.outcome = outcome
        super().__init__(outcome)


@contextmanager
def snapshot(path, max_bytes):
    """Reject special files/symlinks and detect replacement or concurrent writes."""
    fd = os.open(path, os.O_RDONLY | os.O_NOFOLLOW | os.O_NONBLOCK)
    if not stat.S_ISREG(os.fstat(fd).st_mode):
        os.close(fd)
        raise InspectionError("not_regular")
    with (
        os.fdopen(fd, "rb") as source,
        tempfile.TemporaryDirectory(prefix="curlguard-inspect-") as directory,
    ):
        before = os.fstat(source.fileno())
        if not stat.S_ISREG(before.st_mode):
            raise InspectionError("not_regular")
        if before.st_size > max_bytes:
            raise InspectionError("oversized")
        staged = Path(directory) / "payload"
        digest, size = hashlib.sha256(), 0
        with staged.open("xb") as out:
            os.chmod(staged, 0o600)
            while chunk := source.read(min(1024 * 1024, max_bytes - size + 1)):
                size += len(chunk)
                if size > max_bytes:
                    raise InspectionError("oversized")
                digest.update(chunk)
                out.write(chunk)

        def unchanged():
            try:
                return (
                    identity(before)
                    == identity(os.fstat(source.fileno()))
                    == identity(Path(path).lstat())
                )
            except OSError:
                return False

        if not unchanged():
            raise InspectionError("changed")
        yield staged, {"sha256": digest.hexdigest(), "size": size}, unchanged


def inspect_file(path, config, scanner, *, destination=None, expected=None):
    """No transports, updates, execution, or input modifications. Export is explicit."""
    evidence = Evidence()
    report = {
        "schema_version": 1,
        "kind": "local_scan",
        "path": str(path),
        "ruleset_id": scanner.ruleset_id,
        "outcome": "unreadable",
        "sha256": None,
        "size": None,
    }
    code = 13
    exporting = False
    try:
        with snapshot(path, config.max_scan_bytes) as (staged, facts, unchanged):
            ready = True
            if config.update_url:
                from curlguard.auto_updater import AutoUpdater

                ready = AutoUpdater(config, scanner).load_active()["usable"]
            report["ruleset_id"] = scanner.ruleset_id
            if not ready and config.require_fresh_rules:
                report["outcome"] = "unavailable"
                evidence.detection = "unavailable"
                evidence.decision, evidence.reason = (
                    "block",
                    "required_rules_unavailable",
                )
            else:
                result = scanner.scan_file(staged)
                report["outcome"] = result.status
                evidence.detection = "no_matches" if result.clean else result.status
                evidence.findings = result.findings
                if result.status in {"unavailable", "error"}:
                    evidence.decision, evidence.reason = "block", "scan_failure"
                elif result.clean:
                    evidence.decision, evidence.reason = "allow", "scan_no_matches"
                    code = 0
                else:
                    decision = evaluate_findings(result, config, set())
                    evidence.decision, evidence.reason = (
                        decision.action,
                        decision.reason,
                    )
                    code = 10
            if not unchanged():
                raise InspectionError("changed")
            report.update(facts)
            if expected is not None:
                evidence.integrity = (
                    "matched" if facts["sha256"] == expected else "mismatched"
                )
                if evidence.integrity == "mismatched":
                    evidence.decision, evidence.reason = (
                        "block",
                        "stored_digest_mismatch",
                    )
                    code = 17
            if destination is not None:
                if evidence.decision != "allow" or code not in {0, 10}:
                    report["export"] = "blocked_policy"
                    code = code if code else 13
                else:
                    from curlguard.reports import publish_new

                    exporting = True
                    publish_new(staged, destination)
                    report["export"] = str(destination)
                    code = 0
    except InspectionError as exc:
        report.update(outcome=exc.outcome, sha256=None, size=None)
        code = 17 if exc.outcome == "changed" else 13
        evidence.decision, evidence.reason = "block", exc.outcome
    except OSError:
        evidence.decision, evidence.reason = "block", "unreadable_or_export_failed"
        code = 16 if exporting else 13
    report["evidence"] = evidence.public()
    report["exit_code"] = code
    return report, code
