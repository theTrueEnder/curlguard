"""Reproducible fetches, reports and declared bootstrap artifacts (never executed)."""

import hashlib
import json
import os
import subprocess
from pathlib import Path
from unittest.mock import Mock

import pytest
from jsonschema import Draft202012Validator
from referencing import Registry, Resource

from curlguard.publisher import COSIGN_VERSION, validate_publisher, verify
from tests.conftest import PAYLOAD

FIXTURES = Path(__file__).parent / "fixtures" / "publisher"
IDENTITY = "https://github.com/sigstore-conformance/extremely-dangerous-public-oidc-beacon/.github/workflows/extremely-dangerous-oidc-beacon.yml@refs/heads/main"


def validate_document(data, name):
    directory = Path(__file__).resolve().parents[1] / "docs" / "schemas"
    registry, schemas = Registry(), {}
    for path in directory.glob("*.schema.json"):
        schema = json.loads(path.read_text())
        schema["$id"] = path.as_uri()
        Draft202012Validator.check_schema(schema)
        schemas[path.name] = schema
        registry = registry.with_resource(path.as_uri(), Resource.from_contents(schema))
    Draft202012Validator(schemas[name + ".schema.json"], registry=registry).validate(
        data
    )


def lock(source, data=PAYLOAD, publisher=None):
    requirements = {"scan_required": True}
    if publisher:
        requirements["publisher"] = publisher
    return {
        "schema_version": 1,
        "kind": "artifact_lock",
        "source": source,
        "sha256": hashlib.sha256(data).hexdigest(),
        "verification": requirements,
    }


def publisher():
    return validate_publisher(
        {
            "issuer": "https://token.actions.githubusercontent.com",
            "identity": IDENTITY,
            "bundle": str(FIXTURES / "bundle.json"),
            "trusted_root": str(FIXTURES / "trusted-root.json"),
            "bundle_sha256": hashlib.sha256(
                (FIXTURES / "bundle.json").read_bytes()
            ).hexdigest(),
            "trusted_root_sha256": hashlib.sha256(
                (FIXTURES / "trusted-root.json").read_bytes()
            ).hexdigest(),
        },
        Path.cwd(),
    )


def test_report_stdout_and_lock_roundtrip(cli, http_server, tmp_path):
    source = http_server[0] + "/artifact"
    report, pinned = tmp_path / "report.json", tmp_path / "lock.json"
    result = cli(
        ["fetch", source, "--report", report, "--write-lock", pinned], management=True
    )
    assert result.returncode == 0 and result.stdout == PAYLOAD
    data = json.loads(report.read_text())
    validate_document(data, "fetch-report")
    validate_document(json.loads(pinned.read_text()), "artifact-lock")
    assert data["schema_version"] == 1 and data["kind"] == "fetch_report"
    assert data["evidence"]["detection"] == "no_matches"
    assert data["evidence"]["authenticity"] == "unverified"
    assert json.loads(pinned.read_text()) == lock(source)
    result = cli(["fetch", "--lock", pinned], management=True)
    assert result.returncode == 0 and result.stdout == PAYLOAD
    changed = lock(source, b"changed")
    pinned.write_text(json.dumps(changed))
    result = cli(["fetch", "--lock", pinned], management=True)
    assert result.returncode == 17 and not result.stdout


def test_report_alias_and_existing_files_fail_before_network(
    cli, http_server, tmp_path
):
    source, requests, _ = http_server
    path = tmp_path / "out"
    path.write_bytes(b"preserved")
    assert cli(["fetch", source, "--report", path], management=True).returncode != 0
    assert (
        cli(["fetch", source, "--report", path, "-o", path], management=True).returncode
        == 15
    )
    assert not requests and path.read_bytes() == b"preserved"


def test_noninteractive_prompt_blocks(cli, http_server):
    result = cli(
        ["fetch", http_server[0] + "/malware", "--report", "-"],
        management=True,
        overrides={"CURLGUARD_MATCH_POLICY": "prompt"},
    )
    assert result.returncode == 10 and not result.stdout
    assert b"noninteractive_prompt_blocked" in result.stderr


def test_offline_verifier_command_and_failure(monkeypatch):
    run = Mock(
        side_effect=[
            subprocess.CompletedProcess(
                [], 0, json.dumps({"gitVersion": COSIGN_VERSION}).encode()
            ),
            subprocess.CompletedProcess([], 0),
        ]
    )
    monkeypatch.setattr(subprocess, "run", run)
    result = verify(FIXTURES / "artifact.txt", publisher(), Path("/cosign"))
    assert result["status"] == "verified"
    command = run.call_args.args[0]
    assert "--offline" in command and "--trusted-root" in command
    assert command[command.index("--certificate-identity") + 1] == IDENTITY
    assert "--insecure-ignore-tlog" not in command
    run.side_effect = subprocess.CalledProcessError(1, [])
    assert (
        verify(FIXTURES / "artifact.txt", publisher(), Path("/cosign"))["status"]
        == "failed"
    )


@pytest.mark.parametrize("change", ["version", "bundle", "root", "invalid_json"])
def test_verifier_fail_closed(monkeypatch, tmp_path, change):
    policy = publisher()
    run = Mock(
        return_value=subprocess.CompletedProcess(
            [],
            0,
            json.dumps(
                {"gitVersion": "v0" if change == "version" else COSIGN_VERSION}
            ).encode(),
        )
    )
    monkeypatch.setattr(subprocess, "run", run)
    if change == "bundle":
        policy["bundle_sha256"] = "0" * 64
    elif change == "root":
        policy["trusted_root_sha256"] = "0" * 64
    elif change == "invalid_json":
        path = tmp_path / "bundle"
        path.write_bytes(b"{")
        policy["bundle"] = str(path)
        policy["bundle_sha256"] = hashlib.sha256(b"{").hexdigest()
    assert (
        verify(FIXTURES / "artifact.txt", policy, Path("/cosign"))["status"] == "failed"
    )
    assert run.call_count == 1


@pytest.mark.parametrize(
    "mutation", [None, "bytes", "identity", "issuer", "proof", "signature"]
)
def test_real_offline_cosign(tmp_path, mutation):
    executable = os.environ.get("CURLGUARD_TEST_COSIGN")
    if not executable:
        pytest.skip(
            "set CURLGUARD_TEST_COSIGN to pinned Cosign for offline integration checks"
        )
    policy = publisher()
    payload = tmp_path / "artifact"
    payload.write_bytes((FIXTURES / "artifact.txt").read_bytes())
    if mutation == "bytes":
        payload.write_bytes(b"changed")
    elif mutation in {"identity", "issuer"}:
        policy[mutation] = "https://wrong.example/identity"
    elif mutation in {"proof", "signature"}:
        data = json.loads((FIXTURES / "bundle.json").read_text())
        if mutation == "proof":
            del data["verificationMaterial"]["tlogEntries"][0]["inclusionProof"]
        else:
            data["messageSignature"]["signature"] = "AAAA"
        path = tmp_path / "bundle.json"
        path.write_text(json.dumps(data))
        policy["bundle"] = str(path)
        policy["bundle_sha256"] = hashlib.sha256(path.read_bytes()).hexdigest()
    result = verify(payload, policy, Path(executable))
    assert result["status"] == ("verified" if mutation is None else "failed")


@pytest.mark.parametrize("flagged", [False, True])
def test_signed_fetch_keeps_detection_independent(
    cli, http_server, tmp_path, monkeypatch, flagged
):
    executable = os.environ.get("CURLGUARD_TEST_COSIGN")
    if not executable:
        pytest.skip("set CURLGUARD_TEST_COSIGN to pinned Cosign")
    body = (FIXTURES / "artifact.txt").read_bytes()
    monkeypatch.setattr("tests.conftest.PAYLOAD", body)
    source = http_server[0] + "/artifact"
    pinned, report = tmp_path / "lock", tmp_path / "report"
    pinned.write_text(json.dumps(lock(source, body, publisher())))
    rules = tmp_path / "rules"
    rules.mkdir()
    if flagged:
        (rules / "test.yar").write_text(
            'rule inert_test { strings: $a = "DO NOT MODIFY ME!" condition: $a }'
        )
    result = cli(
        ["fetch", "--lock", pinned, "--report", report],
        management=True,
        overrides={
            "CURLGUARD_COSIGN_PATH": executable,
            "CURLGUARD_RULES_DIR": str(rules),
            "CURLGUARD_MATCH_POLICY": "block",
        },
    )
    data = json.loads(report.read_text())
    validate_document(data, "fetch-report")
    assert data["evidence"]["authenticity"] == "verified"
    assert data["evidence"]["detection"] == ("flagged" if flagged else "no_matches")
    assert result.returncode == (10 if flagged else 0)
    assert result.stdout == (b"" if flagged else body)


def test_publisher_failure_before_publication(cli, http_server, tmp_path):
    source = http_server[0] + "/artifact"
    pinned = tmp_path / "lock.json"
    pinned.write_text(json.dumps(lock(source, publisher=publisher())))
    output = tmp_path / "out"
    output.write_bytes(b"preserved")
    result = cli(
        ["fetch", "--lock", pinned, "-o", output],
        management=True,
        overrides={"CURLGUARD_COSIGN_PATH": "/missing/cosign"},
    )
    assert result.returncode == 17 and output.read_bytes() == b"preserved"


@pytest.mark.parametrize("tampered", [False, True])
def test_bootstrap_fetches_only_declared_artifacts(
    cli, http_server, tmp_path, tampered
):
    source, requests, _ = http_server
    manifest = {
        "schema_version": 1,
        "kind": "bootstrap_manifest",
        "artifacts": [
            {
                "id": "bootstrap.txt",
                "role": "bootstrap",
                "lock": lock(source + "/artifact"),
            },
            {
                "id": "secondary.txt",
                "role": "secondary",
                "lock": lock(source + "/empty", b"changed" if tampered else b""),
            },
        ],
    }
    path = tmp_path / "manifest.json"
    path.write_text(json.dumps(manifest))
    directory = tmp_path / "outputs"
    result = cli(
        ["bootstrap", path, "--output-dir", directory, "--json"], management=True
    )
    report = json.loads(result.stdout)
    validate_document(manifest, "bootstrap-manifest")
    validate_document(report, "bootstrap-report")
    assert result.returncode == (17 if tampered else 0)
    assert report["undeclared_secondary_downloads"] == "outside_coverage"
    assert (directory / "bootstrap.txt").read_bytes() == PAYLOAD
    assert (directory / "secondary.txt").exists() is not tampered
    assert len(requests) == 2


def test_manifest_validated_before_network(cli, http_server, tmp_path):
    source, requests, _ = http_server
    path = tmp_path / "manifest.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "kind": "bootstrap_manifest",
                "artifacts": [
                    {"id": "../escape", "role": "bootstrap", "lock": lock(source)}
                ],
            }
        )
    )
    assert (
        cli(
            ["bootstrap", path, "--output-dir", tmp_path / "out"], management=True
        ).returncode
        == 15
    )
    assert not requests
