"""Offline keyless publisher verification delegated to pinned Sigstore Cosign."""

import json
import os
import subprocess
import tempfile
from pathlib import Path

from curlguard.inspection import snapshot
from curlguard.policy import sha256

COSIGN_VERSION = "v3.1.3"


def validate_publisher(raw, base):
    if not isinstance(raw, dict) or set(raw) != {
        "issuer",
        "identity",
        "bundle",
        "bundle_sha256",
        "trusted_root",
        "trusted_root_sha256",
    }:
        raise ValueError(
            "publisher requires exact issuer, identity, bundle and trusted_root with SHA-256 pins"
        )
    result = dict(raw)
    for key in ("issuer", "identity", "bundle", "trusted_root"):
        if (
            not isinstance(result[key], str)
            or not result[key]
            or any(ord(c) < 32 for c in result[key])
        ):
            raise ValueError(f"invalid publisher {key}")
    for key in ("bundle", "trusted_root"):
        result[key] = str((base / result[key]).absolute())
        result[key + "_sha256"] = sha256(result.get(key + "_sha256"))
    return result


def verify(payload, policy, executable):
    """Local bundle/root only; no discovery, network fallback or trust refresh."""
    result = {
        "verifier": "cosign",
        "version": COSIGN_VERSION,
        "issuer": policy["issuer"],
        "identity": policy["identity"],
        "offline": True,
        "status": "failed",
    }
    with tempfile.TemporaryDirectory(prefix="curlguard-cosign-") as home:
        env = {"PATH": os.defpath, "HOME": home, "XDG_CONFIG_HOME": home}
        try:
            version = subprocess.run(
                [str(executable), "version", "--json"],
                capture_output=True,
                timeout=5,
                env=env,
                check=True,
            )
            version_data = json.loads(version.stdout)
            if (
                not isinstance(version_data, dict)
                or version_data.get("gitVersion") != COSIGN_VERSION
            ):
                result["reason"] = "unsupported_verifier_version"
                return result
            with (
                snapshot(policy["bundle"], 16 * 1024 * 1024) as (
                    bundle,
                    bundle_facts,
                    _,
                ),
                snapshot(policy["trusted_root"], 4 * 1024 * 1024) as (
                    root,
                    root_facts,
                    _,
                ),
            ):
                if (
                    bundle_facts["sha256"] != policy["bundle_sha256"]
                    or root_facts["sha256"] != policy["trusted_root_sha256"]
                ):
                    result["reason"] = "verification_material_mismatch"
                    return result
                data = json.loads(bundle.read_text(encoding="utf-8"))
                if (
                    not isinstance(data, dict)
                    or data.get("mediaType")
                    != "application/vnd.dev.sigstore.bundle.v0.3+json"
                ):
                    result["reason"] = "unsupported_bundle_format"
                    return result
                subprocess.run(
                    [
                        str(executable),
                        "verify-blob",
                        "--offline",
                        "--bundle",
                        str(bundle),
                        "--trusted-root",
                        str(root),
                        "--certificate-identity",
                        policy["identity"],
                        "--certificate-oidc-issuer",
                        policy["issuer"],
                        str(Path(payload).absolute()),
                    ],
                    capture_output=True,
                    timeout=30,
                    env=env,
                    check=True,
                )
            result["status"] = "verified"
            result["reason"] = "offline_bundle_verified"
        except (OSError, ValueError, subprocess.SubprocessError):
            result["reason"] = "offline_verification_failed"
    return result
