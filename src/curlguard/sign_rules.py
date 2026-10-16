"""Publisher utility: python -m curlguard.sign_rules --help."""

import argparse
import hashlib
import json
from pathlib import Path

from cryptography.hazmat.primitives import serialization

from curlguard.auto_updater import encode
from curlguard.policy import timestamp


def main():
    parser = argparse.ArgumentParser(
        description="Sign an inert YARA source using an externally provisioned Ed25519 PEM private key"
    )
    parser.add_argument("source", type=Path)
    parser.add_argument("output", type=Path)
    parser.add_argument("--private-key", type=Path, required=True)
    parser.add_argument("--key-id", required=True)
    parser.add_argument("--feed-id", required=True)
    parser.add_argument("--sequence", type=int, required=True)
    parser.add_argument("--published-at", required=True)
    parser.add_argument("--expires-at", required=True)
    args = parser.parse_args()
    if args.sequence < 1 or timestamp(args.expires_at) <= timestamp(args.published_at):
        parser.error("positive sequence and expiration after publication required")
    source = args.source.read_bytes()
    if len(source) > 5 * 1024 * 1024:
        parser.error("source exceeds 5 MiB")
    key = serialization.load_pem_private_key(
        args.private_key.read_bytes(), password=None
    )
    manifest = json.dumps(
        {
            "schema_version": 1,
            "feed_id": args.feed_id,
            "sequence": args.sequence,
            "published_at": args.published_at,
            "expires_at": args.expires_at,
            "rules_sha256": hashlib.sha256(source).hexdigest(),
            "rules": encode(source),
        },
        sort_keys=True,
    ).encode()
    args.output.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "key_id": args.key_id,
                "manifest": encode(manifest),
                "signature": encode(key.sign(manifest)),
            }
        ),
        encoding="utf-8",
    )


if __name__ == "__main__":
    main()
