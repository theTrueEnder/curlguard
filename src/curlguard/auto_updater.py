"""Explicit signed-feed updates with atomic, last-known-good generations."""

import base64
import hashlib
import json
import os
import re
import shutil
import sys
import tempfile
import time
from datetime import datetime, timezone
from pathlib import Path
from urllib.parse import urljoin, urlsplit

from curlguard.policy import sha256, timestamp


def encode(data):
    return base64.b64encode(data).decode("ascii")


def decode(data):
    if not isinstance(data, str):
        raise ValueError("bundle encoding must be a string")
    return base64.b64decode(data, validate=True)


class AutoUpdater:
    MAX_BYTES = 8 * 1024 * 1024
    MAX_RULE_BYTES = 5 * 1024 * 1024

    def __init__(self, config, scanner):
        self._config, self._scanner = config, scanner
        self._base = config.quarantine_dir.parent / "feeds"
        self._failure_file = self._base / "last-failure.json"
        self._last_update_file = self._base / "active"

    def _keys(self):
        path = self._config.update_keys_file
        if not path or not path.is_file():
            raise ValueError("provision CURLGUARD_UPDATE_KEYS_FILE locally")
        data = json.loads(path.read_text(encoding="utf-8"))
        if (
            not isinstance(data, dict)
            or not isinstance(data.get("keys"), dict)
            or not data["keys"]
        ):
            raise ValueError("key file requires a nonempty keys object")
        return data["keys"]

    def _trust_id(self):
        return hashlib.sha256(
            json.dumps(self._keys(), sort_keys=True).encode()
        ).hexdigest()

    def verify(self, body, *, allow_expired=False):
        from cryptography.hazmat.primitives.asymmetric.ed25519 import Ed25519PublicKey

        if len(body) > self.MAX_BYTES:
            raise ValueError("rule bundle exceeds 8 MiB")
        envelope = json.loads(body)
        if not isinstance(envelope, dict) or (
            type(envelope.get("schema_version")) is not int
            or envelope.get("schema_version") != 1
        ):
            raise ValueError("signed bundle requires schema_version=1")
        key = self._keys().get(envelope.get("key_id"))
        if key is None:
            raise ValueError("unknown signing key")
        manifest_bytes = decode(envelope.get("manifest"))
        Ed25519PublicKey.from_public_bytes(decode(key)).verify(
            decode(envelope.get("signature")), manifest_bytes
        )
        manifest = json.loads(manifest_bytes)
        if not isinstance(manifest, dict) or (
            type(manifest.get("schema_version")) is not int
            or manifest.get("schema_version") != 1
        ):
            raise ValueError("invalid signed manifest")
        if (
            not self._config.update_feed_id
            or manifest.get("feed_id") != self._config.update_feed_id
        ):
            raise ValueError(
                "rule feed identity does not match CURLGUARD_UPDATE_FEED_ID"
            )
        sequence = manifest.get("sequence")
        if type(sequence) is not int or sequence < 1:
            raise ValueError("rule sequence must be a positive integer")
        published, expires = (
            timestamp(manifest.get("published_at")),
            timestamp(manifest.get("expires_at")),
        )
        now = datetime.now(timezone.utc)
        if (
            published > now
            or expires <= published
            or (expires <= now and not allow_expired)
        ):
            raise ValueError("rule bundle is expired or has invalid publication dates")
        source = decode(manifest.get("rules"))
        if len(source) > self.MAX_RULE_BYTES or hashlib.sha256(
            source
        ).hexdigest() != sha256(manifest.get("rules_sha256")):
            raise ValueError("rule source exceeds size limit or digest does not match")
        source.decode("utf-8")
        return manifest, source

    def current(self):
        if not self._last_update_file.exists():
            return None
        name = self._last_update_file.read_text().strip()
        if not re.fullmatch(r"[a-f0-9]{64}", name):
            raise ValueError("invalid active rule generation")
        directory = self._base / "generations" / name
        binding = json.loads((directory / "binding.json").read_text())
        if binding != {"url": self._config.update_url, "trust_id": self._trust_id()}:
            raise ValueError(
                "feed source or configured trust changed; explicitly migrate feed state"
            )
        body = (directory / "bundle.json").read_bytes()
        if hashlib.sha256(body).hexdigest() != name:
            raise ValueError("rule generation identity mismatch")
        manifest, source = self.verify(body, allow_expired=True)
        return name, manifest, source

    def status(self):
        status = {
            "configured": bool(self._config.update_url),
            "usable": not bool(self._config.update_url),
            "feed_id": self._config.update_feed_id,
            "sequence": None,
            "expires_at": None,
            "generation": None,
            "last_failure": None,
        }
        try:
            if self._failure_file.exists():
                status["last_failure"] = json.loads(self._failure_file.read_text())
            current = self.current() if self._config.update_url else None
            if current:
                name, manifest, _ = current
                status.update(
                    generation=name,
                    sequence=manifest["sequence"],
                    expires_at=manifest["expires_at"],
                    usable=timestamp(manifest["expires_at"])
                    > datetime.now(timezone.utc),
                )
        except Exception as exc:
            status["error"] = type(exc).__name__
            status["usable"] = False
        return status

    def load_active(self):
        """Never fetch here. Verify persisted bytes before compiling them."""
        status = self.status()
        if self._config.update_url:
            try:
                current = self.current()
                if current:
                    self._scanner.set_remote(current[2].decode("utf-8"))
            except Exception as exc:
                status.update(usable=False, error=type(exc).__name__)
        return status

    def should_update(self):
        if not self._config.update_url:
            return False
        return not (
            self._failure_file.exists()
            and time.time() - self._failure_file.stat().st_mtime < 300
        )

    def check_and_update(self):
        if not self._config.update_url:
            raise ValueError(
                "configure CURLGUARD_UPDATE_URL and a signed rule feed first"
            )
        import fcntl

        self._base.mkdir(parents=True, exist_ok=True, mode=0o700)
        fd = os.open(
            self._base / ".update.lock", os.O_CREAT | os.O_RDWR | os.O_NOFOLLOW, 0o600
        )
        with os.fdopen(fd, "a") as lock:
            try:
                fcntl.flock(lock, fcntl.LOCK_EX | fcntl.LOCK_NB)
            except BlockingIOError:
                return False
            if not self.should_update():
                return False
            try:
                self.fetch_rules(self._config.update_url)
                self._failure_file.unlink(missing_ok=True)
                return True
            except Exception as exc:
                self._failure_file.write_text(
                    json.dumps(
                        {
                            "time": datetime.now(timezone.utc).isoformat(),
                            "error": type(exc).__name__,
                        }
                    )
                )
                os.chmod(self._failure_file, 0o600)
                print(
                    f"curlguard: signed rule update failed ({type(exc).__name__}); retaining active generation",
                    file=sys.stderr,
                )
                return False

    def fetch_rules(self, url):
        import requests

        original_url = url
        body = bytearray()
        with requests.Session() as session:
            for _ in range(6):
                if urlsplit(url).scheme != "https":
                    raise ValueError(
                        "rule updates require HTTPS through every redirect"
                    )
                with session.get(
                    url, timeout=30, stream=True, allow_redirects=False
                ) as response:
                    if response.is_redirect:
                        url = urljoin(url, response.headers["Location"])
                        continue
                    response.raise_for_status()
                    if response.status_code != 200:
                        raise ValueError("rule bundle requires HTTP 200")
                    for chunk in response.iter_content(65536):
                        body.extend(chunk)
                        if len(body) > self.MAX_BYTES:
                            raise ValueError("rule bundle exceeds 8 MiB")
                    break
            else:
                raise ValueError("too many rule update redirects")
        manifest, source = self.verify(bytes(body))
        identity = hashlib.sha256(body).hexdigest()
        previous = self.current()
        if previous and (
            manifest["sequence"] < previous[1]["sequence"]
            or (
                manifest["sequence"] == previous[1]["sequence"]
                and identity != previous[0]
            )
        ):
            raise ValueError("rule bundle rollback or conflicting sequence")
        generations = self._base / "generations"
        generations.mkdir(parents=True, exist_ok=True, mode=0o700)
        staged = Path(tempfile.mkdtemp(prefix=".stage-", dir=generations))
        pointer = None
        try:
            rules = staged / "rules.yar"
            rules.write_bytes(source)
            candidate = self._scanner.compile_candidate(rules)
            (staged / "bundle.json").write_bytes(body)
            (staged / "binding.json").write_text(
                json.dumps({"url": original_url, "trust_id": self._trust_id()})
            )
            destination = generations / identity
            if destination.exists():
                shutil.rmtree(staged)
            else:
                os.replace(staged, destination)
            fd, name = tempfile.mkstemp(prefix=".active-", dir=self._base)
            pointer = Path(name)
            with os.fdopen(fd, "w") as handle:
                handle.write(identity + "\n")
                handle.flush()
                os.fsync(handle.fileno())
            os.replace(pointer, self._last_update_file)
            self._scanner.set_remote(source.decode("utf-8"), candidate)
        finally:
            if staged.exists():
                shutil.rmtree(staged)
            if pointer:
                pointer.unlink(missing_ok=True)
