import json
import sys
from pathlib import Path
from unittest.mock import patch

sys.path.insert(0, str(Path(__file__).parent.parent / "src"))

from curlguard.cli import main


def test_quarantine_list_command_shows_entries(monkeypatch, tmp_path, capsys):
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir()
    payload_path = quarantine_dir / "1713900000_payload.download"
    payload_path.write_text("evil")
    payload_path.with_name(f"{payload_path.name}.json").write_text(
        json.dumps(
            {
                "timestamp": "2026-04-24T12:00:00+00:00",
                "url": "https://evil.example/payload.sh",
                "rules_triggered": ["suspicious_pipe_bash"],
                "sha256": "a" * 64,
                "size_bytes": 4,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CURLGUARD_MODE", "per-user")
    monkeypatch.setenv("CURLGUARD_QUARANTINE", str(quarantine_dir))

    with patch.object(sys, "argv", ["curlguard", "quarantine", "list"]):
        exit_code = main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "1713900000_payload.download" in captured.out
    assert "evil.example" in captured.out


def test_quarantine_inspect_command_shows_metadata(monkeypatch, tmp_path, capsys):
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir()
    payload_path = quarantine_dir / "1713900000_payload.download"
    payload_path.write_text("evil")
    payload_path.with_name(f"{payload_path.name}.json").write_text(
        json.dumps(
            {
                "timestamp": "2026-04-24T12:00:00+00:00",
                "url": "https://evil.example/payload.sh",
                "rules_triggered": ["suspicious_pipe_bash"],
                "sha256": "b" * 64,
                "size_bytes": 4,
            }
        ),
        encoding="utf-8",
    )
    monkeypatch.setenv("CURLGUARD_MODE", "per-user")
    monkeypatch.setenv("CURLGUARD_QUARANTINE", str(quarantine_dir))

    with patch.object(sys, "argv", ["curlguard", "quarantine", "inspect", payload_path.name]):
        exit_code = main()

    captured = capsys.readouterr()
    assert exit_code == 0
    assert "Source URL:    https://evil.example/payload.sh" in captured.out
    assert "SHA-256:       " + ("b" * 64) in captured.out


def test_quarantine_inspect_command_reports_missing_item(monkeypatch, tmp_path, capsys):
    quarantine_dir = tmp_path / "quarantine"
    quarantine_dir.mkdir()
    monkeypatch.setenv("CURLGUARD_MODE", "per-user")
    monkeypatch.setenv("CURLGUARD_QUARANTINE", str(quarantine_dir))

    with patch.object(sys, "argv", ["curlguard", "quarantine", "inspect", "missing-item"]):
        exit_code = main()

    captured = capsys.readouterr()
    assert exit_code == 1
    assert "no quarantined payload matched" in captured.err
