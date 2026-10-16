"""Inert scan corpus and bounded finding presentation."""

import json
import subprocess
import sys
from pathlib import Path

import pytest

from curlguard.evidence import safe_text
from curlguard.scanner import YaraScanner


def test_scan_corpus():
    manifest = json.loads(
        (Path(__file__).parent / "fixtures/scan-corpus.json").read_text()
    )
    scanner = YaraScanner()
    for sample in manifest["samples"]:
        result = scanner.scan(sample["content"].encode())
        assert sorted(result.rules_triggered) == sorted(sample["expected_rules"]), (
            sample["id"]
        )


def test_findings_are_structured_and_evidence_is_private():
    result = YaraScanner().scan(b"echo x | base64 -d | bash\n")
    finding = result.findings[0]
    assert finding.rule == "base64_encoded_shell"
    assert finding.namespace == "builtin"
    assert finding.description and finding.severity == "high"
    assert finding.ruleset_id and finding.locations and finding.evidence
    assert "evidence" not in finding.public()
    assert len(finding.locations) <= 8


def test_bad_optional_metadata_defaults_conservatively(tmp_path):
    (tmp_path / "odd.yar").write_text(
        "rule odd { meta: severity=42 confidence=false category=7 condition: true }"
    )
    findings = YaraScanner([tmp_path]).scan(b"inert").findings
    assert len(findings) == 1
    assert findings[0].severity == "high" and findings[0].confidence == "unknown"


def test_terminal_controls_and_markup_are_not_interpreted():
    from curlguard.tui import PlainStatic

    text = safe_text("\x1b[31m[bold]untrusted[/bold]\n")
    assert "\x1b" not in text and "\\x1b" in text
    widget = PlainStatic(text)
    assert "[bold]" in str(widget.render())


def test_real_compiler_timeout_reaps_worker(monkeypatch, tmp_path):
    scanner = YaraScanner()
    previous = scanner.ruleset_id
    pid_path = tmp_path / "pid"
    real_run = subprocess.run

    def slow_worker(*args, **kwargs):
        command = [
            sys.executable,
            "-c",
            "import os,sys,time; open(sys.argv[1],'w').write(str(os.getpid())); time.sleep(30)",
            str(pid_path),
        ]
        kwargs["timeout"] = 0.5
        return real_run(command, **kwargs)

    monkeypatch.setattr("curlguard.scanner.subprocess.run", slow_worker)
    with pytest.raises(subprocess.TimeoutExpired):
        scanner.compile_candidate()
    assert scanner.ruleset_id == previous
    import os

    with pytest.raises(ProcessLookupError):
        os.kill(int(pid_path.read_text()), 0)


def test_compile_worker_sets_real_resource_limits(tmp_path):
    # An inert replacement YARA module observes limits in an actual worker process.
    fake = tmp_path / "yara.py"
    fake.write_text(
        "import resource,json\ndef compile(**kw):\n assert resource.getrlimit(resource.RLIMIT_CPU)==(20,20)\n assert resource.getrlimit(resource.RLIMIT_AS)==(536870912,536870912)\n assert kw['includes'] is False\n return type('R',(),{'save':lambda self,path:open(path,'w').write('ok')})()\n"
    )
    source = tmp_path / "source.json"
    source.write_text('{"inert":"rule x {condition:true}"}')
    import os

    worker = Path(__file__).resolve().parents[1] / "src/curlguard/compile_worker.py"
    result = subprocess.run(
        [sys.executable, str(worker), str(source), str(tmp_path / "compiled")],
        cwd=tmp_path,
        env={**os.environ, "PYTHONPATH": str(tmp_path)},
        capture_output=True,
    )
    assert result.returncode == 0, result.stderr
