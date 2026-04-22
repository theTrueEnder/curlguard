# Contributing to curlguard

## YARA Rules

Rules are in `.yar` format. When adding a rule:
1. Name it descriptively: `suspicious_pipe_bash` not `rule1`
2. Include `meta.description` explaining what it detects
3. Set `meta.severity`: `critical`, `high`, `medium`, `low`
4. Test against the true positive sample in `examples/known_malware/sample.sh`

Rule format:
```
rule rule_name {
  meta:
    description = "What this detects"
    severity = "high"
  strings:
    $a = "pattern"
  condition:
    $a
}
```

## Code Style

- Format: `ruff format`
- Lint: `ruff check`
- Type check: `mypy` (when added)

## Tests

```bash
pytest tests/ -v
```

Add tests for any new module or significant logic change.

## Submitting Changes

1. Add YARA rule to foundation.yar (for general rules) or user rules dir
2. Ensure `pytest tests/ -v` passes
3. Commit with descriptive message: `feat(core): ...`, `fix(scanner): ...`, `docs: ...`