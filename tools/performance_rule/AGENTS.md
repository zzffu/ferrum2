# Rule Performance Controller Guidelines

## Entry point and owners

The only supported CLI is `python -B -m tools.performance_rule`. Do not add a
single-file entrypoint, import alias, facade, or schema compatibility reader.
`cli.py` is the composition root; current runner-report validation, pairing,
policy, calibration evidence, and schema contracts stay with their named owners.

## Evidence and calibration

Production accepts only the current v6 controller report and current reviewed
calibration v2 schema. Historical v2/v3/v4 verification is test-owned under
`tests/performance_rule/archive_verifier.py` and must never be imported by the
active package. A newly collected A/A report remains `CALIBRATION_REQUIRED` until
an operator explicitly reviews it into a separate artifact bound to the source
report, runner hash, arguments, execution policy, and scenario set. Synthetic
fixtures and archived evidence cannot approve a calibration.

## Verification

Keep production and test owners below 1,000 lines. Use AST parsing, imports, and
the offline controller tests for ordinary verification:

```text
python -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v
```

These tests validate synthetic evidence and mocked runner behavior; they must not execute
benchmarks or A/A/A/B collection. Verify externally materialized release evidence only through
the test-owned content-addressed manifest tool. Use `python3` for these commands on Unix.
