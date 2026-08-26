# Rule performance evidence

This directory separates ordinary controller/schema tests from large release evidence. Current production accepts only controller v6 and reviewed-calibration v2. Historical controller v2/v3/v4 validation is test-owned in `archive_verifier.py` and is invoked only by the explicit external verifier.

## Ordinary tracked fixtures

`fixtures/release-evidence-contract-v1.json` is a small, explicitly synthetic contract fixture. It covers the current runner/control schemas, runner-to-A/B identity binding, representative generated and pinned SRS provenance, allocation-free matching, paired MatchSet evidence, and the 5% median/15% p99 local gate. It is not benchmark evidence and cannot support a performance claim.

`fixtures/external-evidence-manifest-v1.json` is the tracked content-addressed inventory for the seven release artifacts. It records exact filenames, roles, byte lengths, SHA-256 digests, and the total 315,725,820-byte boundary. The manifest is evidence metadata, not a substitute for the raw JSON.

Ordinary tests require only tracked files:

```text
python3 -B -m unittest discover -s tests/performance_rule -v
```

## External release evidence

`release-*.json` remains ignored by Git and must live in an approved immutable artifact store. A clean checkout intentionally does not contain or download these files. After an operator explicitly materializes all seven files into one evidence directory, verify the complete-file identities before reading or using them:

```text
python3 -B -m tests.performance_rule.verify_external_evidence \
  --evidence-directory /path/to/materialized-rule-evidence
```

The verifier accepts only direct child files named by the manifest and checks every byte length and SHA-256. A missing, reparse-linked, truncated, extra-version, or changed required artifact fails closed. Artifact retrieval and retention are external operational responsibilities; any future workflow must fetch by immutable identity and run this verifier before evidence-contract analysis.

The external chain contains:

- the original v2 A/A diagnostic;
- the passing v3 A/A calibration;
- the failed v3 A/B diagnostic;
- archived v4 A/A and A/B reports;
- the full candidate qualification report;
- the candidate smoke report.

Fresh evidence is generated directly with the current schemas. A current A/A report remains `CALIBRATION_REQUIRED`; it cannot approve itself. An operator must explicitly review it into a separate, source-hash-bound calibration artifact before A/B can execute. Archived v2/v3/v4 files are provenance inputs only, not accepted production formats.
