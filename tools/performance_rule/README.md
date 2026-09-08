# Rule performance controller

The entry point is `python -B -m tools.performance_rule`. The controller accepts
only current controller v6, reviewed calibration v2, and the current Rust runner
report. A/A collection never approves its own calibration; `review-calibration`
is an explicit operator action.

Before starting any A/B runner, the controller validates the complete reviewed
calibration and its hash-bound A/A source: raw mathematics, derived decisions,
runner identity, exact argument vector, execution policy and scenario catalog.
The source supplies the expected workload identity for the first and every later
runner report. That identity includes fixtures, configuration, measurement policy
and reported environment. Each report must also match the requested Rust profile
and complete configuration. Engine mode remains an observed implementation result.

Pass runner arguments after `--`. Supported measurement options are `--profile`,
`--samples`, `--iterations-per-sample`, `--include-100k`, `--workspace-root`, and
`--output`. Value options accept `--option value` or `--option=value`; duplicate,
unknown and abbreviated options are rejected. Help/version options do not collect
evidence and are not accepted as measurement arguments.

The default profile is `smoke`, with 101 samples and 8192 base iterations per
sample. Samples must be 5–1001; base iterations must be 1–10000000. Profile scales
are checked against the Rust producer:

| Profile | MatchSet | Route | DNS |
| --- | --- | --- | --- |
| smoke | 100 | 1, 32, 63, 64, 65 | 1 |
| qualification | 100, 1000, 10000 | 1, 32, 63, 64, 65, 1000, 10000 | 1, 64, 65, 100, 1000, 10000 |

`--include-100k` appends 100000 to MatchSet scales. Workspace and optional runner
output paths remain bound by the exact argument vector used for calibration.

`review-calibration --source-report source.json --reviewed-by NAME
--reviewed-utc UTC --output calibration.json` requires separate source and output
files in the same resolved directory. Cross-directory output is rejected before
writing; there is no implicit source copy. Keep the source alongside calibration.

Collection, JSON readers and final output share a 64 MiB encoded evidence bound.
Each prospective report is charged with its enclosing controller metadata and
trace before admission. Final comparisons and policy are checked before encoding
the complete document. If the next report or final summary cannot fit, collection
stops and emits an `INVALID` artifact retaining every previously admitted raw
report. The oversized report is not admitted. A partial artifact may contain a
half pair and cannot be reviewed as calibration. This is an encoded evidence
limit, not a process RSS guarantee. Output files are replaced atomically only
after the encoded document passes the bound.

Failures print only closed stage/category diagnostics. They never print runner
stderr, exception messages, invalid reports or paths. When `--output` is supplied,
failure metadata is atomically written beside it as
`<stem>.failure.<content-sha256>.json`; no additional file is written without
`--output`. This separate `ferrum2.rule-qualification-failure.v1` artifact binds
the full bounded controller request by SHA-256 and, when available, the runner
hash, pair/order/role, runner-argument hash and exact saved partial-report hash.
It is not calibration or a successful controller report.

Failure diagnostics contain only fingerprint byte counts, SHA-256 and truncation
flags, plus closed categories and valid integer exit/errno codes. No raw error
content or Base64 copy is saved. Fingerprints describe the retained bounded
prefix: capture uses the stdout/stderr bounds above; exception fingerprints use
at most 65536 characters. A truncated fingerprint does not claim to hash the
unread remainder. The controller accepts at most 64 arguments totaling 65536
characters. Failure-artifact write errors preserve the primary category and add
a closed output failure diagnostic. Ordinary help and interruption exit semantics
are retained.

The shared `tools/owned_process.py` capture owner includes thread startup and complete
child-tree cleanup in one lifetime. Unix leaders are observed without reaping until
final group termination; Windows Jobs retain descendant ownership after leader exit.
A single five-second cleanup deadline bounds final termination, confirmation and reader
joins. Kill/wait/join failures retain the primary category and
report `cleanup_unconfirmed`. A reader that remains alive may still own an
inherited pipe; Python cannot forcibly terminate that thread. Its capture bytes
are not read or fingerprinted, and the run cannot return successful evidence.

Ordinary verification uses compact synthetic evidence and mocked runners only:

```text
python -B -m unittest discover -s tests/performance_rule -p 'test_*.py' -v
```
