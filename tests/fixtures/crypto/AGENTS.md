# Cryptographic Vector Guidelines

Keep these JSON vectors deterministic and independently reproducible. Record generator inputs and
source lineage in `PROVENANCE.toml`; generated output must not depend on local randomness, clocks, or
platform formatting.

Never replace reviewed vectors merely to make an implementation pass. Regenerate only when the
specified algorithm or versioned vector contract changes.
