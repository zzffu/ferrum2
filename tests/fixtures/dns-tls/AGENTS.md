# DNS TLS Fixture Guidelines

This directory owns the test-only CA, certificate, and private key used by DNS TLS interoperability
tests. Keep the files deterministic, non-production, and limited to the consumers documented in
`README.md`.

Do not log private-key contents or reuse these credentials outside tests. Update the documented
fingerprints and every exact consumer allowlist when replacing the fixture set.
