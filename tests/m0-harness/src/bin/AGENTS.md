# Qualification Binary Guidelines

`m0_qualification.rs` is a command-line adapter over the qualification support API. Keep argument
parsing, exit-status mapping, and user-facing evidence selection here; keep case execution and resource
ownership in `src/qualification` or `src/external_support`.

CLI failures must be bounded, deterministic, and free of credentials or peer payloads.
