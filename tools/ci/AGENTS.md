# CI Tooling Guidelines

The repository and `tools` guides remain in force. This directory owns small, deterministic
controllers that keep root GitHub Actions workflows declarative. Prefer standard-library Python,
typed data at module boundaries, and pure planning or validation functions separated from network
and subprocess effects.

Read canonical reviewed metadata and policy files instead of repeating their values in workflow
YAML. Fail closed on missing, malformed, or inconsistent inputs. Keep exact version, digest, action,
and source-identity checks intact; do not add floating discovery or compatibility fallbacks.

Every controller must have offline behavior tests under `tests/ci`. Tests may use temporary files,
repositories, and injected fakes, but must not download providers, start privileged networking, run
fuzz campaigns, or execute performance workloads.
