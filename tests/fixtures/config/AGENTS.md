# Configuration Fixture Guidelines

These TOML files are stable public configuration examples shared across packages and tests. Each
filename must state the role and expected validity; invalid cases should isolate the named failure.

When the current configuration contract changes, update all in-repository consumers in the same
change. Do not retain legacy aliases or migration fixtures.
