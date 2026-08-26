# Shared Fixture Guidelines

This directory owns versioned, cross-workspace test inputs. Keep each fixture in its domain
subdirectory and preserve deterministic bytes, schema versions, and provenance when regenerating it.

Consumers may read these files, but must not rewrite them during a test run. Put package-private or
fuzz-only corpora next to their owning crate instead.
