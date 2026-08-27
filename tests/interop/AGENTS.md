# Interoperability Metadata Guidelines

This directory records reviewed external implementation and protocol versions used by hosted
qualification. Pin exact versions; do not use floating tags, implicit latest versions, or local
environment discovery.

Changing a pin requires corresponding qualification evidence from the workflow that consumes it.
`tools/ci/interop_provision.py` is the canonical typed consumer for Linux provider setup; update its
offline behavior tests under `tests/ci` atomically with any metadata schema or archive-contract change.
