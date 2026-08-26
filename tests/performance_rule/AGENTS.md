# Performance Rule Controller Guidelines

This directory owns release-evidence schemas, pairing and calibration policy tests, archive verification,
and reviewed example evidence. Treat schema/version or threshold changes as release-policy changes.

Keep parsers bounded and strict: reject duplicate or unexpected fields, unreviewed candidate identities,
and incomplete pair sets. Unit tests may construct evidence but must not execute performance workloads.
