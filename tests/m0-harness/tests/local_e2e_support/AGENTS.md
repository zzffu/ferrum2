# Local End-to-End Support Guidelines

This module owns reusable local client/server topology setup for portable end-to-end tests. Allocate
isolated loopback endpoints, use bounded readiness checks, and return owners that clean up every child.

Keep protocol-specific assertions in the calling test unless they are genuinely shared behavior.
