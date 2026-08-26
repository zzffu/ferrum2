# SOCKS UDP Test Support Guidelines

This module owns shared SOCKS5 UDP framing, association setup, and routing-test helpers. Preserve exact
wire-level assertions and make policy-denial scenarios deterministic rather than dependent on ambient
network failures.

All sockets and product processes must remain bounded and locally owned.
