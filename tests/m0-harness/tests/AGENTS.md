# M0 Integration Test Guidelines

Tests here exercise built binaries and public contracts. Share setup through the adjacent support
façades, assert protocol bytes, exit status, readiness, and cleanup, and keep loopback resources isolated.

Portable tests must remain unprivileged. Windows TUN, hosted-provider, long-lifecycle, and profiling
targets may validate their static contract locally but execute only in their designated workflow.
