# Configuration CLI Support Guidelines

This module contains shared black-box setup and assertions for configuration CLI tests. Keep fixture
selection, process invocation, and observable diagnostics centralized so individual tests describe
only the contract case.

Do not parse product source or depend on private configuration types.
