# External Qualification Support Guidelines

This module owns hosted-provider cases, external artifacts, process guards, pin/hash validation, and
TCP/UDP/DNS dispatch. Keep each case row isolated and require exact reviewed provider identities.

All waits and reads must be bounded. Cleanup failure is a qualification failure, and logs must not
expose provider credentials, keys, or peer data.
