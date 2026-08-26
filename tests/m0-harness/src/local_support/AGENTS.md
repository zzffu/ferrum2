# Local Harness Support Guidelines

This façade owns portable loopback allocation, product-process lifecycle, readiness, DNS, and
configuration fixtures. Keep each owner in its named module and expose only the operations integration
tests need.

Resource setup must be transactional: failed construction and panics must reap child processes and
release ports without relying on test order.
