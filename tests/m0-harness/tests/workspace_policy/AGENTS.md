# Workspace Policy Guidelines

`architecture.toml` is the declarative source for package ownership, dependency, fixture-consumer, and
boundary rules; `r0_policy.rs` evaluates the baseline workspace contract. Prefer structured metadata
over source-text shape checks.

Update the policy in the same change as an intentional architecture move. Tests should report the
violated rule and exact owner or path.
