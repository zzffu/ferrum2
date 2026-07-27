# ferrum2

This context names the contracts used to distinguish ferrum2 product guarantees
from the evidence and mechanics used to prove them.

## Language

**Normative invariant**:
A product, wire, security, API, platform, or release outcome that must remain true
regardless of implementation or test mechanism.
_Avoid_: Test requirement, implementation detail

**Selected conformance profile**:
The currently approved, reproducible combination of tests, probes, dependency
edges, and evidence used to prove one or more normative invariants.
_Avoid_: Immutable architecture, sole possible proof

**Equivalent evidence substitution**:
A reviewed replacement for part of a selected conformance profile that proves the
same claims and failure modes without weakening any normative invariant.
_Avoid_: Waiver, skip, test relaxation

**Mechanical realization**:
The non-normative spelling or platform plumbing of an approved conformance profile,
such as line-ending handling, exact test selection, or linker discovery.
_Avoid_: Product contract, architectural decision
