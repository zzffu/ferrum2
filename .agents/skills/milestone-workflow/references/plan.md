# Plan

## Bootstrap

1. Inspect repository purpose, architecture, build files, tests, CI, and constraints.
2. Create only missing workflow directories/config/templates; preserve product files.
3. Fill `docs/agents/milestone-workflow.md` with the actual base branch and validation
   commands. Empty command blocks mean unknown, not pass.
4. Summarize current delivery state in `docs/roadmap.md`; do not invent past evidence.

## Feature or milestone plan

1. Pin the baseline commit and describe current behavior with file/symbol evidence.
2. Define one independently verifiable outcome and explicit non-goals.
3. Record only hard-to-reverse decisions in ADRs.
4. Write a short spec for observable behavior and a test plan mapping each MUST to a
   primary evidence item.
5. Split work into small vertical tickets. Each ticket needs:
   - outcome and acceptance criteria;
   - dependencies;
   - owned paths;
   - focused and repository validation commands;
   - risks and rollback notes when relevant.
6. Prefer slices that expose integration risk early. Unknown ownership overlaps.
7. Mark future behavior as planned until integrated and validated.

## Test-footprint plan

For each planned evidence item, identify the cheapest sufficient layer and the existing test file,
table, fixture, or helper to extend. Estimate expected growth separately for test cases, support
code, and fixtures; the estimate is a forecast, not a correctness cap. Explicitly call out any new
harness or third helper implementation for Architect/QA review.

Use the repository defaults unless the accepted evidence map justifies another threshold:
`tests/code` warning/review at `2.0/2.5`, change-set test growth at `240/600`, and a growing test
file at `800/1200`. A changed threshold requires an isolated policy revision with a durable
`reforecast_ref`; do not hide additional evidence by compressing tests to fit an obsolete estimate.

## Plan gate

A plan is ready when the baseline resolves, scope is bounded, dependencies are acyclic,
ownership is non-overlapping or serialized, acceptance is observable, and required
validation is known. Otherwise return the smallest blocking question or investigation.
