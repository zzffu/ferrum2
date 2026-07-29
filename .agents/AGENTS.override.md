# Installer-managed Agent Skills

This subtree contains installed Agent Skills and is part of the workflow control
plane. During product work (`bootstrap`, `feature`, `plan`, `execute`, `resume`, or
`close`), treat every file under `.agents/skills/` as read-only, including third-party
Skills such as TDD, code review, research, and codebase design.

Do not repair a product ticket by changing a Skill, its helper scripts, tests,
references, templates, or invocation policy. If the workflow lacks a capability,
record it with `workflow.py workflow-debt ...`, report
`CONTROL_PLANE_CHANGE_REQUIRED`, and stop that product path. Control-plane changes
require a separate user-requested workflow-maintenance or package-upgrade task.
