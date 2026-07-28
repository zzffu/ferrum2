# Installation and Upgrade Policy

The installer is dry-run by default and supports fresh installation and managed
upgrade.

## Managed files

Core Skill files, workflow scripts/tests, references, templates, and role instructions
are package-managed. During upgrade they are replaced only when their current hash is
recognized, or when `--force-managed` is explicitly supplied. Every replacement is
backed up first.

## Merged files

- `workflow.toml`: project-specific branches, agents, documents, state path, and
  validation commands are preserved. Convergence/test-budget settings are migrated.
- `AGENTS.md`: only the delimited workflow section is replaced.
- `.gitignore`: missing workflow entries are appended.
- `code-review/agents/openai.yaml`: only `policy.allow_implicit_invocation` is patched
  to false; other metadata is retained.

## Project-owned files

Existing ADRs, specs, test plans, tickets, roadmap, CI status, handoffs, and review
debt are never overwritten. Missing templates or control documents may be added.

## Backup and metadata

Upgrades write backups below `.codex/milestone-workflow-backups/` and installation
metadata to `.codex/milestone-workflow-install.json`. Unknown local edits produce a
conflict report and are not overwritten unless explicitly forced.
