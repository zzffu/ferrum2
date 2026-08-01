# Recovery

Recover from repository evidence; never guess or rely on an opaque local ledger.

1. Stop writers and record `git status --short --branch` in every relevant worktree.
2. List worktrees, branches, recent commits, and merge-bases.
3. Match worktrees and commits to ticket IDs from branch names, commit subjects, and
   changed paths.
4. Keep clean committed candidates. Preserve dirty work before any cleanup.
5. Re-run only invalidated focused gates, then the configured repository gate.
6. Rebuild concise ticket/milestone status from verified commits and evidence.
7. Resume at the first incomplete gate: implementation, review, repair, integration,
   validation, or close.

Do not use destructive reset/clean commands, delete branches, or rewrite remote history
as recovery shortcuts.
