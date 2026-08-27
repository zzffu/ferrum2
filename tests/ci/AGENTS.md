# CI Controller Test Guidelines

The repository and `tests` guides remain in force. This directory owns offline behavior tests for
the controllers in `tools/ci`; it does not reproduce workflow implementation text.

Exercise public planning and validation behavior with temporary directories, temporary Git
repositories, and injected or mocked side effects. Assert fail-closed handling of malformed policy,
metadata, paths, and process results. Never contact hosted providers, run a fuzz target, start a
privileged network path, or execute a performance workload from ordinary test discovery.

Required-job tests must cover both executed and deliberately skipped closures, plus malformed,
missing, duplicate, failed, and cancelled dependency results.

Fuzz-impact tests treat new root-level executable inputs as affected and verify that only explicitly
typed Markdown exclusions can bypass the campaign.
